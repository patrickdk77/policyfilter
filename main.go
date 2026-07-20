package main

import (
	"context"
	"flag"
	"log"
	"math"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"database/sql"

	"github.com/emersion/go-milter"
	_ "github.com/go-sql-driver/mysql"
	"github.com/valkey-io/valkey-go"
)

var debugLog bool

func debugf(format string, v ...any) {
	if debugLog {
		log.Printf(format, v...)
	}
}

func parseNetworks(envs string) []*net.IPNet {
	var nets []*net.IPNet
	if envs == "" {
		return nets
	}
	parts := strings.Split(envs, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.Contains(p, "/") {
			if strings.Contains(p, ":") {
				p = p + "/128"
			} else {
				p = p + "/32"
			}
		}
		_, ipnet, err := net.ParseCIDR(p)
		if err == nil && ipnet != nil {
			nets = append(nets, ipnet)
		} else {
			log.Printf("Warning: failed to parse whitelist network %s", p)
		}
	}
	return nets
}

func main() {
	flagReport := flag.Bool("report", false, "Generate out-of-band DMARC RUA report for yesterday")
	flag.Parse()

	log.Println("Starting Postfix Policy Filter (Milter) for SPF, DKIM, and DMARC")

	debugVal := os.Getenv("DEBUG")
	if strings.ToLower(debugVal) == "true" || debugVal == "1" {
		debugLog = true
	}

	policyConfigFile := os.Getenv("CONFIG")
	if policyConfigFile == "" {
		policyConfigFile = "/etc/policyfilter.yaml"
	}

	var yc *YAMLConfig
	cfg, err := LoadPolicyTable(policyConfigFile)
	if err != nil {
		if os.Getenv("CONFIG") != "" {
			log.Printf("Warning: Failed to load CONFIG %s: %v", policyConfigFile, err)
		}
	} else {
		log.Printf("Loaded policies and configuration from %s", policyConfigFile)
		yc = cfg
	}

	resolveBool := func(envKey string, yamlVal *bool, fallback bool) bool {
		if val, ok := os.LookupEnv(envKey); ok {
			val = strings.ToLower(val)
			if b, err := strconv.ParseBool(val); err == nil {
				return b
			}
		}
		if yamlVal != nil {
			return *yamlVal
		}
		return fallback
	}

	resolveInt := func(envKey string, yamlVal *int, fallback int) int {
		if val, ok := os.LookupEnv(envKey); ok {
			if i, err := strconv.Atoi(val); err == nil {
				return i
			}
		}
		if yamlVal != nil {
			return *yamlVal
		}
		return fallback
	}

	resolveStr := func(envKey string, yamlVal *string, fallback string) string {
		if val, ok := os.LookupEnv(envKey); ok {
			return val
		}
		if yamlVal != nil {
			return *yamlVal
		}
		return fallback
	}

	resolveAction := func(envKey string, enableYaml *bool, rejectYaml *bool, enableFallback, rejectFallback bool) (bool, bool) {
		enable := enableFallback
		reject := rejectFallback
		if enableYaml != nil {
			enable = *enableYaml
		}
		if rejectYaml != nil {
			reject = *rejectYaml
		}

		val, ok := os.LookupEnv(envKey)
		if !ok {
			return enable, reject
		}

		val = strings.ToLower(val)
		switch val {
		case "true", "1", "yes":
			return true, false
		case "reject":
			return true, true
		case "false", "0", "no":
			return false, false
		}
		return enable, reject
	}

	var dfltOvr OverridePolicy
	if yc != nil && yc.Profiles != nil {
		if pf, ok := yc.Profiles["default"]; ok {
			dfltOvr = pf
		}
	}

	enableSPF, rejectSPF := resolveAction("ENABLE_SPF", dfltOvr.EnableSPF, dfltOvr.RejectOnSPFFail, true, false)
	enableDKIM, rejectDKIM := resolveAction("ENABLE_DKIM", dfltOvr.EnableDKIM, dfltOvr.RejectOnDKIMFail, true, false)
	enableDMARC, rejectDMARC := resolveAction("ENABLE_DMARC", dfltOvr.EnableDMARC, dfltOvr.RejectOnDMARCFail, true, true)

	var ycValkeyUrl, ycMysql, ycMilterAddr, ycWhite, ycHostname *string
	var ycReportSmtp, ycReportOrg, ycReportEmail, ycReportContact, ycReportDomain *string
	var ycMaxMsg *int
	var ycMysqlCacheTTL *int
	var ycMysqlQuery *string
	var ycHeloTTL, ycGreyV4, ycGreyV6, ycGreyWait, ycGreyUn, ycGreyMat *int
	var ycSPFMaxDNS, ycSPFMaxVoid *int

	if yc != nil {
		ycMaxMsg = yc.Config.MaxMessageSize
		ycHostname = yc.Config.MailName
		ycWhite = yc.Config.WhitelistNetworks
		ycMilterAddr = yc.Config.MilterAddress
		ycValkeyUrl = yc.Config.ValkeyUrl
		if yc.Config.Mysql != nil {
			ycMysql = yc.Config.Mysql.DSN
			ycMysqlQuery = yc.Config.Mysql.Query
			ycMysqlCacheTTL = yc.Config.Mysql.CacheMins
		}
		if yc.Config.Report != nil {
			ycReportSmtp = yc.Config.Report.SMTP
			ycReportOrg = yc.Config.Report.OrgName
			ycReportEmail = yc.Config.Report.Email
			ycReportContact = yc.Config.Report.ContactInfo
			ycReportDomain = yc.Config.Report.Domain
		}
		if yc.Config.Helo != nil {
			ycHeloTTL = yc.Config.Helo.TTLDays
		}
		if yc.Config.Greylist != nil {
			ycGreyV4 = yc.Config.Greylist.IPv4Mask
			ycGreyV6 = yc.Config.Greylist.IPv6Mask
			ycGreyWait = yc.Config.Greylist.WaitMins
			ycGreyUn = yc.Config.Greylist.UnmatchedTTLDays
			ycGreyMat = yc.Config.Greylist.MatchedTTLDays
		}
		if yc.Config.SPF != nil {
			ycSPFMaxDNS = yc.Config.SPF.MaxDNSLookups
			ycSPFMaxVoid = yc.Config.SPF.MaxVoidLookups
		}
	}

	hostname := os.Getenv("MAILNAME")
	if hostname == "" && ycHostname != nil {
		hostname = *ycHostname
	}
	if hostname == "" {
		hostname = os.Getenv("HOSTNAME")
	}
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	if hostname == "" {
		hostname = "localhost"
	}

	config := &Config{
		BasePolicy: PolicyConfig{
			EnableSPF:               enableSPF,
			EnableDKIM:              enableDKIM,
			EnableDKIMATPS:          resolveBool("ENABLE_DKIM_ATPS", dfltOvr.EnableDKIMATPS, false),
			EnableDMARC:             enableDMARC,
			EnableGreylisting:       resolveBool("ENABLE_GREYLISTING", dfltOvr.EnableGreylist, false),
			EnableNullSenders:       resolveBool("ENABLE_NULL_SENDERS", dfltOvr.EnableNullSenders, true),
			RejectOnSPFFail:         rejectSPF,
			RejectOnDKIMFail:        rejectDKIM,
			RejectOnDMARCFail:       rejectDMARC,
			RejectOnUnauthenticated: resolveBool("REJECT_UNAUTHENTICATED", dfltOvr.RejectOnUnauthenticated, true),
			HeloMaxChanges:          resolveInt("HELO_MAX_CHANGES", dfltOvr.HeloMaxChanges, 0),
			GreylistWhitelistCount:  resolveInt("GREYLIST_WHITELIST_COUNT", dfltOvr.GreylistWhitelistCount, 0),
			DelayGreylisting:        resolveBool("DELAY_GREYLISTING", dfltOvr.DelayGreylisting, true),
			SPFSoftFailAsPass:       resolveBool("SPF_SOFTFAIL_AS_PASS", dfltOvr.SPFSoftFailAsPass, false),
			SPFNeutralAsPass:        resolveBool("SPF_NEUTRAL_AS_PASS", dfltOvr.SPFNeutralAsPass, false),
		},
		ValkeyURL:            resolveStr("VALKEY_URL", ycValkeyUrl, ""),
		MysqlDSN:             resolveStr("MYSQL_DSN", ycMysql, ""),
		MysqlQuery:           resolveStr("MYSQL_QUERY", ycMysqlQuery, "SELECT policy FROM mail_virtual WHERE address = ? LIMIT 1"),
		MysqlCacheTTL:        int64(resolveInt("MYSQL_CACHE_MINS", ycMysqlCacheTTL, 0) * 60),
		Hostname:             hostname,
		HeloTTL:              int64(resolveInt("HELO_TTL_DAYS", ycHeloTTL, 14) * 86400),
		GreylistIPv4Mask:     resolveInt("GREYLIST_IPV4_MASK", ycGreyV4, 24),
		GreylistIPv6Mask:     resolveInt("GREYLIST_IPV6_MASK", ycGreyV6, 64),
		GreylistWait:         int64(resolveInt("GREYLIST_WAIT_MINS", ycGreyWait, 1)*60) - 10,
		GreylistUnmatchedTTL: int64(resolveInt("GREYLIST_UNMATCHED_TTL_DAYS", ycGreyUn, 2) * 86400),
		GreylistMatchedTTL:   int64(resolveInt("GREYLIST_MATCHED_TTL_DAYS", ycGreyMat, 30) * 86400),
		WhitelistedNetworks:  parseNetworks(resolveStr("WHITELIST_NETWORKS", ycWhite, "10.0.0.0/8,192.168.0.0/16,172.16.0.0/12,127.0.0.0/8,fe80::/10,::1/128")),
		MaxMessageSize:       resolveInt("MAX_MESSAGE_SIZE", ycMaxMsg, 10485760*40),
		ReportSMTP:           resolveStr("REPORT_SMTP", ycReportSmtp, ""),
		ReportOrgName:        resolveStr("REPORT_ORG_NAME", ycReportOrg, hostname),
		ReportEmail:          resolveStr("REPORT_EMAIL", ycReportEmail, "noreply@"+hostname),
		ReportContactInfo:    resolveStr("REPORT_CONTACT_INFO", ycReportContact, ""),
		ReportDomain:         resolveStr("REPORT_DOMAIN", ycReportDomain, hostname),
		MaxSPFDNSLookups:     uint(resolveInt("MAX_SPF_DNS_LOOKUPS", ycSPFMaxDNS, 10)),
		MaxSPFVoidLookups:    uint(resolveInt("MAX_SPF_VOID_LOOKUPS", ycSPFMaxVoid, 2)),
	}

	if config.MysqlDSN != "" && yc == nil {
		log.Printf("Warning: POLICY_CONFIG_FILE is missing or invalid. Disabling MYSQL_DSN.")
		config.MysqlDSN = ""
	}

	address := resolveStr("MILTER_ADDRESS", ycMilterAddr, "127.0.0.1:9998")

	debugf("Configuration:")
	debugf("  Listening on %s", address)
	debugf("  SPF: Enable=%v Reject=%v MaxDNSLookups=%d MaxVoidLookups=%d",
		config.BasePolicy.EnableSPF, config.BasePolicy.RejectOnSPFFail,
		config.MaxSPFDNSLookups, config.MaxSPFVoidLookups)
	debugf("  DKIM: Enable=%v Reject=%v ATPS=%v", config.BasePolicy.EnableDKIM, config.BasePolicy.RejectOnDKIMFail, config.BasePolicy.EnableDKIMATPS)
	debugf("  DMARC: Enable=%v Reject=%v", config.BasePolicy.EnableDMARC, config.BasePolicy.RejectOnDMARCFail)
	debugf("  HeloMaxChanges=%d HeloTTLDays=%d", config.BasePolicy.HeloMaxChanges, int(math.Round(float64(config.HeloTTL)/86400)))
	debugf("  Greylist: Enable=%v v4=/%d v6=/%d Wait=%dm UnmatchedTTLDays=%dd MatchedTTLDays=%dd",
		config.BasePolicy.EnableGreylisting, config.GreylistIPv4Mask, config.GreylistIPv6Mask,
		int(math.Round(float64(config.GreylistWait)/60)), int(math.Round(float64(config.GreylistUnmatchedTTL)/86400)), int(math.Round(float64(config.GreylistMatchedTTL)/86400)))

	needsValkey := config.ValkeyURL != "" || config.BasePolicy.HeloMaxChanges > 0 || config.BasePolicy.EnableGreylisting
	var vc valkey.Client

	if needsValkey {
		if config.ValkeyURL == "" {
			log.Fatalf("VALKEY_URL is required since HELO checking or Greylisting is enabled. Please set VALKEY_URL, or disable them to run without Valkey.")
		}

		u, err := url.Parse(config.ValkeyURL)
		if err != nil {
			log.Fatalf("Invalid VALKEY_URL %s: %v", config.ValkeyURL, err)
		}

		var opt valkey.ClientOption
		if u.Scheme == "valkey" || u.Scheme == "valkeys" {
			opt, err = valkey.ParseURL(config.ValkeyURL)
			if err != nil {
				log.Fatalf("Invalid VALKEY_URL %s: %v", config.ValkeyURL, err)
			}
		} else if u.Scheme == "sentinel" {
			host := u.Hostname()
			port := u.Port()
			if port == "" {
				port = "26379" // default sentinel port
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			ips4, _ := net.DefaultResolver.LookupIP(ctx, "ip4", host)
			ips6, _ := net.DefaultResolver.LookupIP(ctx, "ip6", host)

			var ips []net.IP
			ips = append(ips, ips4...)
			ips = append(ips, ips6...)

			if len(ips) == 0 {
				log.Fatalf("Failed to lookup any IPv4 or IPv6 addresses for sentinel hostname %s", host)
			}
			var initAddrs []string
			for _, ip := range ips {
				addr := net.JoinHostPort(ip.String(), port)
				conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
				if err == nil {
					conn.Close()
					initAddrs = append(initAddrs, addr)
				} else {
					log.Printf("Warning: Skipping sentinel at %s, failed to connect: %v", addr, err)
				}
			}
			if len(initAddrs) == 0 {
				log.Fatalf("Failed to connect to any sentinel IP addresses for hostname %s", host)
			}

			masterName := strings.TrimPrefix(u.Path, "/")
			q := u.Query()

			dbStr := q.Get("db")

			if _, err := strconv.Atoi(masterName); err == nil {
				if dbStr == "" {
					dbStr = masterName
				}
				masterName = ""
			}

			if ms := q.Get("master_set"); ms != "" {
				masterName = ms
			}

			if masterName == "" {
				log.Fatalf("Sentinel master name must be provided in the URL path or master_set query parameter")
			}

			sentinelUser := ""
			sentinelPass := ""
			if u.User != nil {
				sentinelUser = u.User.Username()
				sentinelPass, _ = u.User.Password()
			}

			db := 0
			if dbStr != "" {
				db, err = strconv.Atoi(dbStr)
				if err != nil {
					log.Fatalf("Invalid database parameter in sentinel URL: %v", err)
				}
			}

			valkeyPass := q.Get("pass")
			if valkeyPass == "" {
				valkeyPass = sentinelPass
			}
			
			valkeyUser := q.Get("user")
			if valkeyUser == "" {
				valkeyUser = sentinelUser
			}

			opt = valkey.ClientOption{
				InitAddress: initAddrs,
				Sentinel: valkey.SentinelOption{
					MasterSet: masterName,
					Username:  sentinelUser,
					Password:  sentinelPass,
				},
				Username: valkeyUser,
				Password: valkeyPass,
				SelectDB: db,
			}
		} else {
			log.Fatalf("Unsupported VALKEY_URL scheme: %s", u.Scheme)
		}

		vc, err = valkey.NewClient(opt)
		if err != nil {
			log.Fatalf("Failed to connect to valkey: %v", err)
		}
		defer vc.Close()
		log.Println("Connected to Valkey.")
	} else if config.ValkeyURL != "" {
		log.Println("VALKEY_URL is provided, but HELO checking and Greylisting are disabled. Valkey connection will not be established.")
	}

	if *flagReport {
		generateDailyReport(config, vc, yc)
		return
	}

	var db *sql.DB
	if config.MysqlDSN != "" {
		var err error
		db, err = sql.Open("mysql", config.MysqlDSN)
		if err != nil {
			log.Fatalf("Failed to open MySQL connection: %v", err)
		}
		if err = db.Ping(); err != nil {
			log.Fatalf("Failed to ping MySQL: %v", err)
		}
		log.Println("Connected to MySQL.")
	} else {
		log.Println("MYSQL_DSN is not set, Recipient Overrides disabled.")
	}

	listener, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatalf("Failed to listen on tcp://%s: %v", address, err)
	}

	wg := &sync.WaitGroup{}
	trackedListener := &TrackedListener{Listener: listener, wg: wg}

	server := milter.Server{
		NewMilter: NewPolicyFilter(config, vc, db),
		Actions:   milter.OptAddHeader | milter.OptChangeHeader, // Can add more if modifying email
		Protocol:  0,
	}

	go func() {
		if err := server.Serve(trackedListener); err != nil && err != milter.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()
	log.Println("Milter server listening...")

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	<-sigc
	log.Println("Shutting down listener...")

	// Close listener to stop accepting new connections
	trackedListener.Listener.Close()

	log.Println("Waiting for active connections to drain...")
	wg.Wait()

	log.Println("All connections finished. Gracefully exiting.")
}

type TrackedListener struct {
	net.Listener
	wg *sync.WaitGroup
}

func (l *TrackedListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.wg.Add(1)
	return &TrackedConn{Conn: conn, wg: l.wg}, nil
}

type TrackedConn struct {
	net.Conn
	wg     *sync.WaitGroup
	closed bool
	mu     sync.Mutex
}

func (c *TrackedConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		c.wg.Done()
	}
	return c.Conn.Close()
}
