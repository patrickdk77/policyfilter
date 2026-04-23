package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/mail"
	"net/textproto"
	"os"
	"strconv"
	"strings"
	"time"

	"database/sql"

	"golang.org/x/net/idna"
	"gopkg.in/yaml.v3"

	"blitiri.com.ar/go/spf"
	"github.com/emersion/go-milter"
	"github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-msgauth/dmarc"
	"github.com/valkey-io/valkey-go"
)

var sld = map[string][]string{
	"at":           {"or", "priv", "gv"},
	"dz":           {"asso", "pol", "art", "tm", "soc"},
	"au":           {"asn", "id", "csiro"},
	"br":           {"social", "xyz", "wiki", "etc", "art", "rec", "am", "fm", "radio", "eco", "log", "emp", "leilao", "agr", "far", "imb", "ind", "inf", "srv", "tmp", "tur", "psi", "b", "g12", "blog", "nom", "bet", "flog", "qsl", "vlog", "esp", "def", "jus", "leg", "mp", "tc", "9guacu", "abc", "aju", "anani", "aparecida", "barueri", "belem", "bhz", "boavista", "bsb", "campinagrande", "campinas", "caxias", "contagem", "cuiaba", "curitiba", "feira", "floripa", "fortal", "foz", "goiania", "gru", "jab", "jampa", "jdf", "joinville", "londrina", "macapa", "maceio", "manaus", "maringa", "morena", "natal", "niteroi", "osasco", "palmas", "poa", "pvh", "recife", "ribeirao", "rio", "riobranco", "riopreto", "salvador", "sampa", "santamaria", "santoandre", "saobernardo", "saogonca", "sjc", "slz", "sorocaba", "the", "udi", "vix", "adm", "adv", "arq", "ato", "bib", "bio", "bmd", "cim", "cng", "cnt", "coz", "des", "det", "ecn", "enf", "eng", "eti", "fnd", "fot", "fst", "geo", "ggf", "jor", "lel", "mat", "med", "mus", "not", "ntr", "odo", "ppg", "pro", "psc", "rep", "slg", "taxi", "teo", "trd", "vet", "zlg", "api", "app", "dev", "ia", "seg", "tec", "coop", "ong"},
	"hu":           {"2000", "agrar", "bolt", "city", "film", "forum", "games", "hotel", "ingation", "jogasz", "media", "museum", "shop", "sport", "tm", "video", "vip", "lakas", "konyvelo", "mobi", "priv", "news", "suli", "tozsde", "utazas", "casino", "erotika", "erotica", "sex", "szex"},
	"nz":           {"geek", "kiwi", "gen", "maori", "cri", "govt", "health", "iwi", "parliament", "archie"},
	"ng":           {"sch", "name", "mobi", "i"},
	"in":           {"firm", "gen", "ind", "ernet"},
	"lk":           {"ngo", "soc", "tld", "assn", "grp", "hotel"},
	"tt":           {"travel", "museum", "aero", "tel", "name", "charity"},
	"tr":           {"tsk", "av", "dr", "bel", "pol", "kep", "bbs", "nom", "tel", "gen", "name"},
	"ua":           {"in", "mi", "dod"},
	"fr":           {"fm", "asso"},
	"il":           {"idf", "muni"},
	"xn--4dbrk0ce": {"idf", "muni"},
	"it":           {"difesa", "esteri"},
	"jp":           {"ad", "ed", "go", "gr", "lg", "ne", "or"},
	"ru":           {"int", "pp"},
	"za":           {"law", "nom", "school", "alt", "ngo", "tm"},
	"kr":           {"ne", "or", "re", "pe", "go", "hs", "ms", "es", "sc", "kg"},
	"es":           {"nom", "gob"},
	"th":           {"go", "mi", "or", "in"},
	"uk":           {"bl", "judiciary", "ltd", "me", "mod", "nhs", "nic", "parliament", "pic", "police", "rct", "royal", "ukaea"},
	"uyk":          {"sch"},
	"zm":           {"sch"},
	"us":           {"fed", "isa", "nsn", "dni"},
}

type PolicyConfig struct {
	EnableSPF               bool
	EnableDKIM              bool
	EnableDMARC             bool
	EnableGreylisting       bool
	EnableNullSenders       bool
	RejectOnSPFFail         bool
	RejectOnDKIMFail        bool
	RejectOnDMARCFail       bool
	RejectOnUnauthenticated bool
	HeloMaxChanges          int
	GreylistWhitelistCount  int
	DelayGreylisting        bool
	SPFSoftFailAsPass       bool
	SPFNeutralAsPass        bool
}

type Config struct {
	BasePolicy PolicyConfig

	ValkeyURL     string
	MysqlDSN      string
	MysqlQuery    string
	MysqlCacheTTL int64
	Hostname      string
	HeloTTL       int64

	GreylistIPv4Mask     int
	GreylistIPv6Mask     int
	GreylistWait         int64
	GreylistUnmatchedTTL int64
	GreylistMatchedTTL   int64

	// Verified: Array naturally transitioned to map[string][]string dictionary at Line 26
	WhitelistedNetworks []*net.IPNet
	MaxMessageSize      int
	ReportSMTP          string
	ReportOrgName       string
	ReportEmail         string
	ReportContactInfo   string
	ReportDomain        string
	MaxSPFDNSLookups    uint
	MaxSPFVoidLookups   uint
}

type YAMLConfig struct {
	Config struct {
		MaxMessageSize    *int    `yaml:"maxmessagesize"`
		MailName          *string `yaml:"mailname"`
		WhitelistNetworks *string `yaml:"whitelistnetworks"`
		MilterAddress     *string `yaml:"milteraddress"`
		ValkeyUrl         *string `yaml:"valkeyurl"`
		Mysql             *struct {
			DSN       *string `yaml:"dsn"`
			Query     *string `yaml:"query"`
			CacheMins *int    `yaml:"cachemins"`
		} `yaml:"mysql"`
		Report *struct {
			SMTP        *string `yaml:"smtp"`
			OrgName     *string `yaml:"orgname"`
			Email       *string `yaml:"email"`
			Domain      *string `yaml:"domain"`
			ContactInfo *string `yaml:"contactinfo"`
		} `yaml:"report"`
		Helo *struct {
			TTLDays *int `yaml:"ttldays"`
		} `yaml:"helo"`
		Greylist *struct {
			IPv4Mask         *int  `yaml:"ipv4mask"`
			IPv6Mask         *int  `yaml:"ipv6mask"`
			WaitMins         *int  `yaml:"waitmins"`
			UnmatchedTTLDays *int  `yaml:"unmatchedttldays"`
			MatchedTTLDays   *int  `yaml:"matchedttldays"`
			Delay            *bool `yaml:"delay"`
		} `yaml:"greylist"`
		SPF *struct {
			MaxDNSLookups  *int `yaml:"maxdnslookups"`
			MaxVoidLookups *int `yaml:"maxvoidlookups"`
		} `yaml:"spf"`
	} `yaml:"config"`
	Profiles map[string]OverridePolicy `yaml:"profiles"`
}

type OverridePolicy struct {
	EnableSPF               *bool `yaml:"EnableSPF"`
	EnableDKIM              *bool `yaml:"EnableDKIM"`
	EnableDMARC             *bool `yaml:"EnableDMARC"`
	EnableGreylist          *bool `yaml:"EnableGreylist"`
	EnableNullSenders       *bool `yaml:"EnableNullSenders"`
	RejectOnSPFFail         *bool `yaml:"RejectOnSPFFail"`
	RejectOnDKIMFail        *bool `yaml:"RejectOnDKIMFail"`
	RejectOnDMARCFail       *bool `yaml:"RejectOnDMARCFail"`
	RejectOnUnauthenticated *bool `yaml:"RejectOnUnauthenticated"`
	HeloMaxChanges          *int  `yaml:"HeloMaxChanges"`
	GreylistWhitelistCount  *int  `yaml:"GreylistWhitelistCount"`
	DelayGreylisting        *bool `yaml:"DelayGreylisting"`
	SPFSoftFailAsPass       *bool `yaml:"SPFSoftFailAsPass"`
	SPFNeutralAsPass        *bool `yaml:"SPFNeutralAsPass"`
}

type Message struct {
	policy          PolicyConfig
	sender          string
	firstRcpt       string
	queueId         string
	from            string
	msgBuf          *bytes.Buffer
	headers         map[string]string
	isNullSender    bool
	spfEvaluated    bool
	spfResult       spf.Result
	spfErr          error
	spfEffectivePass bool
	greylistDelayed bool
}

type DmarcRuaStat struct {
	IP          string `json:"ip"`
	Disposition string `json:"disposition"`
	DKIMDomain  string `json:"dkim_domain"`
	DKIMResult  string `json:"dkim_result"`
	SPFDomain   string `json:"spf_domain"`
	SPFResult   string `json:"spf_result"`
}

type PolicyFilter struct {
	milter.NoOpMilter
	config *Config
	valkey valkey.Client
	db     *sql.DB

	// Per SMTP Connection details
	ip            net.IP
	whitelisted   bool
	heloName      string
	clientResolve string
	clientPtr     string
	clientName    string
	tlsVersion    string
	cipher        string
	cipherBits    string

	// Active message tracking pointer
	msg *Message
}

var PolicyTable map[string]PolicyConfig

// setSpfResult stores the SPF verification result and pre-computes
// spfEffectivePass — whether the result counts as a pass for non-DMARC
// decisions (rejections, greylisting) — according to the active policy flags.
// Call this exactly once per message, at the moment of SPF evaluation.
func (pf *PolicyFilter) setSpfResult(result spf.Result, err error) {
	pf.msg.spfResult = result
	pf.msg.spfErr = err
	pf.msg.spfEvaluated = true
	pf.msg.spfEffectivePass = result == spf.Pass ||
		(result == spf.SoftFail && pf.msg.policy.SPFSoftFailAsPass) ||
		(result == spf.Neutral && pf.msg.policy.SPFNeutralAsPass)
}

func LoadPolicyTable(filePath string) (*YAMLConfig, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var rootConfig YAMLConfig
	if err := yaml.Unmarshal(data, &rootConfig); err != nil {
		return nil, err
	}

	normalizedTable := make(map[string]PolicyConfig)
	if rootConfig.Profiles != nil {
		mergedDefault := PolicyConfig{
			EnableSPF:               true,
			EnableDKIM:              true,
			EnableDMARC:             true,
			EnableGreylisting:       false,
			DelayGreylisting:        true,
			EnableNullSenders:       true,
			RejectOnSPFFail:         false,
			RejectOnDKIMFail:        false,
			RejectOnDMARCFail:       true,
			RejectOnUnauthenticated: true,
			HeloMaxChanges:          0,
			GreylistWhitelistCount:  0,
		}

		for k, ovr := range rootConfig.Profiles {
			mergedPolicy := mergedDefault
			mergeOverride(&mergedPolicy, ovr)
			normalizedTable[strings.ToLower(k)] = mergedPolicy
		}
	}

	PolicyTable = normalizedTable
	return &rootConfig, nil
}

func mergeOverride(mergedPolicy *PolicyConfig, ovr OverridePolicy) {
	if ovr.EnableSPF != nil {
		mergedPolicy.EnableSPF = *ovr.EnableSPF
	}
	if ovr.EnableDKIM != nil {
		mergedPolicy.EnableDKIM = *ovr.EnableDKIM
	}
	if ovr.EnableDMARC != nil {
		mergedPolicy.EnableDMARC = *ovr.EnableDMARC
	}
	if ovr.EnableGreylist != nil {
		mergedPolicy.EnableGreylisting = *ovr.EnableGreylist
	}
	if ovr.EnableNullSenders != nil {
		mergedPolicy.EnableNullSenders = *ovr.EnableNullSenders
	}
	if ovr.RejectOnSPFFail != nil {
		mergedPolicy.RejectOnSPFFail = *ovr.RejectOnSPFFail
	}
	if ovr.RejectOnDKIMFail != nil {
		mergedPolicy.RejectOnDKIMFail = *ovr.RejectOnDKIMFail
	}
	if ovr.RejectOnDMARCFail != nil {
		mergedPolicy.RejectOnDMARCFail = *ovr.RejectOnDMARCFail
	}
	if ovr.RejectOnUnauthenticated != nil {
		mergedPolicy.RejectOnUnauthenticated = *ovr.RejectOnUnauthenticated
	}
	if ovr.HeloMaxChanges != nil {
		mergedPolicy.HeloMaxChanges = *ovr.HeloMaxChanges
	}
	if ovr.GreylistWhitelistCount != nil {
		mergedPolicy.GreylistWhitelistCount = *ovr.GreylistWhitelistCount
	}
	if ovr.DelayGreylisting != nil {
		mergedPolicy.DelayGreylisting = *ovr.DelayGreylisting
	}
}

func (pf *PolicyFilter) debugf(format string, v ...any) {
	if !debugLog {
		return
	}
	if pf.msg != nil && pf.msg.queueId != "" {
		log.Printf("[%s] "+format, append([]any{pf.msg.queueId}, v...)...)
	} else {
		log.Printf(format, v...)
	}
}

func (pf *PolicyFilter) updateMacros(m *milter.Modifier) {
	if m != nil && m.Macros != nil {
		if qid, ok := m.Macros["i"]; ok && qid != "" {
			if pf.msg != nil {
				pf.msg.queueId = qid
			}
		}
		if hostname, ok := m.Macros["j"]; ok && hostname != "" {
			pf.config.Hostname = hostname
		}
		if addrStr, ok := m.Macros["{client_addr}"]; ok && addrStr != "" {
			if parsed := net.ParseIP(addrStr); parsed != nil {
				pf.ip = parsed
			}
		}
		if resolve, ok := m.Macros["{client_resolve}"]; ok && resolve != "" {
			pf.clientResolve = resolve
		}
		if ptr, ok := m.Macros["{client_ptr}"]; ok && ptr != "" {
			pf.clientPtr = ptr
		}
		if name, ok := m.Macros["{client_name}"]; ok && name != "" {
			pf.clientName = name
		}
		if tv, ok := m.Macros["{tls_version}"]; ok && tv != "" {
			pf.tlsVersion = tv
		}
		if c, ok := m.Macros["{cipher}"]; ok && c != "" {
			pf.cipher = c
		}
		if cb, ok := m.Macros["{cipher_bits}"]; ok && cb != "" {
			pf.cipherBits = cb
		}
	}
}

func NewPolicyFilter(cfg *Config, vc valkey.Client, db *sql.DB) func() milter.Milter {
	return func() milter.Milter {
		sessionCfg := *cfg // clone connection context config
		return &PolicyFilter{
			config: &sessionCfg,
			valkey: vc,
			db:     db,
		}
	}
}

func (pf *PolicyFilter) isWhitelistedIP() bool {
	for _, network := range pf.config.WhitelistedNetworks {
		if network.Contains(pf.ip) {
			return true
		}
	}
	return false
}

func (pf *PolicyFilter) Connect(host string, family string, port uint16, addr net.IP, m *milter.Modifier) (milter.Response, error) {
	pf.updateMacros(m)
	if addr == nil || addr.String() == "<nil>" {
		pf.debugf("Rejecting invalid client IP: '%v'", addr)
		return milter.NewResponseStr('4', "4.3.0 Invalid client IP"), nil
	}
	pf.ip = addr
	pf.whitelisted = pf.isWhitelistedIP() // Compute only once dynamically per socket layer

	return milter.RespContinue, nil
}

func (pf *PolicyFilter) Helo(name string, m *milter.Modifier) (milter.Response, error) {
	pf.updateMacros(m)
	if pf.whitelisted {
		return milter.RespContinue, nil
	}

	if name == "" || strings.ToLower(name) == "unknown" {
		pf.debugf("Rejecting invalid or unknown HELO name: '%s'", name)
		return milter.NewResponseStr('4', "4.5.0 Invalid or unknown HELO name"), nil
	}
	if asciiName, err := idna.ToASCII(name); err == nil {
		name = asciiName
	}
	pf.heloName = strings.ToLower(name)

	if pf.valkey != nil && pf.config.BasePolicy.HeloMaxChanges > 0 {
		ctx := context.Background()
		clientIP := pf.ip.String()
		key := fmt.Sprintf("helo:%s", clientIP)
		heloTTLSecs := pf.config.HeloTTL

		script := `
			local field_ttl_resp = redis.call('HTTL', KEYS[1], 'FIELDS', '1', ARGV[1])
			local current_ttl = tonumber(field_ttl_resp[1])
			local max_ttl = tonumber(ARGV[2])

			if current_ttl < 0 then
				redis.call('HSET', KEYS[1], ARGV[1], "1")
				redis.call('HEXPIRE', KEYS[1], max_ttl, 'FIELDS', '1', ARGV[1])
			elseif current_ttl < (max_ttl / 2) then
				redis.call('HEXPIRE', KEYS[1], max_ttl, 'FIELDS', '1', ARGV[1])
			end

			local key_ttl = redis.call('TTL', KEYS[1])
			if key_ttl < (max_ttl / 2) then
				redis.call('EXPIRE', KEYS[1], max_ttl)
			end

			return redis.call('HLEN', KEYS[1])
		`

		cmd := pf.valkey.B().Eval().Script(script).Numkeys(1).Key(key).Arg(name).Arg(strconv.FormatInt(heloTTLSecs, 10)).Build()
		resp := pf.valkey.Do(ctx, cmd)

		count, err := resp.AsInt64()
		if err == nil {
			if int(count) > 1 {
				pf.debugf("IP %s has used %d unique HELO names (limit %d)", clientIP, count, pf.config.BasePolicy.HeloMaxChanges)
			}
			if int(count) > pf.config.BasePolicy.HeloMaxChanges {
				pf.debugf("Rejecting IP %s for excessive HELO changes", clientIP)
				return milter.NewResponseStr('5', "5.7.1 Too many HELO names for this IP"), nil
			}
		} else {
			pf.debugf("Error evaluating HELO anomalies from valkey script: %v", err)
		}
	}

	return milter.RespContinue, nil
}

func (pf *PolicyFilter) MailFrom(from string, m *milter.Modifier) (milter.Response, error) {
	// 1. Reset pipelined session state for new message securely via GC separation
	pf.msg = &Message{
		policy:  pf.config.BasePolicy,
		msgBuf:  &bytes.Buffer{},
		headers: make(map[string]string),
	}

	// 2. Extract new message phase macros
	pf.updateMacros(m)

	if pf.whitelisted {
		return milter.RespContinue, nil
	}

	sender := strings.TrimSpace(from)
	sender = strings.Trim(sender, "<> \"'") // Strip brackets and bounding whitespace robustly

	pf.msg.isNullSender = sender == ""

	parts := strings.SplitN(sender, "@", 2)
	if len(parts) == 2 {
		if asciiDomain, err := idna.ToASCII(parts[1]); err == nil {
			sender = parts[0] + "@" + strings.ToLower(asciiDomain)
		}
	}
	pf.msg.sender = sender

	return milter.RespContinue, nil
}

func maskIP(ip net.IP, v4Mask, v6Mask int) string {
	if ip.To4() != nil {
		mask := net.CIDRMask(v4Mask, 32)
		return ip.To4().Mask(mask).String()
	}
	mask := net.CIDRMask(v6Mask, 128)
	return ip.To16().Mask(mask).String()
}

func convertEmailToPunycode(email string) string {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) == 2 {
		if asciiDomain, err := idna.ToASCII(parts[1]); err == nil {
			return parts[0] + "@" + strings.ToLower(asciiDomain)
		}
	}
	return email
}

func extractDomainFromAddress(addr string) string {
	// Unfold RFC 2822 folded header whitespace (CRLF + WSP)
	addr = strings.ReplaceAll(addr, "\r\n", " ")
	addr = strings.ReplaceAll(addr, "\n", " ")
	addr = strings.TrimSpace(addr)

	// Use the standard library parser which handles display names and angle brackets
	if parsed, err := mail.ParseAddress(addr); err == nil {
		addr = parsed.Address
	} else {
		// Fallback: extract content inside angle brackets if present
		if start := strings.LastIndex(addr, "<"); start != -1 {
			if end := strings.Index(addr[start:], ">"); end != -1 {
				addr = addr[start+1 : start+end]
			}
		}
	}

	parts := strings.SplitN(addr, "@", 2)
	if len(parts) == 2 {
		domain := strings.ToLower(strings.TrimSpace(parts[1]))
		if asciiDomain, err := idna.ToASCII(domain); err == nil {
			return asciiDomain
		}
		return domain
	}
	return ""
}

func (pf *PolicyFilter) RcptTo(rcptTo string, m *milter.Modifier) (milter.Response, error) {
	pf.updateMacros(m)

	if pf.whitelisted {
		return milter.RespContinue, nil
	}

	rcpt := strings.Trim(rcptTo, "<>")
	if rcpt != "" && rcpt != "<>" && !strings.Contains(rcpt, "@") {
		pf.debugf("Rejecting invalid recipient address: '%s'", rcpt)
		return milter.NewResponseStr('4', "4.1.3 Invalid recipient address"), nil
	}

	if pf.db != nil && pf.msg.firstRcpt == "" {
		pf.msg.firstRcpt = rcpt
		queryAddress := convertEmailToPunycode(rcpt)

		var policyStr string
		cacheHit := false

		if pf.valkey != nil && pf.config.MysqlCacheTTL > 0 {
			cacheKey := "policy_cache:" + queryAddress
			ctxC := context.Background()
			if cached, err := pf.valkey.Do(ctxC, pf.valkey.B().Get().Key(cacheKey).Build()).AsBytes(); err == nil {
				policyStr = string(cached)
				cacheHit = true
				//pf.debugf("Policy cache hit for %s: %s", queryAddress, policyStr)
			}
		}

		if !cacheHit {
			err := pf.db.QueryRow(pf.config.MysqlQuery, queryAddress).Scan(&policyStr)
			if err != nil && err != sql.ErrNoRows {
				pf.debugf("Error querying recipient policy for %s: %v", queryAddress, err)
				policyStr = ""
			} else if err == nil && pf.valkey != nil && pf.config.MysqlCacheTTL > 0 {
				cacheKey := "policy_cache:" + queryAddress
				ctxC := context.Background()
				pf.valkey.Do(ctxC, pf.valkey.B().Set().Key(cacheKey).Value(policyStr).ExSeconds(pf.config.MysqlCacheTTL).Build())
				//pf.debugf("Policy cache set for %s: %s (TTL %ds)", queryAddress, policyStr, pf.config.MysqlCacheTTL)
			}
		}

		if policyStr != "" {
			if override, exists := PolicyTable[strings.ToLower(policyStr)]; exists {
				cacheStr := ""
				if cacheHit {
					cacheStr = " (cache hit)"
				} else if pf.valkey != nil && pf.config.MysqlCacheTTL > 0 {
					cacheStr = " (cache miss)"
				}
				pf.debugf("Applied policy '%s' for first recipient %s%s", policyStr, queryAddress, cacheStr)
				pf.msg.policy = override
			}
		}
	}

	if pf.msg.policy.EnableSPF && !pf.msg.spfEvaluated {
		spfOpts := []spf.Option{
			spf.OverrideLookupLimit(pf.config.MaxSPFDNSLookups),
			spf.OverrideVoidLookupLimit(pf.config.MaxSPFVoidLookups),
		}
		result, err := spf.CheckHostWithSender(pf.ip, pf.heloName, pf.msg.sender, spfOpts...)
		pf.setSpfResult(result, err)
		//pf.debugf("SPF Evaluated early during RcptTo: %v (err: %v)", pf.msg.spfResult, pf.msg.spfErr)
	}

	if pf.valkey != nil && pf.msg.policy.EnableGreylisting {
		if pf.msg.spfEvaluated && pf.msg.spfEffectivePass {
			pf.debugf("Skipping greylisting because SPF passed (result: %v).", pf.msg.spfResult)
			return milter.RespContinue, nil
		}

		ctx := context.Background()

		if pf.msg.policy.GreylistWhitelistCount > 0 {
			successKey := "gl_success:" + pf.ip.String()
			scriptLen := `return redis.call('HLEN', KEYS[1])`
			cmdLen := pf.valkey.B().Eval().Script(scriptLen).Numkeys(1).Key(successKey).Build()
			count, _ := pf.valkey.Do(ctx, cmdLen).AsInt64()
			if count >= int64(pf.msg.policy.GreylistWhitelistCount) {
				pf.debugf("Bypassing greylisting, IP %s has %d active successes", pf.ip.String(), count)
				return milter.RespContinue, nil
			}
		}

		maskedIP := maskIP(pf.ip, pf.config.GreylistIPv4Mask, pf.config.GreylistIPv6Mask)

		if asciiRcpt, err := idna.ToASCII(rcpt); err == nil {
			rcpt = asciiRcpt
		}

		key := fmt.Sprintf("gl:%s:%s:%s", maskedIP, pf.msg.sender, rcpt)
		now := time.Now().Unix()

		resp, err := pf.valkey.Do(ctx, pf.valkey.B().Get().Key(key).Build()).AsInt64()
		if valkey.IsValkeyNil(err) {
			// No record exists
			pf.valkey.Do(ctx, pf.valkey.B().Set().Key(key).Value(strconv.FormatInt(now, 10)).ExSeconds(pf.config.GreylistUnmatchedTTL).Build())
			pf.debugf("Greylisting NEW triplet (IP %s, Sender %s, Rcpt %s)", maskedIP, pf.msg.sender, rcpt)
			if pf.msg.policy.DelayGreylisting {
				pf.msg.greylistDelayed = true
				return milter.RespContinue, nil
			}
			return milter.NewResponseStr('4', "4.7.1 Greylisted, please try again later"), nil
		} else if err != nil {
			pf.debugf("Greylist Valkey error: %v", err)
			return milter.RespContinue, nil
		}

		if now < resp+pf.config.GreylistWait {
			pf.debugf("Greylisting WAITING triplet (IP %s, Sender %s, Rcpt %s)", maskedIP, pf.msg.sender, rcpt)
			if pf.msg.policy.DelayGreylisting {
				pf.msg.greylistDelayed = true
				return milter.RespContinue, nil
			}
			return milter.NewResponseStr('4', "4.7.1 Greylisted, please try again later"), nil
		} else {
			pf.valkey.Do(ctx, pf.valkey.B().Expire().Key(key).Seconds(pf.config.GreylistMatchedTTL).Build())
			pf.debugf("Greylisting PASSED triplet (IP %s, Sender %s, Rcpt %s)", maskedIP, pf.msg.sender, rcpt)

			if pf.msg.policy.GreylistWhitelistCount > 0 {
				successKey := "gl_success:" + pf.ip.String()
				successField := pf.msg.sender + ":" + rcpt
				scriptSuccess := `
					redis.call('HSET', KEYS[1], ARGV[1], '1')
					redis.call('HEXPIRE', KEYS[1], tonumber(ARGV[2]), 'FIELDS', '1', ARGV[1])
					local key_ttl = redis.call('TTL', KEYS[1])
					if key_ttl < (tonumber(ARGV[2]) / 2) then
						redis.call('EXPIRE', KEYS[1], tonumber(ARGV[2]))
					end
				`
				cmdSuccess := pf.valkey.B().Eval().Script(scriptSuccess).Numkeys(1).Key(successKey).Arg(successField).Arg(strconv.FormatInt(pf.config.GreylistMatchedTTL, 10)).Build()
				pf.valkey.Do(ctx, cmdSuccess)
			}
		}
	}

	return milter.RespContinue, nil
}

func (pf *PolicyFilter) Header(name string, value string, m *milter.Modifier) (milter.Response, error) {
	// Reconstruct the header line mechanically without format parsing allocations
	pf.msg.msgBuf.WriteString(name)
	pf.msg.msgBuf.WriteString(": ")
	pf.msg.msgBuf.WriteString(value)
	pf.msg.msgBuf.WriteString("\r\n")

	if strings.EqualFold(name, "From") {
		pf.msg.from = value
	}

	return milter.RespContinue, nil
}

func (pf *PolicyFilter) Headers(h textproto.MIMEHeader, m *milter.Modifier) (milter.Response, error) {
	// End of headers -> add a blank line
	pf.msg.msgBuf.WriteString("\r\n")
	return milter.RespContinue, nil
}

func (pf *PolicyFilter) BodyChunk(chunk []byte, m *milter.Modifier) (milter.Response, error) {
	if pf.msg.msgBuf.Len()+len(chunk) > pf.config.MaxMessageSize {
		pf.debugf("Rejecting message: exceeded MaxMessageSize of %d bytes", pf.config.MaxMessageSize)
		return milter.NewResponseStr('5', "5.3.4 Message size exceeds maximum allowed size"), nil
	}
	pf.msg.msgBuf.Write(chunk)
	return milter.RespContinue, nil
}

func (pf *PolicyFilter) Body(m *milter.Modifier) (milter.Response, error) {
	pf.updateMacros(m)
	if pf.whitelisted {
		return milter.RespContinue, nil
	}

	pf.debugf("Processing message from %s (IP: %s)", pf.msg.sender, pf.ip)

	policy := pf.msg.policy
	bypassRejections := policy.EnableNullSenders && pf.msg.isNullSender
	var dkimPass bool = false
	var dmarcPass bool = false

	var spfErr error = pf.msg.spfErr
	var spfResult spf.Result = pf.msg.spfResult
	if policy.EnableSPF {
		if !pf.msg.spfEvaluated {
			result, err := spf.CheckHostWithSender(pf.ip, pf.heloName, pf.msg.sender)
			pf.setSpfResult(result, err)
			spfResult = result
			spfErr = err
		}
		pf.debugf("SPF Result: %v (err: %v)", spfResult, spfErr)
	}

	// 2. DKIM Validation
	var dkimDomains []string
	var dkimResults []*dkim.Verification
	if policy.EnableDKIM || policy.EnableDMARC {
		// Read entire payload for signature scanning natively without buffering duplication
		r := bytes.NewReader(pf.msg.msgBuf.Bytes())
		verifications, err := dkim.Verify(r)
		if err != nil && err != io.EOF {
			pf.debugf("DKIM Verify error: %v", err)
		} else {
			dkimResults = verifications
			for _, v := range verifications {
				if v.Err == nil {
					pf.debugf("DKIM Passed for domain: %s", v.Domain)
					dkimPass = true

					d := v.Domain
					if asciiDomain, err := idna.ToASCII(d); err == nil {
						d = asciiDomain
					}
					dkimDomains = append(dkimDomains, strings.ToLower(d))
				} else {
					pf.debugf("DKIM Failed for domain %s: %v", v.Domain, v.Err)
				}
			}
		}
	}

	// 3. DMARC Validation
	var dmarcRecord *dmarc.Record
	fromDomain := ""
	if pf.msg.policy.EnableDMARC && pf.msg.from != "" {
		// Extract domain from 'From' header
		fromDomain = extractDomainFromAddress(pf.msg.from)
		if fromDomain != "" {
			var dmarcErr error
			dmarcRecord, dmarcErr = dmarc.Lookup(fromDomain)
			if dmarcErr != nil {
				pf.debugf("DMARC Lookup error for domain %s: %v", fromDomain, dmarcErr)
			} else {
				pf.debugf("DMARC Record for %s: %+v", fromDomain, dmarcRecord)

				// Very basic DMARC evaluation
				// Checks if either SPF or DKIM passed in alignment with From domain
				spfAligned := false
				dkimAligned := false

				// Check DKIM Alignment
				if dkimPass {
					for _, d := range dkimDomains {
						if isAligned(fromDomain, d, dmarcRecord.DKIMAlignment) {
							dkimAligned = true
							break
						}
					}
				}

				senderDomain := extractDomainFromAddress(pf.msg.sender)
				if pf.msg.policy.EnableSPF {
					if isAligned(fromDomain, senderDomain, dmarcRecord.SPFAlignment) {
						if spfResult == spf.Pass {
							//pf.debugf("DMARC SPF aligned successfully")
							spfAligned = true
						}
					}
				}

				if dkimAligned || spfAligned {
					dmarcPass = true
				}

				if pf.valkey != nil {
					disposition := string(dmarcRecord.Policy)
					if dmarcPass {
						disposition = "none"
					}

					dkimDom := ""
					dkimRes := "none"
					if len(dkimResults) > 0 {
						dkimRes = "fail"
						for _, v := range dkimResults {
							if v.Err == nil {
								dkimDom = v.Domain
								dkimRes = "pass"
								break
							} else if dkimDom == "" {
								dkimDom = v.Domain
							}
						}
					}

					spfResStr := "none"
					switch spfResult {
					case spf.Pass:
						spfResStr = "pass"
					case spf.Fail, spf.SoftFail:
						spfResStr = "fail"
					case spf.PermError, spf.TempError:
						spfResStr = "error"
					}

					stat := DmarcRuaStat{
						IP:          pf.ip.String(),
						Disposition: disposition,
						DKIMDomain:  dkimDom,
						DKIMResult:  dkimRes,
						SPFDomain:   senderDomain,
						SPFResult:   spfResStr,
					}

					if b, err := json.Marshal(stat); err == nil {
						key := fmt.Sprintf("dmarc_rua:%s:%s", time.Now().Format("20060102"), fromDomain)
						luaScript := `
							redis.call('HINCRBY', KEYS[1], ARGV[1], 1)
							if ARGV[2] ~= "" then
								redis.call('HSET', KEYS[1], '_rua', ARGV[2])
							end
							if ARGV[3] ~= "" then
								redis.call('HSET', KEYS[1], '_policy', ARGV[3])
							end
							redis.call('EXPIRE', KEYS[1], 180000)
							return 1
						`

						ruaStr := ""
						if len(dmarcRecord.ReportURIAggregate) > 0 {
							ruaStr = strings.Join(dmarcRecord.ReportURIAggregate, ",")
						}

						pct := 100
						if dmarcRecord.Percent != nil {
							pct = *dmarcRecord.Percent
						}

						policyBlob, _ := json.Marshal(map[string]any{
							"domain": fromDomain,
							"adkim":  string(dmarcRecord.DKIMAlignment),
							"aspf":   string(dmarcRecord.SPFAlignment),
							"p":      string(dmarcRecord.Policy),
							"sp":     string(dmarcRecord.SubdomainPolicy),
							"pct":    pct,
						})

						go func(k, s, r, pol string) {
							ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
							defer cancel()
							pf.valkey.Do(ctx, pf.valkey.B().Eval().Script(luaScript).Numkeys(1).Key(k).Arg(s).Arg(r).Arg(pol).Build())
						}(key, string(b), ruaStr, string(policyBlob))
					}
				}

				if dmarcPass {
					pf.debugf("DMARC validation passed, SPF aligned: %t, DKIM aligned: %t", spfAligned, dkimAligned)
				} else {
					pf.debugf("DMARC validation failed or no passing/aligned signatures, SPF aligned: %t, DKIM aligned: %t", spfAligned, dkimAligned)
					if pf.msg.policy.RejectOnDMARCFail && !bypassRejections && !dmarcPass && dmarcRecord.Policy == dmarc.PolicyReject {
						pf.debugf("Rejecting message: DMARC policy failed, From: %v, Sender: %v, Rcpt: %v", fromDomain, senderDomain, pf.msg.firstRcpt)
						return milter.NewResponseStr('5', "5.7.1 DMARC policy failed"), nil
					}
				}
			}
		} else {
			pf.debugf("Skipping DMARC, NO dns records structurally bound for domain %v", fromDomain)
		}
	}

	// effectiveSPFPass is pre-computed once when SPF is evaluated (see setSpfResult).
	effectiveSPFPass := pf.msg.spfEffectivePass

	// 4. Combined Authentication Check
	if pf.msg.policy.EnableSPF && pf.msg.policy.EnableDKIM && pf.msg.policy.RejectOnUnauthenticated && !bypassRejections && !dmarcPass {
		if !effectiveSPFPass && !dkimPass {
			pf.debugf("Rejecting because neither SPF nor DKIM passed")
			if spfResult == spf.TempError {
				return milter.NewResponseStr('4', "4.7.1 Message is not authenticated (SPF/DKIM failed)"), nil
			}
			return milter.NewResponseStr('5', "5.7.1 Message is not authenticated (SPF/DKIM failed)"), nil
		}
	}

	if policy.EnableSPF && policy.RejectOnSPFFail && !bypassRejections && !dmarcPass && spfResult == spf.Fail {
		pf.debugf("Rejecting message: SPF validation failed")
		return milter.NewResponseStr('5', "5.7.1 SPF validation failed"), nil
	}

	if pf.msg.policy.EnableDKIM && pf.msg.policy.RejectOnDKIMFail && !bypassRejections && !dmarcPass && !dkimPass && len(dkimResults) > 0 {
		pf.debugf("Rejecting message: DKIM signature missing or invalid")
		return milter.NewResponseStr('5', "5.7.1 DKIM signature missing or invalid"), nil
	}

	if !effectiveSPFPass && !dmarcPass && !dkimPass && pf.msg.greylistDelayed {
		pf.debugf("Applying delayed Greylisting rejection after payload analysis")
		return milter.NewResponseStr('4', "4.7.1 Greylisted, please try again later"), nil
	} else if pf.msg.greylistDelayed {
		pf.debugf("Not applying delayed Greylisting rejection after payload analysis due to authentication")
	}

	if policy.EnableSPF || policy.EnableDKIM || policy.EnableDMARC {
		var ar strings.Builder
		ar.WriteString("Authentication-Results: ")
		ar.WriteString(pf.config.Hostname)
		ar.WriteByte(';')

		// SPF entry
		if policy.EnableSPF {
			var resStr string
			switch spfResult {
			case spf.Pass:
				resStr = "pass"
			case spf.Fail, spf.SoftFail:
				resStr = "fail"
			case spf.PermError, spf.TempError:
				resStr = "error"
			default:
				resStr = "none"
			}
			fmt.Fprintf(&ar, "\r\n       spf=%s (%s: domain of %s designates %s as permitted sender) smtp.mailfrom=%s;",
				resStr, pf.config.Hostname, pf.msg.sender, pf.ip.String(), pf.msg.sender)
		}

		// DKIM entry/entries
		if policy.EnableDKIM {
			if len(dkimResults) > 0 {
				var dkimPassStr string
				var domain string
				valid := false
				var errStr string
				for _, v := range dkimResults {
					domain = v.Domain
					if v.Err == nil {
						valid = true
						break
					} else {
						errStr = v.Err.Error()
					}
				}
				if valid {
					dkimPassStr = "pass"
				} else {
					dkimPassStr = "fail (" + errStr + ")"
				}
				fmt.Fprintf(&ar, "\r\n       dkim=%s header.i=@%s;", dkimPassStr, domain)
			}
		}

		// DMARC entry
		if policy.EnableDMARC && fromDomain != "" {
			dmarcResStr := "fail"
			if dmarcPass {
				dmarcResStr = "pass"
			} else if dmarcRecord == nil {
				dmarcResStr = "none"
			}
			fmt.Fprintf(&ar, "\r\n       dmarc=%s header.from=%s;", dmarcResStr, fromDomain)
		}

		// BIMI
		if policy.EnableDMARC && fromDomain != "" {
			bimiPassStr := "skipped"
			if dmarcPass {
				bimiPassStr = "none"

				lookupBimi := func(domain string) string {
					txts, err := net.LookupTXT("default._bimi." + domain)
					if err == nil {
						for _, txt := range txts {
							if strings.HasPrefix(txt, "v=BIMI1;") || strings.HasPrefix(txt, "v=BIMI1 ") {
								return txt
							}
						}
					}
					return ""
				}

				record := lookupBimi(fromDomain)
				if record == "" {
					org := getOrgDomain(fromDomain)
					if org != fromDomain {
						record = lookupBimi(org)
					}
				}

				if record != "" {
					bimiPassStr = "pass"
				}
			}
			fmt.Fprintf(&ar, "\r\n       bimi=%s header.d=%s;", bimiPassStr, fromDomain)
		}

		// IPRev
		clientResolve := pf.clientResolve
		if clientResolve == "" && pf.clientName != "" {
			if strings.ToLower(pf.clientName) == "unknown" {
				clientResolve = "FAIL"
			} else {
				clientResolve = "OK"
			}
		}

		if clientResolve != "" {
			iprevRes := "none"
			switch strings.ToUpper(clientResolve) {
			case "OK":
				iprevRes = "pass"
			case "FAIL", "NXDOMAIN", "FORGED":
				iprevRes = "fail"
			case "TEMP":
				iprevRes = "temperror"
			}

			ptrPart := ""
			if pf.clientPtr != "" && strings.ToLower(pf.clientPtr) != "unknown" {
				ptrPart = fmt.Sprintf(" policy.iprev=%s", pf.clientPtr)
			} else if pf.ip != nil {
				ptrPart = fmt.Sprintf(" smtp.remote-ip=%s", pf.ip.String())
			}
			fmt.Fprintf(&ar, "\r\n       iprev=%s%s;", iprevRes, ptrPart)
		}

		// TLS
		if pf.tlsVersion != "" {
			var tlsPart strings.Builder
			fmt.Fprintf(&tlsPart, " tls.version=%s", pf.tlsVersion)
			if pf.cipher != "" {
				fmt.Fprintf(&tlsPart, " tls.cipher=%s", pf.cipher)
			}
			if pf.cipherBits != "" {
				fmt.Fprintf(&tlsPart, " tls.bits=%s", pf.cipherBits)
			}
			fmt.Fprintf(&ar, "\r\n       tls=pass%s;", tlsPart.String())
		}

		// Strip trailing ';' and emit header
		headerVal := strings.TrimSuffix(ar.String(), ";")
		m.AddHeader("Authentication-Results", headerVal)
	}

	return milter.RespAccept, nil
}

func (pf *PolicyFilter) Abort(m *milter.Modifier) error {
	pf.msg = nil // Drop payload securely to defer payload memory cleanly
	return nil
}

func getOrgDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) >= 3 {
		switch parts[len(parts)-2] {
		case "org", "net", "gov", "edu", "co", "com", "ac", "mil", "tv", "info", "web", "biz", "k12":
			return parts[len(parts)-3] + "." + parts[len(parts)-2] + "." + parts[len(parts)-1]
		}
		tld := parts[len(parts)-1]
		sldPrefix := parts[len(parts)-2]
		if prefixes, ok := sld[tld]; ok {
			for _, prefix := range prefixes {
				if prefix == sldPrefix {
					return parts[len(parts)-3] + "." + parts[len(parts)-2] + "." + parts[len(parts)-1]
				}
			}
		}
	}

	if len(parts) >= 2 {
		return parts[len(parts)-2] + "." + parts[len(parts)-1]
	}

	return domain
}

func isAligned(fromDomain, testDomain string, mode dmarc.AlignmentMode) bool {
	fromDomain = strings.ToLower(fromDomain)
	testDomain = strings.ToLower(testDomain)

	if mode == dmarc.AlignmentStrict {
		return fromDomain == testDomain
	}

	// Relaxed alignment: base domain must match, quick check before we attempt organization matches
	if fromDomain == testDomain || strings.HasSuffix(fromDomain, "."+testDomain) || strings.HasSuffix(testDomain, "."+fromDomain) {
		return true
	}

	// DMARC says for relaxed alignment, we should use organization domain, but this changes between TLDs and some resell subdomains
	// So we will use a simple version for now, that does not need external lookups
	return getOrgDomain(fromDomain) == getOrgDomain(testDomain)
}
