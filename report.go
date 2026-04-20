package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/valkey-io/valkey-go"
)

type Feedback struct {
	XMLName         xml.Name        `xml:"feedback"`
	ReportMetadata  ReportMetadata  `xml:"report_metadata"`
	PolicyPublished PolicyPublished `xml:"policy_published"`
	Record          []Record        `xml:"record"`
}

type ReportMetadata struct {
	OrgName          string    `xml:"org_name"`
	Email            string    `xml:"email"`
	ExtraContactInfo string    `xml:"extra_contact_info,omitempty"`
	ReportID         string    `xml:"report_id"`
	DateRange        DateRange `xml:"date_range"`
}

type DateRange struct {
	Begin int64 `xml:"begin"`
	End   int64 `xml:"end"`
}

type PolicyPublished struct {
	Domain string `xml:"domain"`
	ADKIM  string `xml:"adkim"`
	ASPF   string `xml:"aspf"`
	P      string `xml:"p"`
	SP     string `xml:"sp"`
	Pct    int    `xml:"pct"`
}

type Record struct {
	Row         Row         `xml:"row"`
	Identifiers Identifiers `xml:"identifiers"`
	AuthResults AuthResults `xml:"auth_results"`
}

type Row struct {
	SourceIP        string          `xml:"source_ip"`
	Count           int             `xml:"count"`
	PolicyEvaluated PolicyEvaluated `xml:"policy_evaluated"`
}

type PolicyEvaluated struct {
	Disposition string `xml:"disposition"`
	DKIM        string `xml:"dkim"`
	SPF         string `xml:"spf"`
}

type Identifiers struct {
	HeaderFrom string `xml:"header_from"`
}

type AuthResults struct {
	DKIM *DKIMAuthResult `xml:"dkim,omitempty"`
	SPF  *SPFAuthResult  `xml:"spf,omitempty"`
}

type DKIMAuthResult struct {
	Domain string `xml:"domain"`
	Result string `xml:"result"`
}

type SPFAuthResult struct {
	Domain string `xml:"domain"`
	Result string `xml:"result"`
}

func generateDailyReport(config *Config, vc valkey.Client, yc *YAMLConfig) {
	if vc == nil {
		log.Println("Reporting requires valkey")
		return
	}
	if config.ReportSMTP == "" {
		log.Println("Reporting requires config.ReportSMTP to be configured")
		return
	}

	smtpURL, err := url.Parse(config.ReportSMTP)
	if err != nil {
		log.Fatalf("Invalid ReportSMTP URL: %v", err)
	}
	smtpHost := smtpURL.Hostname()
	if smtpHost == "" {
		smtpHost = "127.0.0.1"
	}
	smtpPort := smtpURL.Port()
	if smtpPort == "" {
		smtpPort = "25"
	}

	var smtpAuth smtp.Auth
	if smtpURL.User != nil {
		smtpPassword, _ := smtpURL.User.Password()
		smtpAuth = smtp.PlainAuth("", smtpURL.User.Username(), smtpPassword, smtpHost)
	}

	yesterday := time.Now().Add(-24 * time.Hour)
	dateStr := yesterday.Format("20060102")

	ctx := context.Background()
	keysResult, err := vc.Do(ctx, vc.B().Keys().Pattern("dmarc_rua:"+dateStr+":*").Build()).AsStrSlice()
	if err != nil {
		log.Fatalf("Failed to retrieve dmarc keys: %v", err)
	}

	for _, key := range keysResult {
		parts := strings.Split(key, ":")
		if len(parts) < 3 {
			continue
		}
		domain := strings.Join(parts[2:], ":")

		hashRaw, err := vc.Do(ctx, vc.B().Hgetall().Key(key).Build()).AsStrMap()
		if err != nil {
			log.Printf("Failed to HGETALL %s: %v", key, err)
			continue
		}

		ruaURLs := ""
		records := []Record{}

		var pubPolicy PolicyPublished
		pubPolicy.Pct = 100
		pubPolicy.ADKIM = "r"
		pubPolicy.ASPF = "r"
		pubPolicy.P = "none"
		pubPolicy.SP = "none"

		for k, v := range hashRaw {
			if k == "_rua" {
				ruaURLs = v
				continue
			}
			if k == "_policy" {
				var pp struct {
					ADKIM string `json:"adkim"`
					ASPF  string `json:"aspf"`
					P     string `json:"p"`
					SP    string `json:"sp"`
					Pct   int    `json:"pct"`
				}
				if err := json.Unmarshal([]byte(v), &pp); err == nil {
					pubPolicy.ADKIM = pp.ADKIM
					pubPolicy.ASPF = pp.ASPF
					pubPolicy.P = pp.P
					pubPolicy.SP = pp.SP
					pubPolicy.Pct = pp.Pct
				}
				continue
			}

			count, _ := strconv.Atoi(v)
			var stat DmarcRuaStat
			if err := json.Unmarshal([]byte(k), &stat); err != nil {
				continue
			}

			rec := Record{
				Row: Row{
					SourceIP: stat.IP,
					Count:    count,
					PolicyEvaluated: PolicyEvaluated{
						Disposition: stat.Disposition,
						DKIM:        stat.DKIMResult,
						SPF:         stat.SPFResult,
					},
				},
				Identifiers: Identifiers{
					HeaderFrom: domain,
				},
				AuthResults: AuthResults{},
			}

			if stat.DKIMDomain != "" {
				rec.AuthResults.DKIM = &DKIMAuthResult{
					Domain: stat.DKIMDomain,
					Result: stat.DKIMResult,
				}
			}
			if stat.SPFDomain != "" {
				rec.AuthResults.SPF = &SPFAuthResult{
					Domain: stat.SPFDomain,
					Result: stat.SPFResult,
				}
			}

			records = append(records, rec)
		}

		if len(records) == 0 || ruaURLs == "" {
			continue
		}

		feedback := Feedback{
			ReportMetadata: ReportMetadata{
				OrgName:          config.ReportOrgName,
				Email:            config.ReportEmail,
				ExtraContactInfo: config.ReportContactInfo,
				ReportID:         fmt.Sprintf("%d", time.Now().Unix()),
				DateRange: DateRange{
					Begin: yesterday.Truncate(24 * time.Hour).Unix(),
					End:   yesterday.Truncate(24 * time.Hour).Add(24*time.Hour - 1*time.Second).Unix(),
				},
			},
			PolicyPublished: PolicyPublished{
				Domain: domain,
				ADKIM:  pubPolicy.ADKIM,
				ASPF:   pubPolicy.ASPF,
				P:      pubPolicy.P,
				SP:     pubPolicy.SP,
				Pct:    pubPolicy.Pct,
			},
			Record: records,
		}

		xmlBytes, _ := xml.MarshalIndent(feedback, "", "  ")
		xmlFull := []byte(xml.Header + string(xmlBytes))

		var gzBuf bytes.Buffer
		zw := gzip.NewWriter(&gzBuf)
		filename := fmt.Sprintf("%s!%s!%d!%d.xml", config.ReportDomain, domain, feedback.ReportMetadata.DateRange.Begin, feedback.ReportMetadata.DateRange.End)
		zw.Name = filename
		zw.Write(xmlFull)
		zw.Close()

		smtpTargets := []string{}
		httpTargets := []string{}
		for _, rawURL := range strings.Split(ruaURLs, ",") {
			rawURL = strings.TrimSpace(rawURL)
			lowerURL := strings.ToLower(rawURL)
			if strings.HasPrefix(lowerURL, "mailto:") {
				addr := strings.TrimPrefix(lowerURL, "mailto:")
				if idx := strings.Index(addr, "?"); idx != -1 {
					addr = addr[:idx]
				}
				// verify target accepts reports for reportdomain
				targetEmailDomain := addr
				if idx := strings.Index(addr, "@"); idx != -1 {
					targetEmailDomain = addr[idx+1:]
				}
				authHost := fmt.Sprintf("%s._report._dmarc.%s", domain, targetEmailDomain)
				txts, err := net.LookupTXT(authHost)
				if err != nil {
					log.Printf("DMARC report auth check failed for %s (querying %s): %v — skipping", addr, authHost, err)
					continue
				}
				authorized := false
				for _, txt := range txts {
					if strings.Contains(strings.ToLower(txt), "v=dmarc1") {
						authorized = true
						break
					}
				}
				if !authorized {
					log.Printf("DMARC report not authorized for %s (no v=DMARC1 at %s) — skipping", addr, authHost)
					continue
				}
				smtpTargets = append(smtpTargets, addr)
			} else if strings.HasPrefix(lowerURL, "http://") || strings.HasPrefix(lowerURL, "https://") {
				httpTargets = append(httpTargets, rawURL)
			}
		}

		if len(smtpTargets) > 0 {
			fromAddr := mail.Address{Name: "DMARC Reporter", Address: "noreply@" + config.ReportDomain}
			boundary := "dmarc-bnd-12345"

			var msg bytes.Buffer
			msg.WriteString(fmt.Sprintf("From: %s\r\n", fromAddr.String()))
			msg.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(smtpTargets, ", ")))
			msg.WriteString(fmt.Sprintf("Subject: Report Domain: %s Submitter: %s Report-ID: %s\r\n", domain, config.ReportDomain, feedback.ReportMetadata.ReportID))
			msg.WriteString(fmt.Sprintf("MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"%s\"\r\n\r\n", boundary))
			msg.WriteString(fmt.Sprintf("--%s\r\n", boundary))
			msg.WriteString("Content-Type: text/plain; charset=\"utf-8\"\r\n\r\n")
			msg.WriteString("Attached is an automated DMARC aggregate report.\r\n\r\n")

			msg.WriteString(fmt.Sprintf("--%s\r\n", boundary))
			msg.WriteString("Content-Type: application/gzip\r\n")
			msg.WriteString(fmt.Sprintf("Content-Disposition: attachment; filename=\"%s.gz\"\r\n", filename))
			msg.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")

			encoded := base64.StdEncoding.EncodeToString(gzBuf.Bytes())

			for i := 0; i < len(encoded); i += 76 {
				end := i + 76
				if end > len(encoded) {
					end = len(encoded)
				}
				msg.WriteString(encoded[i:end] + "\r\n")
			}

			msg.WriteString(fmt.Sprintf("\r\n--%s--\r\n", boundary))

			err = smtp.SendMail(fmt.Sprintf("%s:%s", smtpHost, smtpPort), smtpAuth, fromAddr.Address, smtpTargets, msg.Bytes())
			if err != nil {
				log.Printf("Failed to send DMARC SMTP report for %s to %v via %s: %v", domain, smtpTargets, smtpHost, err)
			} else {
				log.Printf("Sent DMARC SMTP report for %s to %v", domain, smtpTargets)
			}
		}

		if len(httpTargets) > 0 {
			client := &http.Client{Timeout: 30 * time.Second}
			for _, hURL := range httpTargets {
				req, err := http.NewRequest("POST", hURL, bytes.NewReader(gzBuf.Bytes()))
				if err != nil {
					log.Printf("Failed to create HTTP request for %s to %s: %v", domain, hURL, err)
					continue
				}
				req.Header.Set("Content-Type", "application/xml")
				req.Header.Set("Content-Encoding", "gzip")

				resp, err := client.Do(req)
				if err != nil {
					log.Printf("Failed to POST DMARC HTTP report for %s to %s: %v", domain, hURL, err)
				} else {
					resp.Body.Close()
					if resp.StatusCode >= 200 && resp.StatusCode < 300 {
						log.Printf("Sent DMARC HTTP report for %s to %s (Status: %d)", domain, hURL, resp.StatusCode)
					} else {
						log.Printf("Failed DMARC HTTP report for %s to %s (Status: %d)", domain, hURL, resp.StatusCode)
					}
				}
			}
		}
	}
}
