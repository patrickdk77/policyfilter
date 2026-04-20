# Postfix Policy Filter (Milter)

A Postfix Mail Filter (Milter) written in Go that performs SPF, DKIM, DMARC validations, unique HELO rate tracking, and dynamic Triplet Greylisting with MySQL recipient-based policy overrides.

This is built as a Milter rather than a standard delegate policy filter because DKIM and DMARC require access to the message headers and body.

## Features

- **Header Modification (`Authentication-Results`):** If DMARC, DKIM, or SPF checking is enabled, an `Authentication-Results` header will be structurally compiled and appended via `m.AddHeader()` detailing the exact passing and failing results cleanly matching RFC conventions.
- **Combined Authentication Security:** Ensures messages explicitly fail if neither SPF nor DKIM passes, safeguarding domains from unauthenticated access patterns.
- **Per-Recipient Overrides (MySQL):** Extracts the initial recipient's email address during the `RcptTo` stage, enforcing ASCII (Punycode) character encoding standards on the domain. Then, it utilizes `MYSQL_DSN` to evaluate `SELECT policy FROM mail_virtual WHERE address = ? LIMIT 1`. Depending entirely on this return string (`accept`, `greylist`, `spam`, `virus`, `default`), the internal parameters are temporarily superseded for the envelope.
- **Greylisting (Valkey):** Intercepts the `RcptTo` callback to evaluate the `Client IP Mask` + `Sender` + `Recipient` triplet against Valkey. If this triplet hasn't been observed, or retry occurred too soon within the `GREYLIST_WAIT_MINS` period, it produces an immediate `451 4.7.1 Greylisted` response. Successful matches increase the record retention lifespan drastically to reward good MTAs!
- **HELO Tracking (Valkey):** Tracks unique HELO names per IP using a Sorted Set. If the IP rotates HELO names more than `HELO_MAX_CHANGES` within `HELO_TTL_SECONDS`, the connection is immediately rejected during the HELO callback.
- **Validation Execution:** During the End of Message callback (`Body` method), it evaluates:
  - `spf.CheckHostWithSender()` to validate SPF.
  - `dkim.Verify()` to validate signatures against DNS-published public keys.
  - `dmarc.Lookup()` to fetch the DMARC policy from DNS and compare the SPF/DKIM validation outputs to check for strict/relaxed domain alignment.

## Configuration (Environment Variables)

This application is configured natively through environment flags:

### Validation Checks
**Note:** The `ENABLE_*` flags accept `true`, `false`, or `reject` (applies the check and rejects bad results).
- `ENABLE_SPF` (default `true`)
- `ENABLE_DKIM` (default `true`)
- `ENABLE_DMARC` (default `reject`) - Enforces 5.7.1 rejection if DMARC fails and policy is reject or p=reject.
- `REJECT_UNAUTHENTICATED` (default `true`) - Enforces 5.7.1 rejection if both SPF and DKIM fail together, without dmarc record.
- `ENABLE_NULL_SENDERS` (default `true`) - Bypass authentication rejections structurally for null senders or MAILER-DAEMON.

### Server Config
- `MAX_MESSAGE_SIZE` (default `10485760` / 10MB) - Caps the memory buffer from unbounded execution exploitation natively.
- `WHITELIST_NETWORKS` (optional, comma separated list of CIDR blocks, e.g. `10.0.0.0/8,192.168.0.0/16,172.16.0.0/12,127.0.0.0/8,fe80::/10,::1/128`)
- `MILTER_ADDRESS` (default `127.0.0.1:9998`)
- `MAILNAME` (optional) - Identifies the host in `Authentication-Results` generated headers. Falls back to `HOSTNAME` and then `os.Hostname()`, the smtp server can override this.
- `MYSQL_DSN` (optional, e.g. `user:pass@tcp(host:port)/dbname`)
- `POLICY_CONFIG_FILE` (optional, required if `MYSQL_DSN` is set. e.g. `/etc/policyfilter.yaml`)

### Valkey Config (HELO / Greylisting)
- `VALKEY_URL` (optional, e.g. `valkey://127.0.0.1:6379/0`)
- `HELO_MAX_CHANGES` (default `0`)
- `HELO_TTL_DAYS` (default `14`)
- `ENABLE_GREYLISTING` (default `false`)
- `GREYLIST_IPV4_MASK` (default `24`)
- `GREYLIST_IPV6_MASK` (default `64`)
- `GREYLIST_WAIT_MINS` (default `1`)
- `GREYLIST_UNMATCHED_TTL_DAYS` (default `2`)
- `GREYLIST_MATCHED_TTL_DAYS` (default `30`)
- `DELAY_GREYLISTING` (default `true`) - Delays the greylisting rejection until the message body is processed. If false, the rejection will happen during the RcptTo stage.
- `GREYLIST_WHITELIST_COUNT` (default `0`) - Ignores Masking, if set to > 0, it will whitelist the IP based on the number of successful greylists till those greylist entries expire.

## How to Run & Test

You can test passing configuration via environment variables:
```bash
ENABLE_DKIM=false ENABLE_SPF=reject ENABLE_GREYLISTING=true ./policyfilter
```

### External Dynamic Policy Configuration (YAML)

When `MYSQL_DSN` is set, the application expects `POLICY_CONFIG_FILE` to map database string keys natively to structural authentication paradigms. Example `policies.yaml`:
```yaml
config:
  maxmessagesize: 10485760
  mailname: mail.example.com
  whitelistnetworks: 127.0.0.0/8,::1/128
  milteraddress: 127.0.0.1:9998
  valkeyurl: valkey://127.0.0.1:6379/0
  mysql: user:pass@tcp(host:port)/dbname
  helo:
    ttldays: 14
  greylist:
    ipv4mask: 24
    ipv6mask: 64
    waitmins: 1
    unmatchedttldays: 2
    matchedttldays: 30
    delay: true
profiles:
  default:
    EnableSPF: true
    EnableDKIM: true
    EnableDMARC: true
    EnableGreylist: false
    DelayGreylisting: true
    EnableNullSenders: true
    RejectOnSPFFail: false
    RejectOnDKIMFail: false
    RejectOnDMARCFail: true
    RejectOnUnauthenticated: false
    HeloMaxChanges: 0
    GreylistWhitelistCount: 0
  bypass:
    EnableGreylist: false
    EnableNullSenders: true
    RejectOnSPFFail: false
    RejectOnDKIMFail: false
    RejectOnDMARCFail: false
    RejectOnUnauthenticated: false
    HeloMaxChanges: 0
    GreylistWhitelistCount: 0
  greylist:
    EnableSPF: true
    EnableDKIM: true
    EnableDMARC: true
    EnableGreylist: true
    DelayGreylisting: true
    EnableNullSenders: false
    RejectOnSPFFail: true
    RejectOnUnauthenticated: true
    HeloMaxChanges: 3
    GreylistWhitelistCount: 10
```

If `MYSQL_DSN` is set and `POLICY_CONFIG_FILE` is missing, the backend database engine will disable itself. If `MYSQL_DSN` is not provided, the `POLICY_CONFIG_FILE` is ignored safely.

### Postfix Integration

To hook this up with Postfix, simply add it to your `main.cf`:
```ini
smtpd_milters = inet:127.0.0.1:9998
```
