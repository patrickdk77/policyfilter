package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"hash"
	"net"
	"strings"

	"github.com/emersion/go-msgauth/dkim"
)

// maxATPSQueries bounds the number of distinct DNS TXT lookups a single
// message may trigger for ATPS checks. Without this, a message carrying
// many DKIM-Signature headers (e.g. duplicated/replayed valid signatures)
// with matching "atps" tags could be used to force unbounded DNS traffic.
const maxATPSQueries = 5

// atpsHashers maps an "atpsh" tag value to the hash used to digest the
// signing (d=) domain, per RFC 6541 Section 4.1. DKIM (RFC 6376 Section 7.7)
// registers sha1 and sha256 for signature hashing, and both remain valid
// choices here even though RFC 8301 forbids sha1 for signing itself: RFC
// 6541 explicitly notes that this hashing "is not a security mechanism", it
// only keeps the resulting DNS label short.
var atpsHashers = map[string]func() hash.Hash{
	"sha1":   sha1.New,
	"sha256": sha256.New,
}

// atpsResult mirrors the "dkim-atps" Authentication-Results codes registered
// by RFC 6541 Section 8.3.
type atpsResult string

const (
	atpsNone      atpsResult = "none"
	atpsPass      atpsResult = "pass"
	atpsFail      atpsResult = "fail"
	atpsTempError atpsResult = "temperror"
	atpsPermError atpsResult = "permerror"
)

// atpsResultRank orders results so an aggregate across several candidate
// signatures can be reduced with a single "best so far" comparison.
func atpsResultRank(r atpsResult) int {
	switch r {
	case atpsPass:
		return 4
	case atpsTempError:
		return 3
	case atpsPermError:
		return 2
	case atpsFail:
		return 1
	default:
		return 0
	}
}

// atpsQueryName builds the DNS query name for an ATPS authorization lookup,
// per RFC 6541 Section 4.3 steps 1-6. ok is false if hashAlgo is neither
// "none" nor a hash algorithm supported for this purpose, in which case the
// query MUST be aborted (the signature's "atps" tag is simply ignored).
func atpsQueryName(adid, hashAlgo, atpsDomain string) (name string, ok bool) {
	adid = strings.ToLower(adid)
	// Canonicalize the suffix too: this keeps dedup-by-query-string correct
	// even if a caller passes a not-yet-lowercased "atps" tag value.
	atpsDomain = strings.ToLower(atpsDomain)

	label := adid
	if hashAlgo != "none" {
		newHash, supported := atpsHashers[hashAlgo]
		if !supported {
			return "", false
		}
		h := newHash()
		h.Write([]byte(adid))
		// RFC 6541 SS4.3 step 4B: base32 as defined in RFC 4648 Section 6.
		// DNS labels can't contain "=" padding, and the label width limit
		// (63) is only ever satisfied by an unpadded encoding for the
		// registered DKIM hash sizes, so padding is stripped.
		label = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(h.Sum(nil))
	}

	return label + "._atps." + atpsDomain, true
}

// parseATPSReply reports whether an ATPS TXT record (RFC 6541 Section 4.4)
// is valid, i.e. it carries a "v=ATPS1" tag.
func parseATPSReply(txt string) bool {
	for _, part := range strings.Split(txt, ";") {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		if strings.TrimSpace(k) == "v" && strings.TrimSpace(v) == "ATPS1" {
			return true
		}
	}
	return false
}

// txtLookupFunc resolves DNS TXT records for a domain name, matching the
// signature of net.LookupTXT.
type txtLookupFunc func(name string) ([]string, error)

// atpsLookupTXT is the TXT resolver used for ATPS queries. It is a package
// variable so tests can substitute a fake resolver instead of hitting real
// DNS.
var atpsLookupTXT txtLookupFunc = net.LookupTXT

// lookupATPS performs the DNS TXT query and reply evaluation described in
// RFC 6541 Sections 4.3-4.4 for a single candidate query name. A nil
// lookupTXT uses atpsLookupTXT; tests may pass a stub directly instead.
func lookupATPS(queryName string, lookupTXT txtLookupFunc) atpsResult {
	if lookupTXT == nil {
		lookupTXT = atpsLookupTXT
	}

	txts, err := lookupTXT(queryName)
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok {
			if dnsErr.IsNotFound {
				// NXDOMAIN: this signer was not authorized by the ADMD.
				return atpsFail
			}
			if dnsErr.IsTimeout || dnsErr.Temporary() {
				return atpsTempError
			}
		}
		return atpsPermError
	}

	if len(txts) == 0 {
		return atpsFail
	}

	for _, txt := range txts {
		if parseATPSReply(txt) {
			return atpsPass
		}
	}
	return atpsFail
}

// evaluateATPS checks every successfully-verified DKIM signature carrying an
// "atps" tag that matches fromDomain against RFC 6541 (Authorized
// Third-Party Signatures). It returns the overall "dkim-atps"
// Authentication-Results code for the message, plus the set of DKIM d=
// domains (lowercased) that were confirmed authorized, which callers should
// treat as DMARC-DKIM-aligned per RFC 6541 Section 5 ("Interpretation").
//
// A failed or errored ATPS lookup never causes the message to be rejected by
// itself: at worst it leaves DMARC alignment exactly as it would have been
// without ATPS support.
func (pf *PolicyFilter) evaluateATPS(dkimResults []*dkim.Verification, fromDomain string) (overall atpsResult, authorizedDomains map[string]bool) {
	overall = atpsNone
	authorizedDomains = make(map[string]bool)
	seenQueries := make(map[string]bool)

	for _, v := range dkimResults {
		if v.Err != nil || v.ATPSDomain == "" {
			continue
		}
		// RFC 6541 SS4.3: compare the "atps" tag's domain to the From
		// domain case-insensitively; ignore the tag entirely if they differ.
		if !strings.EqualFold(v.ATPSDomain, fromDomain) {
			continue
		}

		queryName, ok := atpsQueryName(v.Domain, v.ATPSHashAlgo, v.ATPSDomain)
		if !ok {
			pf.debugf("Skipping ATPS query for DKIM domain %s: unsupported atpsh %q", v.Domain, v.ATPSHashAlgo)
			continue
		}
		if seenQueries[queryName] {
			continue
		}
		if len(seenQueries) >= maxATPSQueries {
			pf.debugf("Skipping further ATPS queries: exceeded max %d distinct queries for this message", maxATPSQueries)
			break
		}
		seenQueries[queryName] = true

		result := lookupATPS(queryName, atpsLookupTXT)
		pf.debugf("ATPS query %s (DKIM domain %s): %s", queryName, v.Domain, result)

		if atpsResultRank(result) > atpsResultRank(overall) {
			overall = result
		}
		if result == atpsPass {
			authorizedDomains[strings.ToLower(v.Domain)] = true
			// RFC 6541 SS4.4: once authorized, further queries SHOULD NOT
			// be initiated.
			break
		}
	}

	return overall, authorizedDomains
}
