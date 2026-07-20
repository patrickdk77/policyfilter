package main

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/emersion/go-msgauth/dkim"
)

// TestAtpsQueryNameRFCExample validates atpsQueryName against the worked
// example in RFC 6541 Appendix A: sha1("one.example.net") and
// sha1("two.example.net"), base32 encoded, queried under "._atps.example.com".
func TestAtpsQueryNameRFCExample(t *testing.T) {
	tests := []struct {
		adid string
		want string
	}{
		{"one.example.net", "QSP4I4D24CRHOPDZ3O3ZIU2KSGS3X6Z6._atps.example.com"},
		{"two.example.net", "ZTZGRRV3F45A4U6HLDKBF3ZCOW4V2AJX._atps.example.com"},
	}
	for _, tc := range tests {
		got, ok := atpsQueryName(tc.adid, "sha1", "example.com")
		if !ok {
			t.Fatalf("atpsQueryName(%q, sha1, example.com) reported !ok", tc.adid)
		}
		if got != tc.want {
			t.Errorf("atpsQueryName(%q, sha1, example.com) = %q, want %q", tc.adid, got, tc.want)
		}
	}
}

func TestAtpsQueryNameHashNone(t *testing.T) {
	got, ok := atpsQueryName("Signer.Example.Net", "none", "example.com")
	if !ok {
		t.Fatal("expected ok=true for atpsh=none")
	}
	want := "signer.example.net._atps.example.com"
	if got != want {
		t.Errorf("got %q, want %q (adid must be lowercased)", got, want)
	}
}

func TestAtpsQueryNameSHA256(t *testing.T) {
	// sha256("one.example.net") base32-encoded (no padding); verified
	// independently against Python's hashlib/base64.
	got, ok := atpsQueryName("one.example.net", "sha256", "example.com")
	if !ok {
		t.Fatal("expected ok=true for atpsh=sha256")
	}
	want := "SQWHEPKQYG5KRIOG6F7LPEDTTNOIF7DQUSVCO2PCHSH3QUGXAKHA._atps.example.com"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if strings.Contains(got, "=") {
		t.Errorf("query name must not contain base32 padding: %q", got)
	}
}

func TestAtpsQueryNameUnsupportedHash(t *testing.T) {
	for _, hashAlgo := range []string{"md5", "sha512", "", "None", "SHA1"} {
		if _, ok := atpsQueryName("one.example.net", hashAlgo, "example.com"); ok {
			t.Errorf("atpsQueryName with hashAlgo %q should report ok=false (case-sensitive tag, or unregistered algorithm)", hashAlgo)
		}
	}
}

func TestParseATPSReply(t *testing.T) {
	tests := []struct {
		name string
		txt  string
		want bool
	}{
		{"valid minimal", "v=ATPS1", true},
		{"valid with d tag", "v=ATPS1; d=one.example.net", true},
		{"valid with whitespace", " v = ATPS1 ; d=one.example.net ", true},
		{"d tag before v tag", "d=one.example.net; v=ATPS1", true},
		{"wrong version", "v=ATPS2", false},
		{"missing v tag", "d=one.example.net", false},
		{"empty string", "", false},
		{"unrelated txt record", "some other unrelated TXT record", false},
		{"lowercase version value", "v=atps1", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseATPSReply(tc.txt); got != tc.want {
				t.Errorf("parseATPSReply(%q) = %v, want %v", tc.txt, got, tc.want)
			}
		})
	}
}

func TestLookupATPS(t *testing.T) {
	tests := []struct {
		name string
		txts []string
		err  error
		want atpsResult
	}{
		{"valid pass", []string{"v=ATPS1"}, nil, atpsPass},
		{"pass among multiple records", []string{"junk", "v=ATPS1"}, nil, atpsPass},
		{"no matching record", []string{"v=ATPS2", "junk"}, nil, atpsFail},
		{"empty reply, no error", []string{}, nil, atpsFail},
		{"NXDOMAIN", nil, &net.DNSError{Err: "no such host", IsNotFound: true}, atpsFail},
		{"timeout", nil, &net.DNSError{Err: "timeout", IsTimeout: true}, atpsTempError},
		{"temporary DNS error", nil, &net.DNSError{Err: "servfail", IsTemporary: true}, atpsTempError},
		{"unrecognized error type", nil, errors.New("boom"), atpsPermError},
		{"non-timeout non-notfound DNSError", nil, &net.DNSError{Err: "weird"}, atpsPermError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stub := func(name string) ([]string, error) { return tc.txts, tc.err }
			if got := lookupATPS("QSP4I4D24CRHOPDZ3O3ZIU2KSGS3X6Z6._atps.example.com", stub); got != tc.want {
				t.Errorf("lookupATPS() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestLookupATPSNilResolverUsesPackageDefault(t *testing.T) {
	called := false
	orig := atpsLookupTXT
	atpsLookupTXT = func(name string) ([]string, error) {
		called = true
		return []string{"v=ATPS1"}, nil
	}
	defer func() { atpsLookupTXT = orig }()

	if got := lookupATPS("x._atps.example.com", nil); got != atpsPass {
		t.Errorf("got %v, want atpsPass", got)
	}
	if !called {
		t.Error("expected the package-level atpsLookupTXT default to be invoked when lookupTXT is nil")
	}
}

// pfForTest builds a bare PolicyFilter sufficient for evaluateATPS's calls to
// pf.debugf, without needing a live milter session.
func pfForTest() *PolicyFilter {
	return &PolicyFilter{}
}

func verification(domain string, err error, atpsDomain, atpsHash string) *dkim.Verification {
	return &dkim.Verification{
		Domain:       domain,
		Err:          err,
		ATPSDomain:   atpsDomain,
		ATPSHashAlgo: atpsHash,
	}
}

func TestEvaluateATPS_Pass(t *testing.T) {
	defer stubATPSLookup(t, allowOnly("QSP4I4D24CRHOPDZ3O3ZIU2KSGS3X6Z6._atps.example.com"))()

	pf := pfForTest()
	results := []*dkim.Verification{
		verification("one.example.net", nil, "example.com", "sha1"),
	}

	overall, authorized := pf.evaluateATPS(results, "example.com")
	if overall != atpsPass {
		t.Errorf("overall = %v, want pass", overall)
	}
	if !authorized["one.example.net"] {
		t.Errorf("expected one.example.net to be recorded as authorized: %v", authorized)
	}
}

func TestEvaluateATPS_IgnoresFailedDKIM(t *testing.T) {
	calls := 0
	defer stubATPSLookup(t, func(name string) ([]string, error) {
		calls++
		return []string{"v=ATPS1"}, nil
	})()

	pf := pfForTest()
	results := []*dkim.Verification{
		verification("one.example.net", errors.New("bad signature"), "example.com", "sha1"),
	}

	overall, authorized := pf.evaluateATPS(results, "example.com")
	if overall != atpsNone {
		t.Errorf("overall = %v, want none (failed DKIM signatures must be ignored)", overall)
	}
	if len(authorized) != 0 {
		t.Errorf("expected no authorized domains, got %v", authorized)
	}
	if calls != 0 {
		t.Errorf("expected no DNS lookups for a failed DKIM signature, got %d", calls)
	}
}

func TestEvaluateATPS_IgnoresNonMatchingFromDomain(t *testing.T) {
	calls := 0
	defer stubATPSLookup(t, func(name string) ([]string, error) {
		calls++
		return []string{"v=ATPS1"}, nil
	})()

	pf := pfForTest()
	results := []*dkim.Verification{
		verification("one.example.net", nil, "other-domain.com", "sha1"),
	}

	overall, _ := pf.evaluateATPS(results, "example.com")
	if overall != atpsNone {
		t.Errorf("overall = %v, want none", overall)
	}
	if calls != 0 {
		t.Errorf("expected no DNS lookups when atps tag doesn't match the From domain, got %d", calls)
	}
}

func TestEvaluateATPS_FromDomainMatchIsCaseInsensitive(t *testing.T) {
	defer stubATPSLookup(t, allowOnly("QSP4I4D24CRHOPDZ3O3ZIU2KSGS3X6Z6._atps.example.com"))()

	pf := pfForTest()
	results := []*dkim.Verification{
		verification("one.example.net", nil, "EXAMPLE.COM", "sha1"),
	}

	overall, authorized := pf.evaluateATPS(results, "example.com")
	if overall != atpsPass || !authorized["one.example.net"] {
		t.Errorf("expected case-insensitive atps-domain match to pass: overall=%v authorized=%v", overall, authorized)
	}
}

func TestEvaluateATPS_SkipsUnsupportedHashAlgo(t *testing.T) {
	calls := 0
	defer stubATPSLookup(t, func(name string) ([]string, error) {
		calls++
		return []string{"v=ATPS1"}, nil
	})()

	pf := pfForTest()
	results := []*dkim.Verification{
		verification("one.example.net", nil, "example.com", "md5"),
		verification("two.example.net", nil, "example.com", ""), // missing atpsh tag
	}

	overall, authorized := pf.evaluateATPS(results, "example.com")
	if overall != atpsNone {
		t.Errorf("overall = %v, want none", overall)
	}
	if len(authorized) != 0 {
		t.Errorf("expected no authorized domains, got %v", authorized)
	}
	if calls != 0 {
		t.Errorf("expected no DNS lookups for unsupported/missing hash algorithms, got %d", calls)
	}
}

func TestEvaluateATPS_DedupesIdenticalQueries(t *testing.T) {
	calls := 0
	defer stubATPSLookup(t, func(name string) ([]string, error) {
		calls++
		return []string{"v=ATPS1"}, nil
	})()

	pf := pfForTest()
	// Same d=, atpsh=, and atps= tuple repeated (e.g. a replayed/duplicated
	// signature) must only trigger one DNS lookup.
	results := []*dkim.Verification{
		verification("one.example.net", nil, "example.com", "sha1"),
		verification("one.example.net", nil, "example.com", "sha1"),
		verification("one.example.net", nil, "example.com", "sha1"),
	}

	overall, _ := pf.evaluateATPS(results, "example.com")
	if overall != atpsPass {
		t.Errorf("overall = %v, want pass", overall)
	}
	if calls != 1 {
		t.Errorf("expected exactly 1 deduplicated DNS lookup, got %d", calls)
	}
}

func TestEvaluateATPS_StopsAfterFirstPass(t *testing.T) {
	calls := 0
	defer stubATPSLookup(t, func(name string) ([]string, error) {
		calls++
		return []string{"v=ATPS1"}, nil
	})()

	pf := pfForTest()
	results := []*dkim.Verification{
		verification("one.example.net", nil, "example.com", "sha1"),
		verification("two.example.net", nil, "example.com", "sha1"),
	}

	overall, authorized := pf.evaluateATPS(results, "example.com")
	if overall != atpsPass {
		t.Errorf("overall = %v, want pass", overall)
	}
	if calls != 1 {
		t.Errorf("expected the second candidate's query to be skipped once a pass is found (RFC 6541 SS4.4), got %d calls", calls)
	}
	if len(authorized) != 1 {
		t.Errorf("expected exactly 1 authorized domain, got %v", authorized)
	}
}

func TestEvaluateATPS_EnforcesMaxQueryCap(t *testing.T) {
	calls := 0
	defer stubATPSLookup(t, func(name string) ([]string, error) {
		calls++
		return []string{"junk"}, nil // never authorizes, so we never break early on a pass
	})()

	pf := pfForTest()
	var results []*dkim.Verification
	for i := 0; i < maxATPSQueries+3; i++ {
		// Distinct domains -> distinct query names -> distinct dedup keys.
		domain := strings.Repeat("a", i+1) + ".example.net"
		results = append(results, verification(domain, nil, "example.com", "sha1"))
	}

	overall, _ := pf.evaluateATPS(results, "example.com")
	if overall != atpsFail {
		t.Errorf("overall = %v, want fail", overall)
	}
	if calls != maxATPSQueries {
		t.Errorf("expected exactly %d DNS lookups (safety cap), got %d", maxATPSQueries, calls)
	}
}

func TestEvaluateATPS_AggregatesWorstNonPassResult(t *testing.T) {
	defer stubATPSLookup(t, func(name string) ([]string, error) {
		if strings.HasPrefix(name, "QSP4I4D24CRHOPDZ3O3ZIU2KSGS3X6Z6") {
			return nil, &net.DNSError{IsNotFound: true} // fail
		}
		return nil, &net.DNSError{IsTimeout: true} // temperror
	})()

	pf := pfForTest()
	results := []*dkim.Verification{
		verification("one.example.net", nil, "example.com", "sha1"), // -> fail
		verification("two.example.net", nil, "example.com", "sha1"), // -> temperror
	}

	overall, authorized := pf.evaluateATPS(results, "example.com")
	if overall != atpsTempError {
		t.Errorf("overall = %v, want temperror (higher severity than fail)", overall)
	}
	if len(authorized) != 0 {
		t.Errorf("expected no authorized domains, got %v", authorized)
	}
}

// stubATPSLookup replaces the package-level DNS resolver for the duration of
// a test and returns a func to restore it; call via `defer stubATPSLookup(...)()`.
func stubATPSLookup(t *testing.T, fn txtLookupFunc) func() {
	t.Helper()
	orig := atpsLookupTXT
	atpsLookupTXT = fn
	return func() { atpsLookupTXT = orig }
}

// allowOnly returns a stub resolver that answers "v=ATPS1" only for the
// given exact query name, and a non-matching TXT record for anything else.
func allowOnly(queryName string) txtLookupFunc {
	return func(name string) ([]string, error) {
		if name == queryName {
			return []string{"v=ATPS1"}, nil
		}
		return []string{"junk"}, nil
	}
}
