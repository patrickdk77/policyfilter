package main

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"regexp"
	"strconv"
	"testing"

	"blitiri.com.ar/go/spf"
	"github.com/emersion/go-milter"
)

var smtpReplyFormat = regexp.MustCompile(`^([45])[0-9]{2} ([45])\.[0-9]{1,3}\.[0-9]{1,3} \S[^\x00]*\x00$`)

func checkReply(t *testing.T, resp milter.Response, want string) {
	t.Helper()
	if resp == nil {
		t.Fatalf("got nil response, want %q", want)
	}
	msg := resp.Response()
	if msg.Code != byte(milter.ActReplyCode) {
		t.Fatalf("milter reply byte %q, want %q", msg.Code, byte(milter.ActReplyCode))
	}
	m := smtpReplyFormat.FindStringSubmatch(string(msg.Data))
	if m == nil {
		t.Fatalf("reply %q is not a valid SMTP reply", msg.Data)
	}
	if m[1] != m[2] {
		t.Fatalf("reply %q: SMTP code class %s differs from enhanced status class %s", msg.Data, m[1], m[2])
	}
	if got := string(msg.Data); got != want+"\x00" {
		t.Fatalf("reply %q, want %q", got, want+"\x00")
	}
}

func checkContinue(t *testing.T, resp milter.Response) {
	t.Helper()
	if resp != milter.RespContinue {
		t.Fatalf("got %#v, want RespContinue", resp)
	}
}

func newTestFilter(policy PolicyConfig) *PolicyFilter {
	return &PolicyFilter{
		config: &Config{BasePolicy: policy, MaxMessageSize: 1 << 20},
		ip:     net.ParseIP("192.0.2.1"),
		msg: &Message{
			policy:  policy,
			sender:  "sender@example.com",
			msgBuf:  &bytes.Buffer{},
			headers: map[string]string{},
		},
	}
}

const unsignedMessage = "From: sender@example.com\r\nSubject: test\r\n\r\nbody\r\n"

func TestConnectRejectsMissingClientIP(t *testing.T) {
	pf := newTestFilter(PolicyConfig{})
	resp, err := pf.Connect("unknown", "tcp4", 25, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	checkReply(t, resp, "451 4.3.0 Invalid client IP")
}

func TestConnectAcceptsClientIP(t *testing.T) {
	pf := newTestFilter(PolicyConfig{})
	resp, err := pf.Connect("host.example.com", "tcp4", 25, net.ParseIP("192.0.2.1"), nil)
	if err != nil {
		t.Fatal(err)
	}
	checkContinue(t, resp)
}

func TestHeloRejectsEmptyName(t *testing.T) {
	pf := newTestFilter(PolicyConfig{})
	resp, err := pf.Helo("", nil)
	if err != nil {
		t.Fatal(err)
	}
	checkReply(t, resp, "451 4.5.0 Invalid or unknown HELO name")
}

func TestHeloRejectsUnknownName(t *testing.T) {
	pf := newTestFilter(PolicyConfig{})
	resp, err := pf.Helo("UNKNOWN", nil)
	if err != nil {
		t.Fatal(err)
	}
	checkReply(t, resp, "451 4.5.0 Invalid or unknown HELO name")
}

func TestHeloAcceptsName(t *testing.T) {
	pf := newTestFilter(PolicyConfig{})
	resp, err := pf.Helo("mail.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	checkContinue(t, resp)
}

func TestRcptToRejectsAddressWithoutDomain(t *testing.T) {
	pf := newTestFilter(PolicyConfig{})
	resp, err := pf.RcptTo("<nobody>", nil)
	if err != nil {
		t.Fatal(err)
	}
	checkReply(t, resp, "501 5.1.3 Invalid recipient address")
}

func TestRcptToAcceptsAddress(t *testing.T) {
	pf := newTestFilter(PolicyConfig{})
	resp, err := pf.RcptTo("<user@example.com>", nil)
	if err != nil {
		t.Fatal(err)
	}
	checkContinue(t, resp)
}

func TestBodyChunkRejectsOversizeMessage(t *testing.T) {
	pf := newTestFilter(PolicyConfig{})
	pf.config.MaxMessageSize = 4
	resp, err := pf.BodyChunk([]byte("12345"), nil)
	if err != nil {
		t.Fatal(err)
	}
	checkReply(t, resp, "552 5.3.4 Message size exceeds maximum allowed size")
}

func TestBodyChunkAcceptsMessageAtLimit(t *testing.T) {
	pf := newTestFilter(PolicyConfig{})
	pf.config.MaxMessageSize = 5
	resp, err := pf.BodyChunk([]byte("12345"), nil)
	if err != nil {
		t.Fatal(err)
	}
	checkContinue(t, resp)
}

func bodyFilter(policy PolicyConfig, message string, spfResult spf.Result) *PolicyFilter {
	pf := newTestFilter(policy)
	pf.msg.msgBuf.WriteString(message)
	pf.msg.spfEvaluated = true
	pf.msg.spfResult = spfResult
	return pf
}

func TestBodyRejectsUnauthenticated(t *testing.T) {
	pf := bodyFilter(PolicyConfig{EnableSPF: true, EnableDKIM: true, RejectOnUnauthenticated: true}, unsignedMessage, spf.Fail)
	resp, err := pf.Body(nil)
	if err != nil {
		t.Fatal(err)
	}
	checkReply(t, resp, "550 5.7.26 Message is not authenticated (SPF/DKIM failed)")
}

func TestBodyTempfailsUnauthenticatedOnSPFTempError(t *testing.T) {
	pf := bodyFilter(PolicyConfig{EnableSPF: true, EnableDKIM: true, RejectOnUnauthenticated: true}, unsignedMessage, spf.TempError)
	resp, err := pf.Body(nil)
	if err != nil {
		t.Fatal(err)
	}
	checkReply(t, resp, "451 4.7.24 Message is not authenticated (SPF/DKIM failed)")
}

func TestBodyRejectsSPFFail(t *testing.T) {
	pf := bodyFilter(PolicyConfig{EnableSPF: true, RejectOnSPFFail: true}, unsignedMessage, spf.Fail)
	resp, err := pf.Body(nil)
	if err != nil {
		t.Fatal(err)
	}
	checkReply(t, resp, "550 5.7.23 SPF validation failed")
}

func TestBodyRejectsInvalidDKIMSignature(t *testing.T) {
	message := "DKIM-Signature: v=1; a=rsa-sha256; d=example.com\r\n" + unsignedMessage
	pf := bodyFilter(PolicyConfig{EnableDKIM: true, RejectOnDKIMFail: true}, message, spf.None)
	resp, err := pf.Body(nil)
	if err != nil {
		t.Fatal(err)
	}
	checkReply(t, resp, "550 5.7.20 DKIM signature missing or invalid")
}

func TestBodyAppliesDelayedGreylist(t *testing.T) {
	pf := bodyFilter(PolicyConfig{}, unsignedMessage, spf.None)
	pf.msg.spfEvaluated = false
	pf.msg.greylistDelayed = true
	resp, err := pf.Body(nil)
	if err != nil {
		t.Fatal(err)
	}
	checkReply(t, resp, "450 4.7.1 Greylisted, please try again later")
}

func TestEveryRejectReplyIsAValidReplyCode(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "filter.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	replies := 0
	ast.Inspect(file, func(n ast.Node) bool {
		if fn, ok := n.(*ast.FuncDecl); ok && fn.Name.Name == "smtpReply" {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fun := call.Fun.(type) {
		case *ast.SelectorExpr:
			if pkg, ok := fun.X.(*ast.Ident); ok && pkg.Name == "milter" &&
				(fun.Sel.Name == "NewResponseStr" || fun.Sel.Name == "NewResponse") {
				t.Errorf("%s: milter.%s called directly; use smtpReply", fset.Position(call.Pos()), fun.Sel.Name)
			}
		case *ast.Ident:
			if fun.Name != "smtpReply" {
				return true
			}
			replies++
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				t.Errorf("%s: smtpReply argument is not a string literal", fset.Position(call.Pos()))
				return true
			}
			text, err := strconv.Unquote(lit.Value)
			if err != nil {
				t.Errorf("%s: %v", fset.Position(call.Pos()), err)
				return true
			}
			m := smtpReplyFormat.FindStringSubmatch(text + "\x00")
			if m == nil || m[1] != m[2] {
				t.Errorf("%s: %q is not a valid SMTP reply", fset.Position(call.Pos()), text)
			}
		}
		return true
	})
	if replies != 13 {
		t.Errorf("found %d smtpReply calls in filter.go, want 13", replies)
	}
}
