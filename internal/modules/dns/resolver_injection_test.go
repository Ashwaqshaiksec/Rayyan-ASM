package dns_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/modules/dns"
	"github.com/stretchr/testify/assert"
)

// fake resolver so we don't have to hit real DNS to test the parsing logic
type fakeTXTResolver struct {
	records map[string][]string
	errs    map[string]error
}

func (f *fakeTXTResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if err, ok := f.errs[name]; ok {
		return nil, err
	}
	if recs, ok := f.records[name]; ok {
		return recs, nil
	}
	return nil, errors.New("no such host")
}

func TestSPF(t *testing.T) {
	cases := []struct {
		name   string
		record string
		policy string
		valid  bool
	}{
		{"fail", "v=spf1 include:_spf.google.com -all", "fail", true},
		{"softfail", "v=spf1 include:_spf.google.com ~all", "softfail", true},
		{"pass all is bad", "v=spf1 +all", "pass", false},
		{"neutral", "v=spf1 ?all", "neutral", false},
		{"no all mechanism", "v=spf1 include:_spf.google.com", "unknown", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &fakeTXTResolver{records: map[string][]string{"example.com": {tc.record}}}
			res := dns.CheckSPF(context.Background(), r, "example.com", time.Second)
			assert.True(t, res.Present)
			assert.Equal(t, tc.policy, res.Policy)
			assert.Equal(t, tc.valid, res.Valid)
		})
	}
}

func TestSPF_NoRecord(t *testing.T) {
	r := &fakeTXTResolver{records: map[string][]string{"example.com": {"some-other-txt"}}}
	res := dns.CheckSPF(context.Background(), r, "example.com", time.Second)
	assert.False(t, res.Present)
}

func TestSPF_LookupFails(t *testing.T) {
	r := &fakeTXTResolver{errs: map[string]error{"example.com": errors.New("no such host")}}
	res := dns.CheckSPF(context.Background(), r, "example.com", time.Second)
	assert.False(t, res.Present)
	assert.Contains(t, res.Issue, "DNS lookup failed")
}

func TestDMARCPolicy(t *testing.T) {
	cases := []struct {
		name   string
		record string
		policy string
		valid  bool
	}{
		{"reject", "v=DMARC1; p=reject", "reject", true},
		{"quarantine full pct", "v=DMARC1; p=quarantine; pct=100", "quarantine", true},
		{"none", "v=DMARC1; p=none", "none", false},
		{"garbage policy", "v=DMARC1; p=bogus", "bogus", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &fakeTXTResolver{records: map[string][]string{"_dmarc.example.com": {tc.record}}}
			res := dns.CheckDMARC(context.Background(), r, "example.com", time.Second)
			assert.Equal(t, tc.policy, res.Policy)
			assert.Equal(t, tc.valid, res.Valid)
		})
	}
}

func TestDMARC_Reject_RUAAndPctParsed(t *testing.T) {
	r := &fakeTXTResolver{records: map[string][]string{
		"_dmarc.example.com": {"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"},
	}}
	res := dns.CheckDMARC(context.Background(), r, "example.com", time.Second)
	assert.Equal(t, "mailto:dmarc@example.com", res.RUA)
	assert.Equal(t, 100, res.PCT) // default per RFC 7489
}

func TestDMARC_QuarantineWithPartialPct(t *testing.T) {
	// pct < 100 means some mail bypasses enforcement, should flag an issue
	r := &fakeTXTResolver{records: map[string][]string{
		"_dmarc.example.com": {"v=DMARC1; p=quarantine; pct=50"},
	}}
	res := dns.CheckDMARC(context.Background(), r, "example.com", time.Second)
	assert.Equal(t, 50, res.PCT)
	assert.Contains(t, res.Issue, "pct=50")
}

func TestDMARC_SubPolicy(t *testing.T) {
	r := &fakeTXTResolver{records: map[string][]string{
		"_dmarc.example.com": {"v=DMARC1; p=reject; sp=quarantine"},
	}}
	res := dns.CheckDMARC(context.Background(), r, "example.com", time.Second)
	assert.Equal(t, "quarantine", res.SubPolicy)
}

func TestDMARC_Missing(t *testing.T) {
	r := &fakeTXTResolver{records: map[string][]string{"_dmarc.example.com": {"unrelated"}}}
	res := dns.CheckDMARC(context.Background(), r, "example.com", time.Second)
	assert.False(t, res.Present)
}

func TestDMARC_LookupFails(t *testing.T) {
	r := &fakeTXTResolver{errs: map[string]error{"_dmarc.example.com": errors.New("timeout")}}
	res := dns.CheckDMARC(context.Background(), r, "example.com", time.Second)
	assert.False(t, res.Present)
}

func TestDKIMKeyType(t *testing.T) {
	cases := []struct {
		name     string
		selector string
		record   string
		keyType  string
	}{
		{"defaults to rsa when k= missing", "default", "v=DKIM1; p=ABCDEF", "rsa"},
		{"explicit rsa", "default", "v=DKIM1; k=rsa; p=ABCDEF", "rsa"},
		{"ed25519", "k1", "v=DKIM1; k=ed25519; p=ABCDEF", "ed25519"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &fakeTXTResolver{records: map[string][]string{
				tc.selector + "._domainkey.example.com": {tc.record},
			}}
			res := dns.CheckDKIM(context.Background(), r, "example.com", time.Second)
			assert.Len(t, res, 1)
			assert.Equal(t, tc.keyType, res[0].KeyType)
		})
	}
}

func TestDKIM_MultipleSelectors(t *testing.T) {
	r := &fakeTXTResolver{records: map[string][]string{
		"default._domainkey.example.com": {"v=DKIM1; k=rsa; p=AAA"},
		"google._domainkey.example.com":  {"v=DKIM1; k=rsa; p=BBB"},
	}}
	res := dns.CheckDKIM(context.Background(), r, "example.com", time.Second)
	assert.Len(t, res, 2)
}

func TestDKIM_NothingFound(t *testing.T) {
	r := &fakeTXTResolver{}
	res := dns.CheckDKIM(context.Background(), r, "example.com", time.Second)
	assert.Empty(t, res)
}

func TestDKIM_AllSelectorsFail(t *testing.T) {
	r := &fakeTXTResolver{errs: map[string]error{
		"default._domainkey.example.com": errors.New("NXDOMAIN"),
		"google._domainkey.example.com":  errors.New("NXDOMAIN"),
	}}
	res := dns.CheckDKIM(context.Background(), r, "example.com", time.Second)
	assert.Empty(t, res)
}

// hits the D grade band and the appendUniq dedup branch, both missed by the
// existing scoring tests
func TestScoreEmailSecurity_GradeDBand(t *testing.T) {
	result := dns.EmailSecurityResult{
		SPF:   dns.SPFResult{Present: true, Policy: "softfail", Valid: true},
		DMARC: dns.DMARCResult{Present: false},
		DKIM:  []dns.DKIMResult{{Selector: "default", Present: true, Valid: true}},
	}
	score, grade, _ := dns.ScoreEmailSecurity(result)
	assert.Equal(t, 45, score)
	assert.Equal(t, "D", grade)
}

func TestScoreEmailSecurity_DuplicateIssueCollapsed(t *testing.T) {
	dup := "SPF uses +all which allows any sender to pass"
	result := dns.EmailSecurityResult{
		SPF:   dns.SPFResult{Present: true, Policy: "pass", Issue: dup},
		DMARC: dns.DMARCResult{Present: true, Policy: "reject", PCT: 100, Valid: true},
		DKIM:  []dns.DKIMResult{{Selector: "default", Present: true, Valid: true}},
	}
	_, _, issues := dns.ScoreEmailSecurity(result)
	count := 0
	for _, issue := range issues {
		if issue == dup {
			count++
		}
	}
	assert.Equal(t, 1, count)
}
