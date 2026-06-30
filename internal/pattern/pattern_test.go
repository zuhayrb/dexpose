package pattern_test

import (
	"strings"
	"testing"

	"github.com/zuhayrb/dexpose/internal/pattern"
)

// minimalTOML is the smallest valid rules file: one rule that compiles cleanly.
const minimalTOML = `
[[rules]]
id          = "test-rule"
regex       = "TESTKEY_[A-Z0-9]+"
description = "Synthetic rule for tests"
`

// --- Load ---

func TestLoad_ValidFile(t *testing.T) {
	m, err := pattern.Load([]byte(minimalTOML))
	if err != nil {
		t.Fatalf("Load returned unexpected error: %v", err)
	}
	if m == nil {
		t.Fatal("Load returned nil Matcher with no error")
	}
}

func TestLoad_RuleCount(t *testing.T) {
	src := `
[[rules]]
id    = "rule-a"
regex = "AAA"

[[rules]]
id    = "rule-b"
regex = "BBB"
`
	m, err := pattern.Load([]byte(src))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := m.RuleCount(); got != 2 {
		t.Errorf("RuleCount() = %d, want 2", got)
	}
}

func TestLoad_InvalidTOML(t *testing.T) {
	bad := `this is not valid toml ===`
	_, err := pattern.Load([]byte(bad))
	if err == nil {
		t.Fatal("Load should have returned an error for invalid TOML")
	}
}

func TestLoad_EmptyRuleSet(t *testing.T) {
	_, err := pattern.Load([]byte("# no rules here\n"))
	if err == nil {
		t.Fatal("Load should have returned an error for an empty rule set")
	}
}

func TestLoad_MissingID(t *testing.T) {
	src := `
[[rules]]
regex = "TESTKEY_[A-Z0-9]+"
`
	_, err := pattern.Load([]byte(src))
	if err == nil {
		t.Fatal("Load should have returned an error for a rule with no id")
	}
}

func TestLoad_EmptyRegex(t *testing.T) {
	src := `
[[rules]]
id    = "bad-rule"
regex = ""
`
	_, err := pattern.Load([]byte(src))
	if err == nil {
		t.Fatal("Load should have returned an error for an empty regex")
	}
}

func TestLoad_InvalidRegex(t *testing.T) {
	src := `
[[rules]]
id    = "broken"
regex = "["
`
	_, err := pattern.Load([]byte(src))
	if err == nil {
		t.Fatal("Load should have returned an error for an invalid regex")
	}
	if !strings.Contains(err.Error(), "broken") {
		t.Errorf("error should name the offending rule; got: %v", err)
	}
}

// Extra gitleaks fields that dexpose does not use should not cause a parse
// error — users must be able to drop in an existing gitleaks rules file.
func TestLoad_ExtraGitleaksFields(t *testing.T) {
	src := `
[[rules]]
id          = "aws-access-key"
description = "AWS Access Key"
regex       = "AKIA[0-9A-Z]{16}"
tags        = ["aws", "credentials"]
entropy     = 3.5

  [[rules.allowlist]]
  regexTarget = "match"
  regexes     = ["AKIAIOSFODNN7EXAMPLE"]
`
	_, err := pattern.Load([]byte(src))
	if err != nil {
		t.Fatalf("Load should tolerate extra gitleaks fields; got: %v", err)
	}
}

// --- Match ---

func TestMatch_Hit(t *testing.T) {
	m, _ := pattern.Load([]byte(minimalTOML))

	got := m.Match("config value: TESTKEY_ABCDE123")
	if len(got) != 1 {
		t.Fatalf("Match: want 1 result, got %d", len(got))
	}
	if got[0].RuleID != "test-rule" {
		t.Errorf("RuleID = %q, want %q", got[0].RuleID, "test-rule")
	}
	if got[0].Value != "TESTKEY_ABCDE123" {
		t.Errorf("Value = %q, want %q", got[0].Value, "TESTKEY_ABCDE123")
	}
}

func TestMatch_NoHit(t *testing.T) {
	m, _ := pattern.Load([]byte(minimalTOML))

	got := m.Match("nothing suspicious here")
	if len(got) != 0 {
		t.Errorf("Match: want 0 results, got %d", len(got))
	}
}

func TestMatch_EmptyString(t *testing.T) {
	m, _ := pattern.Load([]byte(minimalTOML))
	got := m.Match("")
	if len(got) != 0 {
		t.Errorf("Match on empty string: want 0 results, got %d", len(got))
	}
}

func TestMatch_MultipleRulesFireOnSameString(t *testing.T) {
	src := `
[[rules]]
id    = "rule-a"
regex = "AAA"

[[rules]]
id    = "rule-b"
regex = "BBB"
`
	m, _ := pattern.Load([]byte(src))

	got := m.Match("value contains AAA and BBB")
	if len(got) != 2 {
		t.Fatalf("Match: want 2 results, got %d: %+v", len(got), got)
	}
	ids := map[string]bool{}
	for _, g := range got {
		ids[g.RuleID] = true
	}
	if !ids["rule-a"] || !ids["rule-b"] {
		t.Errorf("expected both rule-a and rule-b to fire; got IDs: %v", ids)
	}
}

func TestMatch_OnlyFirstOccurrencePerRule(t *testing.T) {
	// A string with two matches for the same rule should yield one Match entry.
	src := `
[[rules]]
id    = "repeated"
regex = "TOKEN_[A-Z]+"
`
	m, _ := pattern.Load([]byte(src))

	got := m.Match("TOKEN_ALPHA and TOKEN_BETA")
	if len(got) != 1 {
		t.Errorf("Match: want 1 result per rule (first hit only), got %d", len(got))
	}
	if got[0].Value != "TOKEN_ALPHA" {
		t.Errorf("Value = %q, want first match TOKEN_ALPHA", got[0].Value)
	}
}

// --- Real-world pattern smoke tests ---
// These test patterns that will appear in patterns/rules.toml.
// They validate that the regexes dexpose ships with actually fire on
// representative credential strings.

func TestMatch_RealWorldPatterns(t *testing.T) {
	cases := []struct {
		name      string
		ruleID    string
		regex     string
		input     string
		wantMatch bool
	}{
		{
			name:      "AWS access key",
			ruleID:    "aws-access-key",
			regex:     `AKIA[0-9A-Z]{16}`,
			input:     "aws_access_key=AKIAIOSFODNN7EXAMPLE",
			wantMatch: true,
		},
		{
			name:      "AWS access key no match",
			ruleID:    "aws-access-key",
			regex:     `AKIA[0-9A-Z]{16}`,
			input:     "nothing here",
			wantMatch: false,
		},
		{
			name:      "Stripe secret key",
			ruleID:    "stripe-secret-key",
			regex:     `sk_live_[0-9a-zA-Z]{24,}`,
			input:     "stripe_key=sk_\x6cive_ZZZZZZZZZZZZZZZZZZZZZZZZ",
			wantMatch: true,
		},
		{
			name:      "Stripe publishable key",
			ruleID:    "stripe-publishable-key",
			regex:     `pk_live_[0-9a-zA-Z]{24,}`,
			input:     "pk_\x6cive_abcdefghijklmnopqrstuvwx",
			wantMatch: true,
		},
		{
			name:      "Slack bot token",
			ruleID:    "slack-bot-token",
			regex:     `xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}`,
			input:     "token=xoxb\x2d0000000000-0000000000000-AAAAAAAAAAAAAAAAAAAAAAAA",
			wantMatch: true,
		},
		{
			name:      "Google API key",
			ruleID:    "google-api-key",
			regex:     `AIza[0-9A-Za-z\-_]{35}`,
			input:     "key=AIz\x61SyD-9tSrke72I6e0T1234567890abcdefgh",
			wantMatch: true,
		},
		{
			name:      "Twilio account SID",
			ruleID:    "twilio-account-sid",
			regex:     `AC[a-z0-9]{32}`,
			input:     "TWILIO_SID=ACzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
			wantMatch: true,
		},
		{
			name:      "SendGrid API key",
			ruleID:    "sendgrid-api-key",
			regex:     `SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}`,
			input:     "\x53G.abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxabcdefghijklmnopqrs",
			wantMatch: true,
		},
		{
			name:      "Mailgun API key",
			ruleID:    "mailgun-api-key",
			regex:     `key-[0-9a-zA-Z]{32}`,
			input:     "MAILGUN_KEY=\x6bey-abcdefghijklmnopqrstuvwxyz123456",
			wantMatch: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Use TOML literal strings (single-quoted) for both id and regex
			// so that backslashes in regex patterns are passed through verbatim
			// rather than being interpreted as TOML escape sequences.
			tomlSrc := "[[rules]]\nid    = '" + tc.ruleID + "'\nregex = '" + tc.regex + "'\n"
			m, err := pattern.Load([]byte(tomlSrc))
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			got := m.Match(tc.input)
			if tc.wantMatch && len(got) == 0 {
				t.Errorf("expected match on %q but got none", tc.input)
			}
			if !tc.wantMatch && len(got) > 0 {
				t.Errorf("expected no match on %q but got %+v", tc.input, got)
			}
		})
	}
}
