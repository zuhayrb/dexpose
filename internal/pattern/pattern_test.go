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

func TestMatch_AllOccurrencesPerRuleDeduped(t *testing.T) {
	// A string with two distinct matches for the same rule should yield two
	// Match entries (FindAllString with dedup).
	src := `
[[rules]]
id    = "repeated"
regex = "TOKEN_[A-Z]+"
`
	m, _ := pattern.Load([]byte(src))

	got := m.Match("TOKEN_ALPHA and TOKEN_BETA")
	if len(got) != 2 {
		t.Fatalf("Match: want 2 results (all unique matches), got %d: %+v", len(got), got)
	}
	// Both values should be returned.
	vals := map[string]bool{}
	for _, g := range got {
		vals[g.Value] = true
	}
	if !vals["TOKEN_ALPHA"] || !vals["TOKEN_BETA"] {
		t.Errorf("expected both TOKEN_ALPHA and TOKEN_BETA; got values: %v", vals)
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
		// --- Phase 8 new rules ---
		{
			name:      "DigitalOcean personal access token",
			ruleID:    "digitalocean-personal-access-token",
			regex:     `dop_v1_[0-9a-f]{64}`,
			input:     "token=dop_v1_" + strings.Repeat("a", 64),
			wantMatch: true,
		},
		{
			name:      "New Relic API key",
			ruleID:    "newrelic-api-key",
			regex:     `NRAK-[A-Z0-9]{27}`,
			input:     "NEW_RELIC_KEY=NRAK-ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
			wantMatch: true,
		},
		{
			name:      "npm access token",
			ruleID:    "npm-access-token",
			regex:     `npm_[A-Za-z0-9]{36}`,
			input:     "NPM_TOKEN=npm_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
			wantMatch: true,
		},
		{
			name:      "PyPI API token",
			ruleID:    "pypi-api-token",
			regex:     `pypi-[A-Za-z0-9\-_]{100,}`,
			input:     "PYPI_TOKEN=" + "pypi-" + strings.Repeat("A", 100),
			wantMatch: true,
		},
		{
			name:      "Doppler service token",
			ruleID:    "doppler-token",
			regex:     `dp\.st\.[a-z0-9\-_]{40,}`,
			input:     "DOPPLER_TOKEN=dp.st." + strings.Repeat("a", 40),
			wantMatch: true,
		},
		{
			name:      "Doppler personal token",
			ruleID:    "doppler-personal-token",
			regex:     `dp\.pt\.[a-z0-9\-_]{40,}`,
			input:     "DOPPLER_TOKEN=dp.pt." + strings.Repeat("b", 40),
			wantMatch: true,
		},
		{
			name:      "Terraform Cloud token",
			ruleID:    "terraform-cloud-token",
			regex:     `(?i)atlasv1\.[A-Za-z0-9\-_]{14,}`,
			input:     "TF_TOKEN=atlasv1.abcdefghijklmnop",
			wantMatch: true,
		},
		{
			name:      "Vault service token",
			ruleID:    "vault-token",
			regex:     `(?i)vault[_\-\.]?token["']?\s*[=:]\s*["']?hvs\.[A-Za-z0-9\-_]{24,}`,
			input:     `VAULT_TOKEN="hvs.` + strings.Repeat("A", 24) + `"`,
			wantMatch: true,
		},
		{
			name:      "Azure storage account key",
			ruleID:    "azure-storage-account-key",
			regex:     `(?i)(?:account[_\-\.]?key|storage[_\-\.]?key)["']?\s*[=:]\s*["']?([A-Za-z0-9+/]{86}==)`,
			input:     "AccountKey=" + strings.Repeat("A", 86) + "==",
			wantMatch: true,
		},
		{
			name:      "Shopify access token",
			ruleID:    "shopify-access-token",
			regex:     `shp(at|ca|pa|bs|ss)_[a-fA-F0-9]{32,}`,
			input:     "SHOPIFY_TOKEN=shpat_" + strings.Repeat("a", 32),
			wantMatch: true,
		},
		{
			name:      "Connection string password",
			ruleID:    "connection-string-password",
			regex:     `(?i)(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|amqp|mssql)://[^:\s]+:([^@\s]{8,})@[^\s]+`,
			input:     "postgres\x3a//user:supersecret123@db.example.com/mydb",
			wantMatch: true,
		},
		{
			name:      "DATABASE_URL password",
			ruleID:    "database-url-password",
			regex:     `(?i)database[_\-\.]?url["']?\s*[=:]\s*["']?[a-z]+://[^:\s]+:([^@\s]{8,})@[^\s]+`,
			input:     "DATABASE_URL=postgres\x3a//admin:hunter2pass@localhost:5432/app",
			wantMatch: true,
		},
		// --- New patterns for APK context ---
		{
			name:      "Google OAuth client ID",
			ruleID:    "google-oauth-client-id",
			regex:     `[0-9]{10,}-[a-zA-Z0-9_]+\.apps\.googleusercontent\.com`,
			input:     "client_id=1039583071963-hopic0upn374f5t24998g8b412ntb56l.apps.googleusercontent.com",
			wantMatch: true,
		},
		{
			name:      "Firebase URL",
			ruleID:    "firebase-url",
			regex:     `[a-zA-Z0-9_-]+\.firebaseio\.com`,
			input:     "db_url=https://andromeda-88668.firebaseio.com",
			wantMatch: true,
		},
		{
			name:      "JWT token",
			ruleID:    "jwt-token",
			regex:     `eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`,
			input:     "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
			wantMatch: true,
		},
		{
			name:      "High-entropy hex string",
			ruleID:    "high-entropy-hex",
			regex:     `[0-9a-fA-F]{32,64}`,
			input:     "hash=2438bce1ddb7bd026d5ff89f598b3b5e",
			wantMatch: true,
		},
		{
			name:      "High-entropy base64 string",
			ruleID:    "high-entropy-base64",
			regex:     `[A-Za-z0-9+/]{40,}={0,2}`,
			input:     "key=" + strings.Repeat("A", 40),
			wantMatch: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Build TOML so that backslashes in regex pass through verbatim.
			// Use literal (''') strings when the regex has no single quotes,
			// and double-quoted strings (with escaped backslashes) when it does.
			var tomlSrc string
			if strings.Contains(tc.regex, "'") {
				// Double-quoted TOML string: escape backslashes and double quotes.
				escaped := strings.ReplaceAll(tc.regex, `\`, `\\`)
				escaped = strings.ReplaceAll(escaped, `"`, `\"`)
				tomlSrc = "[[rules]]\nid    = '" + tc.ruleID + "'\nregex = \"" + escaped + "\"\n"
			} else {
				tomlSrc = "[[rules]]\nid    = '" + tc.ruleID + "'\nregex = '" + tc.regex + "'\n"
			}
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
