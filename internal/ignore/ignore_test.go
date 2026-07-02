package ignore_test

import (
	"strings"
	"sync"
	"testing"

	"github.com/zuhayrb/dexpose/internal/ignore"
	"github.com/zuhayrb/dexpose/internal/model"
)

// --- Load ---

func TestLoad_ValidFile(t *testing.T) {
	src := `
[[ignore]]
pattern = "generic-api-key"
`
	l, err := ignore.Load([]byte(src))
	if err != nil {
		t.Fatalf("Load returned unexpected error: %v", err)
	}
	if l == nil {
		t.Fatal("Load returned nil List with no error")
	}
}

func TestLoad_EmptyFile(t *testing.T) {
	l, err := ignore.Load([]byte("# no entries here\n"))
	if err != nil {
		t.Fatalf("Load should accept a file with zero entries; got: %v", err)
	}
	if got := l.EntryCount(); got != 0 {
		t.Errorf("EntryCount() = %d, want 0", got)
	}
}

func TestLoad_InvalidTOML(t *testing.T) {
	bad := `this is not valid toml ===`
	_, err := ignore.Load([]byte(bad))
	if err == nil {
		t.Fatal("Load should have returned an error for invalid TOML")
	}
}

func TestLoad_EntryWithNoFieldsSet(t *testing.T) {
	src := `
[[ignore]]
pattern = "real-rule"

[[ignore]]
`
	_, err := ignore.Load([]byte(src))
	if err == nil {
		t.Fatal("Load should have returned an error for an entry that sets no fields")
	}
	if !strings.Contains(err.Error(), "entry 2") {
		t.Errorf("error should identify the offending entry by position; got: %v", err)
	}
}

func TestLoad_EntryCount(t *testing.T) {
	src := `
[[ignore]]
pattern = "rule-a"

[[ignore]]
value = "some-value"

[[ignore]]
source = "assets/vendor.bundle.js"
`
	l, err := ignore.Load([]byte(src))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := l.EntryCount(); got != 3 {
		t.Errorf("EntryCount() = %d, want 3", got)
	}
}

// The exact PRD example file: three single-dimension entries combined in one file.
func TestLoad_PRDExampleFile(t *testing.T) {
	src := `
[[ignore]]
pattern = "generic-api-key"

[[ignore]]
value = "AKIAIOSFODNN7EXAMPLE"

[[ignore]]
source = "assets/vendor.bundle.js"
`
	l, err := ignore.Load([]byte(src))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	cases := []struct {
		name string
		f    model.Finding
		want bool
	}{
		{"pattern dimension", model.Finding{Pattern: "generic-api-key", Match: "anything", Source: "classes.dex"}, true},
		{"value dimension", model.Finding{Pattern: "aws-access-key", Match: "AKIAIOSFODNN7EXAMPLE", Source: "classes.dex"}, true},
		{"source dimension", model.Finding{Pattern: "stripe-secret-key", Match: "sk_live_xxx", Source: "assets/vendor.bundle.js"}, true},
		{"matches none", model.Finding{Pattern: "stripe-secret-key", Match: "sk_live_xxx", Source: "classes.dex"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := l.Suppressed(tc.f); got != tc.want {
				t.Errorf("Suppressed(%+v) = %v, want %v", tc.f, got, tc.want)
			}
		})
	}
}

// --- Suppressed: single-dimension entries ---

func TestSuppressed_PatternMatch(t *testing.T) {
	l, _ := ignore.Load([]byte(`[[ignore]]
pattern = "generic-api-key"
`))
	f := model.Finding{Pattern: "generic-api-key", Match: "xyz", Source: "classes.dex"}
	if !l.Suppressed(f) {
		t.Error("expected finding to be suppressed by pattern match")
	}
}

func TestSuppressed_PatternNoMatch(t *testing.T) {
	l, _ := ignore.Load([]byte(`[[ignore]]
pattern = "generic-api-key"
`))
	f := model.Finding{Pattern: "stripe-secret-key", Match: "xyz", Source: "classes.dex"}
	if l.Suppressed(f) {
		t.Error("expected finding not to be suppressed; pattern differs")
	}
}

func TestSuppressed_ValueMatch(t *testing.T) {
	l, _ := ignore.Load([]byte(`[[ignore]]
value = "AKIAIOSFODNN7EXAMPLE"
`))
	f := model.Finding{Pattern: "aws-access-key", Match: "AKIAIOSFODNN7EXAMPLE", Source: "classes.dex"}
	if !l.Suppressed(f) {
		t.Error("expected finding to be suppressed by value match")
	}
}

func TestSuppressed_SourceMatch(t *testing.T) {
	l, _ := ignore.Load([]byte(`[[ignore]]
source = "assets/vendor.bundle.js"
`))
	f := model.Finding{Pattern: "generic-api-key", Match: "xyz", Source: "assets/vendor.bundle.js"}
	if !l.Suppressed(f) {
		t.Error("expected finding to be suppressed by source match")
	}
}

func TestSuppressed_NoEntriesMatch(t *testing.T) {
	l, _ := ignore.Load([]byte(`[[ignore]]
pattern = "generic-api-key"
`))
	f := model.Finding{Pattern: "stripe-secret-key", Match: "abc", Source: "classes2.dex"}
	if l.Suppressed(f) {
		t.Error("expected finding not to be suppressed")
	}
}

// --- Suppressed: exact, case-sensitive equality, no wildcards ---

func TestSuppressed_CaseSensitive(t *testing.T) {
	l, _ := ignore.Load([]byte(`[[ignore]]
pattern = "generic-api-key"
`))
	f := model.Finding{Pattern: "Generic-API-Key", Match: "xyz", Source: "classes.dex"}
	if l.Suppressed(f) {
		t.Error("matching should be case-sensitive; differing case must not suppress")
	}
}

func TestSuppressed_NoSubstringMatching(t *testing.T) {
	l, _ := ignore.Load([]byte(`[[ignore]]
source = "vendor.bundle.js"
`))
	f := model.Finding{Pattern: "generic-api-key", Match: "xyz", Source: "assets/vendor.bundle.js"}
	if l.Suppressed(f) {
		t.Error("matching should require exact equality, not substring containment")
	}
}

// --- Suppressed: multi-field entries (AND within an entry) ---

func TestSuppressed_MultiFieldEntry_AllFieldsMatch(t *testing.T) {
	l, _ := ignore.Load([]byte(`[[ignore]]
pattern = "generic-api-key"
source  = "assets/vendor.bundle.js"
`))
	f := model.Finding{Pattern: "generic-api-key", Match: "xyz", Source: "assets/vendor.bundle.js"}
	if !l.Suppressed(f) {
		t.Error("expected suppression when all set fields on the entry match")
	}
}

func TestSuppressed_MultiFieldEntry_PartialMatchDoesNotSuppress(t *testing.T) {
	l, _ := ignore.Load([]byte(`[[ignore]]
pattern = "generic-api-key"
source  = "assets/vendor.bundle.js"
`))
	// Pattern matches but source does not — AND semantics require both.
	f := model.Finding{Pattern: "generic-api-key", Match: "xyz", Source: "classes.dex"}
	if l.Suppressed(f) {
		t.Error("expected no suppression when only some of the entry's set fields match")
	}
}

func TestSuppressed_MultiFieldEntry_AllThreeFields(t *testing.T) {
	l, _ := ignore.Load([]byte(`[[ignore]]
pattern = "generic-api-key"
value   = "xyz"
source  = "assets/vendor.bundle.js"
`))
	match := model.Finding{Pattern: "generic-api-key", Match: "xyz", Source: "assets/vendor.bundle.js"}
	if !l.Suppressed(match) {
		t.Error("expected suppression when pattern, value, and source all match")
	}

	noMatch := model.Finding{Pattern: "generic-api-key", Match: "different-value", Source: "assets/vendor.bundle.js"}
	if l.Suppressed(noMatch) {
		t.Error("expected no suppression when value differs from the entry's set value")
	}
}

// --- Suppressed: multiple entries (OR across entries) ---

func TestSuppressed_MultipleEntries_AnyMatchSuppresses(t *testing.T) {
	l, _ := ignore.Load([]byte(`[[ignore]]
pattern = "generic-api-key"

[[ignore]]
value = "AKIAIOSFODNN7EXAMPLE"
`))

	byPattern := model.Finding{Pattern: "generic-api-key", Match: "anything", Source: "classes.dex"}
	if !l.Suppressed(byPattern) {
		t.Error("expected suppression via the first entry (pattern)")
	}

	byValue := model.Finding{Pattern: "aws-access-key", Match: "AKIAIOSFODNN7EXAMPLE", Source: "classes.dex"}
	if !l.Suppressed(byValue) {
		t.Error("expected suppression via the second entry (value)")
	}

	neither := model.Finding{Pattern: "stripe-secret-key", Match: "sk_live_xxx", Source: "classes.dex"}
	if l.Suppressed(neither) {
		t.Error("expected no suppression; finding matches neither entry")
	}
}

// --- SuppressedCount ---

func TestSuppressedCount_IncrementsOnSuppression(t *testing.T) {
	l, _ := ignore.Load([]byte(`[[ignore]]
pattern = "generic-api-key"
`))
	suppressed := model.Finding{Pattern: "generic-api-key", Match: "a", Source: "classes.dex"}
	notSuppressed := model.Finding{Pattern: "stripe-secret-key", Match: "b", Source: "classes.dex"}

	l.Suppressed(suppressed)
	l.Suppressed(notSuppressed)
	l.Suppressed(suppressed)

	if got := l.SuppressedCount(); got != 2 {
		t.Errorf("SuppressedCount() = %d, want 2", got)
	}
}

func TestSuppressedCount_ZeroWhenNothingSuppressed(t *testing.T) {
	l, _ := ignore.Load([]byte(`[[ignore]]
pattern = "generic-api-key"
`))
	l.Suppressed(model.Finding{Pattern: "stripe-secret-key", Match: "b", Source: "classes.dex"})

	if got := l.SuppressedCount(); got != 0 {
		t.Errorf("SuppressedCount() = %d, want 0", got)
	}
}

// --- Nil safety ---
// scan.Config.IgnoreFile is empty when no ignore file is provided; callers
// should be able to pass a nil *List through unconditionally in that case.

func TestSuppressed_NilList(t *testing.T) {
	var l *ignore.List
	f := model.Finding{Pattern: "generic-api-key", Match: "a", Source: "classes.dex"}
	if l.Suppressed(f) {
		t.Error("a nil *List should never suppress a finding")
	}
}

func TestSuppressedCount_NilList(t *testing.T) {
	var l *ignore.List
	if got := l.SuppressedCount(); got != 0 {
		t.Errorf("SuppressedCount() on nil *List = %d, want 0", got)
	}
}

func TestEntryCount_NilList(t *testing.T) {
	var l *ignore.List
	if got := l.EntryCount(); got != 0 {
		t.Errorf("EntryCount() on nil *List = %d, want 0", got)
	}
}

// --- Concurrency ---
// The scan package's output goroutine is the only documented caller of
// Suppressed today, but List is documented as safe for concurrent use —
// verify that claim holds under -race with concurrent callers.

func TestSuppressed_ConcurrentUse(t *testing.T) {
	l, _ := ignore.Load([]byte(`[[ignore]]
pattern = "generic-api-key"
`))

	const goroutines = 50
	const callsEach = 20

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < callsEach; j++ {
				l.Suppressed(model.Finding{Pattern: "generic-api-key", Match: "x", Source: "classes.dex"})
			}
		}()
	}
	wg.Wait()

	want := goroutines * callsEach
	if got := l.SuppressedCount(); got != want {
		t.Errorf("SuppressedCount() = %d, want %d", got, want)
	}
}
