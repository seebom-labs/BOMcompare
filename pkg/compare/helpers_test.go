package compare

import (
	"testing"

	"github.com/seebom-labs/BOMcompare/pkg/sbom"
)

func TestNormVersion(t *testing.T) {
	cases := map[string]string{
		"v1.2.3":      "1.2.3",
		"1.2.3":       "1.2.3",
		"  v2.0  ":    "2.0",
		"":            "",
		"NOASSERTION": "",
		"noassertion": "",
		"NONE":        "",
	}
	for in, want := range cases {
		if got := normVersion(in); got != want {
			t.Errorf("normVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormName(t *testing.T) {
	if got := normName("  GitHub.com/Foo  "); got != "github.com/foo" {
		t.Errorf("normName = %q", got)
	}
}

func TestLastSegment(t *testing.T) {
	cases := map[string]string{
		"github.com/spf13/cobra": "cobra",
		"cobra":                  "cobra",
		"":                       "",
		"a/b/c/":                 "",
	}
	for in, want := range cases {
		if got := lastSegment(in); got != want {
			t.Errorf("lastSegment(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormLicenseOrderIndependentAnd(t *testing.T) {
	a := normLicense("MIT AND Apache-2.0")
	b := normLicense("apache-2.0 and mit")
	if a != b {
		t.Errorf("AND-joined licenses should normalize equal: %q vs %q", a, b)
	}
	if got := normLicense("mit"); got != "MIT" {
		t.Errorf("normLicense(mit) = %q, want MIT", got)
	}
	if got := normLicense("   "); got != "" {
		t.Errorf("normLicense(blank) = %q, want empty", got)
	}
}

func TestPct(t *testing.T) {
	if got := pct(1, 4); got != 25 {
		t.Errorf("pct(1,4) = %v, want 25", got)
	}
	if got := pct(3, 0); got != 0 {
		t.Errorf("pct(3,0) = %v, want 0 (no divide by zero)", got)
	}
}

func TestCoverageStarsPct(t *testing.T) {
	cases := []struct {
		in   float64
		want int
	}{
		{100, 5}, {95, 5}, {94.9, 4}, {80, 4}, {60, 3}, {30, 2}, {29.9, 1}, {0, 1},
	}
	for _, c := range cases {
		if got := coverageStarsPct(c.in); got != c.want {
			t.Errorf("coverageStarsPct(%v) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestCoverageStars(t *testing.T) {
	cases := []struct {
		self, other, want int
	}{
		{0, 5, 1},  // empty SBOM
		{5, 0, 5},  // other empty
		{5, 5, 5},  // equal
		{8, 10, 4}, // 0.8
		{6, 10, 3}, // 0.6
		{4, 10, 2}, // 0.4
		{3, 10, 1}, // 0.3
		{10, 5, 5}, // bigger than other
	}
	for _, c := range cases {
		if got := coverageStars(c.self, c.other); got != c.want {
			t.Errorf("coverageStars(%d,%d) = %d, want %d", c.self, c.other, got, c.want)
		}
	}
}

func TestRound1(t *testing.T) {
	cases := map[float64]float64{
		2.34: 2.3,
		2.35: 2.4,
		5.0:  5.0,
	}
	for in, want := range cases {
		if got := round1(in); got != want {
			t.Errorf("round1(%v) = %v, want %v", in, got, want)
		}
	}
}

func TestMatchKeyAndLooseKeys(t *testing.T) {
	p := &sbom.NormalizedPackage{
		Name:       "github.com/spf13/cobra",
		Version:    "v1.8.0",
		ModulePath: "github.com/spf13/cobra",
		PURL:       "pkg:golang/github.com/spf13/cobra@v1.8.0",
	}
	if got := matchKey(p); got != "github.com/spf13/cobra@1.8.0" {
		t.Errorf("matchKey = %q", got)
	}
	keys := looseKeys(p)
	// last-path-segment+version must be among the loose keys.
	var sawSeg bool
	for _, k := range keys {
		if k == "cobra@1.8.0" {
			sawSeg = true
		}
	}
	if !sawSeg {
		t.Errorf("looseKeys missing last-segment key: %v", keys)
	}
}

func TestMatchKeyFallsBackToPURLVersion(t *testing.T) {
	// No VersionInfo, but the purl carries the version.
	p := &sbom.NormalizedPackage{
		Name:       "demo",
		ModulePath: "demo",
		PURL:       "pkg:generic/demo@1.0.0",
	}
	if got := matchKey(p); got != "demo@1.0.0" {
		t.Errorf("matchKey with purl-only version = %q, want demo@1.0.0", got)
	}
}

func TestIsWellFormedCPE(t *testing.T) {
	cases := []struct {
		cpe  string
		want bool
	}{
		{"cpe:2.3:a:spf13:cobra:1.8.0:*:*:*:*:*:*:*", true},
		{"cpe:2.3:a:vendor\\/x:product:1.0:*:*:*:*:*:*:*", false}, // escaped slash
		{"cpe:/a:vendor:product:1.0", false},                      // not 2.3
		{"cpe:2.3:a:v:p", false},                                  // too few fields
	}
	for _, c := range cases {
		if got := isWellFormedCPE(c.cpe); got != c.want {
			t.Errorf("isWellFormedCPE(%q) = %v, want %v", c.cpe, got, c.want)
		}
	}
}

func TestGraphDepthLinearChain(t *testing.T) {
	p := &sbom.Parsed{
		Packages: []sbom.NormalizedPackage{{SPDXID: "root"}, {SPDXID: "a"}, {SPDXID: "b"}},
		Relationships: []sbom.Relationship{
			{SPDXElementID: "SPDXRef-DOCUMENT", RelationshipType: "DESCRIBES", RelatedSPDXElement: "root"},
			{SPDXElementID: "root", RelationshipType: "DEPENDS_ON", RelatedSPDXElement: "a"},
			{SPDXElementID: "a", RelationshipType: "DEPENDS_ON", RelatedSPDXElement: "b"},
		},
	}
	if got := graphDepth(p); got != 2 {
		t.Errorf("graphDepth(root->a->b) = %d, want 2 edges", got)
	}
}

func TestGraphDepthCycleSafe(t *testing.T) {
	p := &sbom.Parsed{
		Packages: []sbom.NormalizedPackage{{SPDXID: "a"}, {SPDXID: "b"}},
		Relationships: []sbom.Relationship{
			{SPDXElementID: "SPDXRef-DOCUMENT", RelationshipType: "DESCRIBES", RelatedSPDXElement: "a"},
			{SPDXElementID: "a", RelationshipType: "DEPENDS_ON", RelatedSPDXElement: "b"},
			{SPDXElementID: "b", RelationshipType: "DEPENDS_ON", RelatedSPDXElement: "a"},
		},
	}
	// Must terminate (cycle guard) and report a bounded depth.
	if got := graphDepth(p); got < 1 {
		t.Errorf("graphDepth on a cycle = %d, want >=1", got)
	}
}

func TestCountBySideForType(t *testing.T) {
	findings := []Finding{
		{Type: MissingComponent, Side: "A"},
		{Type: MissingComponent, Side: "B"},
		{Type: MissingComponent, Side: "B"},
		{Type: VersionMismatch, Side: "both"},
	}
	a, b, both := CountBySideForType(findings, MissingComponent)
	if a != 1 || b != 2 || both != 0 {
		t.Errorf("CountBySideForType(MISSING) = (%d,%d,%d), want (1,2,0)", a, b, both)
	}
	if got := CountByType(findings)[MissingComponent]; got != 3 {
		t.Errorf("CountByType[MISSING] = %d, want 3", got)
	}
}

// TestSignificantThresholdGating verifies the --diff-threshold knob: with a high
// threshold, a same-standard package delta should not gate CI.
func TestSignificantThresholdGating(t *testing.T) {
	a := load(t, "../../testdata/binary.spdx.json")
	b := load(t, "../../testdata/binary.cdx.json")

	low := Run(a, b, Options{SignificantThreshold: 1})
	high := Run(a, b, Options{SignificantThreshold: 1000})

	// Identical version data → no mismatch; gating then depends purely on the
	// runtime-unique threshold.
	if low.Versions.Mismatch == 0 && high.Overall.Significant && !low.Overall.Significant {
		t.Errorf("raising the threshold should not make a diff MORE significant")
	}
	if high.Versions.Mismatch == 0 && high.Overall.Significant {
		t.Errorf("with a very high threshold and no version mismatch, diff should not be significant")
	}
}

// TestBuildSetsMatchedBFallthrough is a regression test: when two A packages
// resolve to the same B by their primary key, the second one must fall through
// to a looser, still-unclaimed B instead of being misreported as missing. Each
// B is paired at most once.
func TestBuildSetsMatchedBFallthrough(t *testing.T) {
	a := &sbom.Parsed{Packages: []sbom.NormalizedPackage{
		{SPDXID: "A1", Name: "demo", Version: "1.0.0", ModulePath: "demo"},
		// Primary (canonical) key "demo@1.0.0" collides with B1, but a loose key
		// (name) uniquely reaches B2.
		{SPDXID: "A2", Name: "github.com/acme/demo", Version: "1.0.0", ModulePath: "demo"},
	}}
	b := &sbom.Parsed{Packages: []sbom.NormalizedPackage{
		{SPDXID: "B1", Name: "demo", Version: "1.0.0", ModulePath: "demo"},
		{SPDXID: "B2", Name: "github.com/acme/demo", Version: "1.0.0", ModulePath: "github.com/acme/demo"},
	}}

	s := buildSets(a, b)

	if len(s.Common) != 2 {
		t.Fatalf("Common = %d, want 2 (A2 must fall through to B2)", len(s.Common))
	}
	if len(s.OnlyA) != 0 || len(s.OnlyB) != 0 {
		t.Errorf("OnlyA=%d OnlyB=%d, want both empty", len(s.OnlyA), len(s.OnlyB))
	}
	// No B may be claimed twice.
	seen := map[string]bool{}
	for _, pair := range s.Common {
		if seen[pair.B.SPDXID] {
			t.Errorf("B %q claimed by more than one pair", pair.B.SPDXID)
		}
		seen[pair.B.SPDXID] = true
	}
}
