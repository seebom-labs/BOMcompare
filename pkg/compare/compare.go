// Package compare implements the SBOM quality comparison engine. It takes two
// normalized SPDX documents and produces a structured Report covering package
// coverage, version accuracy, license/PURL/CPE quality, dependency graph depth,
// supplier and checksum coverage, annotations and a weighted composite score.
package compare

import (
	"github.com/seebom-labs/BOMcompare/pkg/sbom"
)

// Report is the full structured comparison result. It is rendered by the report
// package into markdown, JSON or a summary table.
type Report struct {
	A *sbom.Parsed `json:"-"`
	B *sbom.Parsed `json:"-"`

	LabelA string `json:"labelA"`
	LabelB string `json:"labelB"`

	// FormatA/FormatB record the detected serialization of each input (e.g.
	// "spdx-json", "cyclonedx-xml"), which is useful context for cross-format runs.
	FormatA string `json:"formatA"`
	FormatB string `json:"formatB"`

	ContextA string `json:"contextA"`
	ContextB string `json:"contextB"`
	// ContextNote is a human note when the two SBOMs differ in scope (e.g. a
	// source SBOM vs a binary SBOM), which explains many findings.
	ContextNote string `json:"contextNote,omitempty"`

	Completeness Completeness `json:"completeness"`
	Versions     Versions     `json:"versions"`
	Licenses     Licenses     `json:"licenses"`
	PURLs        PURLQuality  `json:"purls"`
	CPEs         CPECoverage  `json:"cpes"`
	Deps         DepGraph     `json:"deps"`
	Suppliers    Suppliers    `json:"suppliers"`
	Checksums    Checksums    `json:"checksums"`
	Annotations  Annotations  `json:"annotations"`

	// MinimumElements is an informational CISA 2026 minimum-elements check;
	// it does not influence the scorecard.
	MinimumElements MinimumElements `json:"minimumElements"`

	Findings []Finding `json:"findings"`

	Scorecard []ScoreRow `json:"scorecard"`
	Overall   Overall    `json:"overall"`
}

// Overall is the weighted composite outcome.
type Overall struct {
	ScoreA      float64 `json:"scoreA"`      // 1.0 - 5.0
	ScoreB      float64 `json:"scoreB"`      // 1.0 - 5.0
	Winner      string  `json:"winner"`      // labelA, labelB, or "tie"
	HasDiff     bool    `json:"hasDiff"`     // any significant differences
	Significant bool    `json:"significant"` // differences large enough for CI gating
}

// ScoreRow is one line of the summary scorecard.
type ScoreRow struct {
	Category string `json:"category"`
	Weight   string `json:"weight"`
	StarsA   int    `json:"starsA"` // 1-5
	StarsB   int    `json:"starsB"` // 1-5
	Note     string `json:"note"`
	weight   float64
}

// PackagePair links a package present in both SBOMs (matched by purl or
// name+version), used for cross-comparison of licenses and versions.
type PackagePair struct {
	Key string
	A   *sbom.NormalizedPackage
	B   *sbom.NormalizedPackage
}

// Sets holds the package partition shared across analyzers so matching is done
// once.
type Sets struct {
	Common []PackagePair
	OnlyA  []*sbom.NormalizedPackage
	OnlyB  []*sbom.NormalizedPackage
	byKeyA map[string]*sbom.NormalizedPackage
	byKeyB map[string]*sbom.NormalizedPackage
	// looseB indexes B by relaxed keys (name+version, last-segment+version) so a
	// generic-typed package in A can still match an ecosystem-typed package in B.
	looseB map[string]*sbom.NormalizedPackage
	// identB indexes B by version-independent identity (module path / name) so a
	// same-package/different-version pair is detected as a version mismatch rather
	// than two missing components. May hold collisions; first writer wins.
	identB map[string]*sbom.NormalizedPackage
}

// Options tunes comparison behavior.
type Options struct {
	// SignificantThreshold is the minimum number of unique-on-either-side
	// packages (excluding test-scoped) that counts as a "significant" diff for
	// CI gating. Version mismatches and missing licenses always count.
	SignificantThreshold int
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() Options {
	return Options{SignificantThreshold: 1}
}

// Run executes the full comparison.
func Run(a, b *sbom.Parsed, opts Options) *Report {
	r := &Report{
		A:        a,
		B:        b,
		LabelA:   a.ToolLabel,
		LabelB:   b.ToolLabel,
		FormatA:  a.Format,
		FormatB:  b.Format,
		ContextA: a.Context,
		ContextB: b.Context,
	}
	if a.Context != b.Context && a.Context != "unknown" && b.Context != "unknown" {
		r.ContextNote = contextNote(a, b)
	}

	sets := buildSets(a, b)

	r.Completeness = analyzeCompleteness(a, b, sets)
	r.Versions = analyzeVersions(sets)
	r.Licenses = analyzeLicenses(a, b, sets)
	r.PURLs = analyzePURLs(a, b)
	r.CPEs = analyzeCPEs(a, b)
	r.Deps = analyzeDeps(a, b)
	r.Suppliers = analyzeSuppliers(a, b)
	r.Checksums = analyzeChecksums(a, b)
	r.Annotations = analyzeAnnotations(a, b)
	r.MinimumElements = analyzeMinimumElements(a, b)

	r.Findings = classifyFindings(r, sets)

	r.Scorecard = buildScorecard(r)
	r.Overall = computeOverall(r, sets, opts)
	return r
}

func contextNote(a, b *sbom.Parsed) string {
	src, bin := a, b
	if b.Context == "source" {
		src, bin = b, a
	}
	return src.ToolLabel + " describes SOURCE (e.g. go.sum/module graph) while " +
		bin.ToolLabel + " describes a BUILT BINARY. A source SBOM lists the full " +
		"transitive/test dependency set; a binary SBOM lists only what is compiled in. " +
		"This explains most package-count and coverage differences below."
}

// buildSets partitions packages into common/unique using purl-first matching
// with a name+version fallback, and Go-aware cross-type matching.
func buildSets(a, b *sbom.Parsed) *Sets {
	s := &Sets{
		byKeyA: make(map[string]*sbom.NormalizedPackage, len(a.Packages)),
		byKeyB: make(map[string]*sbom.NormalizedPackage, len(b.Packages)),
		looseB: make(map[string]*sbom.NormalizedPackage, len(b.Packages)*2),
		identB: make(map[string]*sbom.NormalizedPackage, len(b.Packages)*2),
	}
	for i := range a.Packages {
		s.byKeyA[matchKey(&a.Packages[i])] = &a.Packages[i]
	}
	for i := range b.Packages {
		pb := &b.Packages[i]
		s.byKeyB[matchKey(pb)] = pb
		for _, k := range looseKeys(pb) {
			// First writer wins to keep matching deterministic.
			if _, exists := s.looseB[k]; !exists {
				s.looseB[k] = pb
			}
		}
		for _, k := range identityKeys(pb) {
			if _, exists := s.identB[k]; !exists {
				s.identB[k] = pb
			}
		}
	}

	matchedB := make(map[string]bool, len(b.Packages))
	for i := range a.Packages {
		pa := &a.Packages[i]
		// findMatch never returns an already-claimed B, so the result is always
		// safe to pair here.
		if pb := findMatch(pa, s.byKeyB, s.looseB, s.identB, matchedB); pb != nil {
			s.Common = append(s.Common, PackagePair{Key: matchKey(pa), A: pa, B: pb})
			matchedB[pb.SPDXID] = true
		} else {
			s.OnlyA = append(s.OnlyA, pa)
		}
	}
	for i := range b.Packages {
		pb := &b.Packages[i]
		if !matchedB[pb.SPDXID] {
			s.OnlyB = append(s.OnlyB, pb)
		}
	}
	return s
}

// looseKeys returns the relaxed match keys a package can be found under:
// name+version and last-path-segment+version.
func looseKeys(p *sbom.NormalizedPackage) []string {
	ver := normVersion(p.Version)
	if ver == "" {
		ver = normVersion(sbom.PURLVersion(p.PURL))
	}
	keys := []string{normName(p.Name) + "@" + ver}
	if seg := lastSegment(p.ModulePath); seg != "" {
		keys = append(keys, seg+"@"+ver)
	}
	if seg := lastSegment(normName(p.Name)); seg != "" {
		keys = append(keys, seg+"@"+ver)
	}
	return keys
}

// matchKey produces the canonical key for a package: prefer module-path+version
// (works across pkg:golang and pkg:generic), else name+version.
func matchKey(p *sbom.NormalizedPackage) string {
	ver := normVersion(p.Version)
	if ver == "" {
		ver = normVersion(sbom.PURLVersion(p.PURL))
	}
	if p.ModulePath != "" {
		return p.ModulePath + "@" + ver
	}
	return normName(p.Name) + "@" + ver
}

// identityKeys returns version-independent identity keys (module path, name,
// last path segment) used as a last-resort match so version mismatches surface.
func identityKeys(p *sbom.NormalizedPackage) []string {
	var keys []string
	if p.ModulePath != "" {
		keys = append(keys, "id:"+p.ModulePath)
		if seg := lastSegment(p.ModulePath); seg != "" {
			keys = append(keys, "id:"+seg)
		}
	}
	if n := normName(p.Name); n != "" {
		keys = append(keys, "id:"+n)
		if seg := lastSegment(n); seg != "" {
			keys = append(keys, "id:"+seg)
		}
	}
	return keys
}

// findMatch resolves a package from A against B's indexes, trying progressively
// looser keys so Go modules with differing purl types still match. Version-aware
// keys are tried first; a version-independent identity match is the last resort
// (so same-package/different-version becomes a comparable pair, not two
// missing components).
//
// A B-package that another A-package has already claimed (matchedB) is never
// returned, so each B is paired at most once and a collision falls through to a
// looser, still-unclaimed candidate instead of being misreported as missing.
func findMatch(pa *sbom.NormalizedPackage, byKeyB, looseB, identB map[string]*sbom.NormalizedPackage, matchedB map[string]bool) *sbom.NormalizedPackage {
	ok := func(pb *sbom.NormalizedPackage, found bool) bool {
		return found && !matchedB[pb.SPDXID] && identityCompatible(pa, pb)
	}
	// 1) exact canonical key (module/name + version).
	if pb, found := byKeyB[matchKey(pa)]; ok(pb, found) {
		return pb
	}
	// 2) relaxed version-aware keys (name+version, last-segment+version).
	for _, k := range looseKeys(pa) {
		if pb, found := looseB[k]; ok(pb, found) {
			return pb
		}
	}
	// 3) version-independent identity (captures version mismatches). Skip targets
	// already matched to avoid collapsing distinct packages.
	for _, k := range identityKeys(pa) {
		if pb, found := identB[k]; ok(pb, found) {
			return pb
		}
	}
	return nil
}

// distroPURLTypes are purl types whose namespace is a vendor/distro qualifier
// (pkg:deb/debian/x vs pkg:deb/ubuntu/x), so packages may match by name alone.
var distroPURLTypes = map[string]bool{
	"deb": true, "rpm": true, "apk": true, "alpm": true, "qpkg": true,
}

// identityCompatible rejects a candidate pair whose ecosystem purls prove they
// are different packages — e.g. github.com/pkg/errors vs
// github.com/go-errors/errors (same last segment) or pkg:npm/debug vs
// pkg:pypi/debug (same name). Pairs where either side lacks an ecosystem purl
// (none, or pkg:generic) stay matchable so a generic main module still lines up
// with its ecosystem-typed counterpart.
func identityCompatible(a, b *sbom.NormalizedPackage) bool {
	if !ecosystemPURL(a) || !ecosystemPURL(b) {
		return true
	}
	if a.PURLType != b.PURLType {
		return false
	}
	if a.ModulePath == b.ModulePath {
		return true
	}
	return distroPURLTypes[a.PURLType] && lastSegment(a.ModulePath) == lastSegment(b.ModulePath)
}

func ecosystemPURL(p *sbom.NormalizedPackage) bool {
	return p.PURL != "" && p.PURLType != "" && p.PURLType != "generic"
}
