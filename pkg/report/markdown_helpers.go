package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/seebom-labs/BOMcompare/pkg/compare"
	"github.com/seebom-labs/BOMcompare/pkg/sbom"
)

// crossStandard reports whether two detected formats belong to different SBOM
// standards (SPDX vs CycloneDX), which changes field semantics.
func crossStandard(fa, fb string) bool {
	return standardOf(fa) != standardOf(fb) &&
		standardOf(fa) != "" && standardOf(fb) != ""
}

func standardOf(format string) string {
	switch format {
	case sbom.FormatSPDXJSON, sbom.FormatSPDXTagValue, sbom.FormatSPDX3JSONLD:
		return "spdx"
	case sbom.FormatCycloneDXJSON, sbom.FormatCycloneDXXML:
		return "cyclonedx"
	default:
		return ""
	}
}

// buildRecommendations derives actionable advice from the analyzed report,
// mirroring the recommendation style of the manual kubelb comparison.
func buildRecommendations(r *compare.Report) []string {
	var recs []string
	l := r.Licenses

	if l.ConcludedResolvedA == 0 && l.DeclaredResolvedA > 0 {
		recs = append(recs, fmt.Sprintf("**%s should populate `licenseConcluded`.** Licenses are resolved in `licenseDeclared` (%.1f%%) but `licenseConcluded` is NOASSERTION for every package — most SBOM consumers and compliance tools read concluded, not declared.", r.LabelA, l.DeclaredRateA))
	}
	if l.ConcludedResolvedB == 0 && l.DeclaredResolvedB > 0 {
		recs = append(recs, fmt.Sprintf("**%s should populate `licenseConcluded`.** Licenses are resolved in `licenseDeclared` (%.1f%%) but `licenseConcluded` is NOASSERTION for every package.", r.LabelB, l.DeclaredRateB))
	}

	if r.PURLs.MainPURLNote != "" {
		recs = append(recs, "**Use an ecosystem-typed main module purl.** "+r.PURLs.MainPURLNote)
	}

	if r.Suppliers.RateA < 50 {
		recs = append(recs, fmt.Sprintf("**%s should add supplier attribution** (currently %.0f%%) — important for supply-chain provenance and CRA compliance.", r.LabelA, r.Suppliers.RateA))
	}
	if r.Suppliers.RateB < 50 {
		recs = append(recs, fmt.Sprintf("**%s should add supplier attribution** (currently %.0f%%).", r.LabelB, r.Suppliers.RateB))
	}

	if r.Deps.HasTestLabelingA && !r.Deps.HasTestLabelingB {
		recs = append(recs, fmt.Sprintf("**%s should classify test vs runtime dependencies** (`TEST_DEPENDENCY_OF`), as %s does — crucial context for vulnerability triage.", r.LabelB, r.LabelA))
	}
	if r.Deps.HasTestLabelingB && !r.Deps.HasTestLabelingA {
		recs = append(recs, fmt.Sprintf("**%s should classify test vs runtime dependencies** (`TEST_DEPENDENCY_OF`), as %s does.", r.LabelA, r.LabelB))
	}

	if r.Annotations.PkgWithAnnA == 0 && r.Annotations.PkgWithAnnB > 0 {
		recs = append(recs, fmt.Sprintf("**%s provides no annotations** while %s annotates %d packages — annotations add valuable provenance/transparency.", r.LabelA, r.LabelB, r.Annotations.PkgWithAnnB))
	}
	if r.Annotations.PkgWithAnnB == 0 && r.Annotations.PkgWithAnnA > 0 {
		recs = append(recs, fmt.Sprintf("**%s provides no annotations** while %s annotates %d packages.", r.LabelB, r.LabelA, r.Annotations.PkgWithAnnA))
	}

	// Coverage gap recommendation when one SBOM has materially fewer packages and
	// it is NOT explained by a source-vs-binary context difference.
	c := r.Completeness
	if r.ContextNote == "" {
		if c.TotalB*4 < c.TotalA*3 { // B < 75% of A
			recs = append(recs, fmt.Sprintf("**%s misses %d packages** present in %s — investigate transitive-dependency coverage.", r.LabelB, c.OnlyACount, r.LabelA))
		}
		if c.TotalA*4 < c.TotalB*3 { // A < 75% of B
			recs = append(recs, fmt.Sprintf("**%s misses %d packages** present in %s.", r.LabelA, c.OnlyBCount, r.LabelB))
		}
	} else {
		recs = append(recs, "**Source vs binary is a use-case choice, not a defect.** The source SBOM is better for CRA compliance and vulnerability coverage (full dependency tree); the binary SBOM is better for runtime/attack-surface analysis. Pick per use case rather than treating the package delta as an error.")
	}

	for _, side := range []struct {
		label string
		pick  func(compare.MinElementRow) compare.MinElementResult
	}{
		{r.LabelA, func(row compare.MinElementRow) compare.MinElementResult { return row.A }},
		{r.LabelB, func(row compare.MinElementRow) compare.MinElementResult { return row.B }},
	} {
		var missing []string
		for _, row := range r.MinimumElements.Rows {
			if side.pick(row).Status == compare.MinFail {
				missing = append(missing, row.Element)
			}
		}
		if len(missing) > 0 {
			recs = append(recs, fmt.Sprintf("**%s misses CISA 2026 minimum elements:** %s.", side.label, strings.Join(missing, ", ")))
		}
	}

	if r.Versions.Mismatch > 0 {
		recs = append(recs, fmt.Sprintf("**Resolve %d version mismatch(es)** on common packages — these indicate the two tools disagree on what is actually present.", r.Versions.Mismatch))
	}
	return recs
}

// ---- small rendering helpers ----

// dashes returns a markdown header separator sized to the label so tables stay
// readable in plain text.
func dashes(label string) string {
	n := len(label)
	if n < 6 {
		n = 6
	}
	if n > 24 {
		n = 24
	}
	return strings.Repeat("-", n)
}

func biggerInt(a, b int, r *compare.Report) string {
	switch {
	case a > b:
		return fmt.Sprintf("%s%s", r.LabelA, deltaSuffix(a, b))
	case b > a:
		return fmt.Sprintf("%s%s", r.LabelB, deltaSuffix(b, a))
	default:
		return "—"
	}
}

func biggerFloat(a, b float64, r *compare.Report) string {
	switch {
	case a > b+0.05:
		return r.LabelA
	case b > a+0.05:
		return r.LabelB
	default:
		return "Tie"
	}
}

// deltaSuffix renders a percentage delta when the baseline is non-zero, else an
// absolute count (e.g. "+4" when the other side has none).
func deltaSuffix(big, small int) string {
	if small == 0 {
		return fmt.Sprintf(" (+%d)", big)
	}
	return fmt.Sprintf(" (+%.0f%%)", (float64(big)-float64(small))/float64(small)*100)
}

func matchStr(rate float64, checked int) string {
	if checked == 0 {
		return "n/a"
	}
	if rate >= 99.95 {
		return "✅ 100% match"
	}
	return fmt.Sprintf("%.1f%% match", rate)
}

func tieIf(cond bool) string {
	if cond {
		return "Tie"
	}
	return "—"
}

func testTag(has bool) string {
	if has {
		return ", test-labeled"
	}
	return ""
}

// mergedTypes returns the union of relationship/purl types across two
// distributions, ordered by total descending then name.
func mergedTypes(a, b []compare.TypeCount) []string {
	totals := map[string]int{}
	for _, t := range a {
		totals[t.Type] += t.Count
	}
	for _, t := range b {
		totals[t.Type] += t.Count
	}
	types := make([]string, 0, len(totals))
	for t := range totals {
		types = append(types, t)
	}
	sort.Slice(types, func(i, j int) bool {
		if totals[types[i]] == totals[types[j]] {
			return types[i] < types[j]
		}
		return totals[types[i]] > totals[types[j]]
	})
	return types
}

func countOf(dist []compare.TypeCount, typ string) int {
	for _, t := range dist {
		if t.Type == typ {
			return t.Count
		}
	}
	return 0
}

func typeDistStr(dist []compare.TypeCount) string {
	if len(dist) == 0 {
		return "_none_"
	}
	parts := make([]string, 0, len(dist))
	for _, t := range dist {
		parts = append(parts, fmt.Sprintf("`%s`=%d", t.Type, t.Count))
	}
	return strings.Join(parts, ", ")
}

func purlOrDash(purl string) string {
	if purl == "" {
		return "_not flagged_"
	}
	return "`" + purl + "`"
}

// findingAssessment returns a short qualitative note for a finding-type row.
func findingAssessment(t compare.FindingType, a, b int) string {
	switch t {
	case compare.MissingComponent:
		if a > b {
			return "B more complete"
		}
		if b > a {
			return "A more complete"
		}
		return "balanced"
	case compare.VersionMismatch:
		return "tools disagree on versions"
	case compare.PurlMismatch:
		return "purl identity differs"
	case compare.LicenseGap:
		return "unresolved licenses"
	case compare.PhantomComponent:
		return "possibly spurious entries"
	case compare.FalsePositive:
		return "identity mismatch"
	default:
		return ""
	}
}
