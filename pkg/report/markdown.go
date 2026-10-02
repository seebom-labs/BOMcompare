package report

import (
	"fmt"
	"strings"
	"time"

	"github.com/seebom-labs/BOMcompare/pkg/compare"
)

// RenderMarkdown renders the full human-readable comparison report, structured
// like the manual kubelb-1.4.2 comparison.
func RenderMarkdown(r *compare.Report) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }

	w("# SBOM Comparison Report\n\n")
	w("**%s** vs **%s**\n\n", r.LabelA, r.LabelB)
	w("Formats: **%s** = `%s`, **%s** = `%s`.\n\n", r.LabelA, r.FormatA, r.LabelB, r.FormatB)
	w("Methodology inspired by [mlieberman85's SBOM quality benchmark](https://gist.github.com/mlieberman85/cb0ed7b600efb211dce0633e2c392626).\n\n")
	w("---\n\n")

	if r.FormatA != r.FormatB && crossStandard(r.FormatA, r.FormatB) {
		w("## Note: Cross-Standard Comparison\n\n")
		w("These SBOMs use different standards (SPDX vs CycloneDX). Field semantics " +
			"differ — most importantly, SPDX separates `licenseDeclared` from " +
			"`licenseConcluded` while CycloneDX only distinguishes them via the 1.6+ " +
			"`acknowledgement` field (licenses without it are mapped to " +
			"`licenseConcluded` here). Read per-field license rates rather than a single " +
			"headline number, and treat small structural deltas as format differences " +
			"rather than defects.\n\n")
		w("---\n\n")
	}

	if r.ContextNote != "" {
		w("## Key Insight: Source SBOM vs Binary SBOM\n\n")
		w("%s\n\n", r.ContextNote)
		w("---\n\n")
	} else {
		w("SBOM context: **%s** = `%s`, **%s** = `%s`.\n\n", r.LabelA, r.ContextA, r.LabelB, r.ContextB)
	}

	writeExecSummary(&b, r)
	writeCompleteness(&b, r)
	writeDeps(&b, r)
	writeLicenses(&b, r)
	writePURLs(&b, r)
	writeCPEs(&b, r)
	writeSuppliers(&b, r)
	writeChecksums(&b, r)
	writeAnnotations(&b, r)
	writeFindings(&b, r)
	writeScorecard(&b, r)
	writeMinimumElements(&b, r)
	writeRecommendations(&b, r)

	w("---\n\n")
	w("*Generated %s by bomcompare — %s vs %s*\n",
		time.Now().Format("2006-01-02"), r.LabelA, r.LabelB)
	return b.String()
}

func writeExecSummary(b *strings.Builder, r *compare.Report) {
	w := func(format string, a ...any) { fmt.Fprintf(b, format, a...) }
	w("## Executive Summary\n\n")
	w("| Criterion | %s | %s | Winner |\n", r.LabelA, r.LabelB)
	w("|-----------|%s|%s|--------|\n", dashes(r.LabelA), dashes(r.LabelB))

	c := r.Completeness
	w("| **Package Count** | %d | %d | %s |\n", c.TotalA, c.TotalB, biggerInt(c.TotalA, c.TotalB, r))
	w("| **Common Packages** | %d | %d | — |\n", c.Common, c.Common)

	v := r.Versions
	w("| **Version Accuracy** | %s | %s | %s |\n",
		matchStr(v.MatchRate, v.CommonChecked), matchStr(v.MatchRate, v.CommonChecked),
		tieIf(v.Mismatch == 0))

	l := r.Licenses
	w("| **License Coverage** | %.1f%% decl / %.1f%% concl | %.1f%% decl / %.1f%% concl | %s |\n",
		l.DeclaredRateA, l.ConcludedRateA, l.DeclaredRateB, l.ConcludedRateB,
		biggerFloat(l.EffectiveRateA, l.EffectiveRateB, r))

	d := r.Deps
	w("| **Dependency Graph** | %d edges%s | %d edges%s | %s |\n",
		d.TotalA, testTag(d.HasTestLabelingA), d.TotalB, testTag(d.HasTestLabelingB),
		biggerInt(d.TotalA, d.TotalB, r))

	s := r.Suppliers
	w("| **Supplier Attribution** | %.0f%% | %.0f%% | %s |\n",
		s.RateA, s.RateB, biggerFloat(s.RateA, s.RateB, r))

	cp := r.CPEs
	w("| **CPE Coverage** | %d (%.0f%% pkgs) | %d (%.0f%% pkgs) | %s |\n",
		cp.TotalCPEsA, cp.PkgCPERateA, cp.TotalCPEsB, cp.PkgCPERateB,
		biggerFloat(cp.PkgCPERateA, cp.PkgCPERateB, r))

	ck := r.Checksums
	w("| **Checksum Coverage** | %d/%d (%.1f%%) | %d/%d (%.1f%%) | %s |\n",
		ck.WithSHA256A, c.TotalA, ck.RateA, ck.WithSHA256B, c.TotalB, ck.RateB,
		biggerFloat(ck.RateA, ck.RateB, r))

	an := r.Annotations
	w("| **Annotations** | %d doc + %d pkg | %d doc + %d pkg | %s |\n",
		an.DocLevelA, an.PkgWithAnnA, an.DocLevelB, an.PkgWithAnnB,
		biggerInt(an.PkgWithAnnA, an.PkgWithAnnB, r))
	w("\n---\n\n")
}

func writeCompleteness(b *strings.Builder, r *compare.Report) {
	w := func(format string, a ...any) { fmt.Fprintf(b, format, a...) }
	c := r.Completeness
	w("## 1. Completeness — Package Coverage\n\n")
	w("| Metric | %s | %s |\n", r.LabelA, r.LabelB)
	w("|--------|%s|%s|\n", dashes(r.LabelA), dashes(r.LabelB))
	w("| Total packages | %d | %d |\n", c.TotalA, c.TotalB)
	w("| Unique to %s | %d | — |\n", r.LabelA, c.OnlyACount)
	w("| Unique to %s | — | %d |\n", r.LabelB, c.OnlyBCount)
	w("| Common | %d | %d |\n", c.Common, c.Common)
	if c.OnlyATestScoped > 0 || c.OnlyBTestScoped > 0 {
		w("| ↳ of which test-scoped | %d | %d |\n", c.OnlyATestScoped, c.OnlyBTestScoped)
	}
	w("\n")

	writeUniqueList(b, fmt.Sprintf("Only in %s", r.LabelB), c.OnlyB)
	writeUniqueList(b, fmt.Sprintf("Only in %s", r.LabelA), c.OnlyA)
	w("---\n\n")
}

func writeUniqueList(b *strings.Builder, title string, refs []compare.PkgRef) {
	if len(refs) == 0 {
		return
	}
	w := func(format string, a ...any) { fmt.Fprintf(b, format, a...) }
	w("### %s (%d packages)\n\n", title, len(refs))
	limit := 60
	for i, ref := range refs {
		if i >= limit {
			w("- … and %d more\n", len(refs)-limit)
			break
		}
		tag := ""
		if ref.TestScope {
			tag = " _(test)_"
		}
		ver := ref.Version
		if ver == "" {
			ver = "—"
		}
		w("- `%s` %s%s\n", ref.Name, ver, tag)
	}
	w("\n")
}

func writeDeps(b *strings.Builder, r *compare.Report) {
	w := func(format string, a ...any) { fmt.Fprintf(b, format, a...) }
	d := r.Deps
	w("## 2. Relationship Coverage — Dependency Graph\n\n")
	w("| Relationship Type | %s | %s |\n", r.LabelA, r.LabelB)
	w("|-------------------|%s|%s|\n", dashes(r.LabelA), dashes(r.LabelB))
	for _, t := range mergedTypes(d.TypeDistA, d.TypeDistB) {
		w("| %s | %d | %d |\n", t, countOf(d.TypeDistA, t), countOf(d.TypeDistB, t))
	}
	w("| **Total** | **%d** | **%d** |\n", d.TotalA, d.TotalB)
	w("| Max chain depth | %d | %d |\n\n", d.MaxDepthA, d.MaxDepthB)
	if d.HasTestLabelingA != d.HasTestLabelingB {
		who, other := r.LabelA, r.LabelB
		if d.HasTestLabelingB {
			who, other = r.LabelB, r.LabelA
		}
		w("**Note:** %s provides explicit `TEST_DEPENDENCY_OF` labeling; %s does not.\n\n", who, other)
	}
	w("---\n\n")
}

func writeLicenses(b *strings.Builder, r *compare.Report) {
	w := func(format string, a ...any) { fmt.Fprintf(b, format, a...) }
	l := r.Licenses
	w("## 3. License Coverage\n\n")
	w("| Metric | %s | %s |\n", r.LabelA, r.LabelB)
	w("|--------|%s|%s|\n", dashes(r.LabelA), dashes(r.LabelB))
	w("| `licenseDeclared` resolved | %d (%.1f%%) | %d (%.1f%%) |\n",
		l.DeclaredResolvedA, l.DeclaredRateA, l.DeclaredResolvedB, l.DeclaredRateB)
	w("| `licenseConcluded` resolved | %d (%.1f%%) | %d (%.1f%%) |\n",
		l.ConcludedResolvedA, l.ConcludedRateA, l.ConcludedResolvedB, l.ConcludedRateB)
	w("| **Effective** (best of either) | **%.1f%%** | **%.1f%%** |\n\n",
		l.EffectiveRateA, l.EffectiveRateB)

	for _, n := range l.Notes {
		w("- %s\n", n)
	}
	if len(l.Notes) > 0 {
		w("\n")
	}

	if len(l.TopLicensesA) > 0 {
		w("**Top license expressions — %s:**\n\n", r.LabelA)
		w("| License | Count |\n|---------|-------|\n")
		for _, lc := range l.TopLicensesA {
			w("| %s | %d |\n", lc.License, lc.Count)
		}
		w("\n")
	}

	if l.CommonChecked > 0 {
		w("### License agreement on %d common packages\n\n", l.CommonChecked)
		w("- **%d/%d (%.0f%%)** identical license expression\n", l.Identical, l.CommonChecked, l.IdenticalRate)
		w("- **%d/%d (%.0f%%)** differ\n\n", l.Differing, l.CommonChecked, 100-l.IdenticalRate)
		if len(l.Differences) > 0 {
			w("| Package | %s | %s |\n", r.LabelA, r.LabelB)
			w("|---------|%s|%s|\n", dashes(r.LabelA), dashes(r.LabelB))
			lim := 25
			for i, d := range l.Differences {
				if i >= lim {
					w("| … +%d more | | |\n", len(l.Differences)-lim)
					break
				}
				w("| `%s` | %s | %s |\n", d.Name, trunc(d.LicenseA, 40), trunc(d.LicenseB, 40))
			}
			w("\n")
		}
	}
	w("---\n\n")
}

func writePURLs(b *strings.Builder, r *compare.Report) {
	w := func(format string, a ...any) { fmt.Fprintf(b, format, a...) }
	q := r.PURLs
	w("## 4. PURL Quality\n\n")
	w("| Metric | %s | %s |\n", r.LabelA, r.LabelB)
	w("|--------|%s|%s|\n", dashes(r.LabelA), dashes(r.LabelB))
	w("| Packages with purl | %d (%.1f%%) | %d (%.1f%%) |\n", q.WithPURLA, q.PURLRateA, q.WithPURLB, q.PURLRateB)
	w("| Main module purl | %s | %s |\n", purlOrDash(q.MainModuleA.PURL), purlOrDash(q.MainModuleB.PURL))
	w("| Zero-version purls | %d | %d |\n", q.ZeroVersionA, q.ZeroVersionB)
	w("| PURLs with qualifiers | %d | %d |\n\n", q.QualifiersA, q.QualifiersB)

	w("**PURL type distribution — %s:** %s\n\n", r.LabelA, typeDistStr(q.TypeDistA))
	w("**PURL type distribution — %s:** %s\n\n", r.LabelB, typeDistStr(q.TypeDistB))
	if q.MainPURLNote != "" {
		w("**Note:** %s\n\n", q.MainPURLNote)
	}
	w("---\n\n")
}

func writeCPEs(b *strings.Builder, r *compare.Report) {
	w := func(format string, a ...any) { fmt.Fprintf(b, format, a...) }
	c := r.CPEs
	w("## 5. CPE Coverage\n\n")
	w("| Metric | %s | %s |\n", r.LabelA, r.LabelB)
	w("|--------|%s|%s|\n", dashes(r.LabelA), dashes(r.LabelB))
	w("| Total CPEs | %d | %d |\n", c.TotalCPEsA, c.TotalCPEsB)
	w("| Packages with ≥1 CPE | %d (%.1f%%) | %d (%.1f%%) |\n", c.PkgsWithCPEA, c.PkgCPERateA, c.PkgsWithCPEB, c.PkgCPERateB)
	w("| CPEs per package (avg) | %.1f | %.1f |\n", c.AvgPerPkgA, c.AvgPerPkgB)
	w("| Well-formed (NVD-style) | %d | %d |\n\n", c.WellFormedA, c.WellFormedB)
	w("---\n\n")
}

func writeSuppliers(b *strings.Builder, r *compare.Report) {
	w := func(format string, a ...any) { fmt.Fprintf(b, format, a...) }
	s := r.Suppliers
	w("## 6. Supplier / Origin Attribution\n\n")
	w("| Metric | %s | %s |\n", r.LabelA, r.LabelB)
	w("|--------|%s|%s|\n", dashes(r.LabelA), dashes(r.LabelB))
	w("| Packages with supplier | %d/%d (%.1f%%) | %d/%d (%.1f%%) |\n",
		s.WithSupplierA, r.Completeness.TotalA, s.RateA,
		s.WithSupplierB, r.Completeness.TotalB, s.RateB)
	w("\n---\n\n")
}

func writeChecksums(b *strings.Builder, r *compare.Report) {
	w := func(format string, a ...any) { fmt.Fprintf(b, format, a...) }
	c := r.Checksums
	w("## 7. Checksum Coverage\n\n")
	w("| Metric | %s | %s |\n", r.LabelA, r.LabelB)
	w("|--------|%s|%s|\n", dashes(r.LabelA), dashes(r.LabelB))
	w("| Packages with SHA256 | %d/%d (%.1f%%) | %d/%d (%.1f%%) |\n",
		c.WithSHA256A, r.Completeness.TotalA, c.RateA,
		c.WithSHA256B, r.Completeness.TotalB, c.RateB)
	w("\n---\n\n")
}

func writeAnnotations(b *strings.Builder, r *compare.Report) {
	w := func(format string, a ...any) { fmt.Fprintf(b, format, a...) }
	a := r.Annotations
	w("## 8. Annotations & Transparency\n\n")
	w("| Metric | %s | %s |\n", r.LabelA, r.LabelB)
	w("|--------|%s|%s|\n", dashes(r.LabelA), dashes(r.LabelB))
	w("| Document-level annotations | %d | %d |\n", a.DocLevelA, a.DocLevelB)
	w("| Package-level annotations | %d/%d | %d/%d |\n",
		a.PkgWithAnnA, r.Completeness.TotalA, a.PkgWithAnnB, r.Completeness.TotalB)
	w("| Distinct annotation fields | %d | %d |\n\n", len(a.FieldsA), len(a.FieldsB))
	if len(a.FieldsA) > 0 {
		w("**%s annotation fields:** %s\n\n", r.LabelA, strings.Join(a.FieldsA, ", "))
	}
	if len(a.FieldsB) > 0 {
		w("**%s annotation fields:** %s\n\n", r.LabelB, strings.Join(a.FieldsB, ", "))
	}
	w("---\n\n")
}

func writeFindings(b *strings.Builder, r *compare.Report) {
	w := func(format string, a ...any) { fmt.Fprintf(b, format, a...) }
	w("## 9. Findings Classification (per Gist Framework)\n\n")
	w("| Finding Type | %s | %s | Both | Assessment |\n", r.LabelA, r.LabelB)
	w("|-------------|%s|%s|------|------------|\n", dashes(r.LabelA), dashes(r.LabelB))
	for _, t := range findingOrder {
		a, bb, both := compare.CountBySideForType(r.Findings, t)
		if a == 0 && bb == 0 && both == 0 {
			w("| **%s** | 0 | 0 | 0 | none |\n", t)
			continue
		}
		w("| **%s** | %d | %d | %d | %s |\n", t, a, bb, both, findingAssessment(t, a, bb))
	}
	w("\n")

	var notable []compare.Finding
	for _, f := range r.Findings {
		if f.Severity == compare.SevHigh || f.Severity == compare.SevMed {
			notable = append(notable, f)
		}
	}
	if len(notable) > 0 {
		w("### Notable findings (medium/high severity)\n\n")
		lim := 40
		for i, f := range notable {
			if i >= lim {
				w("- … and %d more\n", len(notable)-lim)
				break
			}
			w("- **%s** [%s] `%s` — %s\n", f.Type, f.Severity, f.Package, f.Detail)
		}
		w("\n")
	}
	w("---\n\n")
}

func writeScorecard(b *strings.Builder, r *compare.Report) {
	w := func(format string, a ...any) { fmt.Fprintf(b, format, a...) }
	w("## 10. Summary Scorecard\n\n")
	w("| Category | Weight | %s | %s | Notes |\n", r.LabelA, r.LabelB)
	w("|----------|--------|%s|%s|-------|\n", dashes(r.LabelA), dashes(r.LabelB))
	for _, row := range r.Scorecard {
		w("| %s | %s | %s | %s | %s |\n",
			row.Category, row.Weight, stars(row.StarsA), stars(row.StarsB), row.Note)
	}
	w("\n")
	w("**Weighted composite:** %s **%.1f / 5.0**  ·  %s **%.1f / 5.0**  →  Winner: **%s**\n\n",
		r.LabelA, r.Overall.ScoreA, r.LabelB, r.Overall.ScoreB, r.Overall.Winner)
	w("---\n\n")
}

func writeMinimumElements(b *strings.Builder, r *compare.Report) {
	w := func(format string, a ...any) { fmt.Fprintf(b, format, a...) }
	m := r.MinimumElements
	w("## 11. Compliance — %s\n\n", m.Reference)
	w("Informational; not part of the weighted scorecard. `warn` = covered only by a declared unknown (NOASSERTION); ")
	w("`unverified` = cannot be judged from the document alone. ")
	w("Gate on these in CI with `--require-min-elements` (skip IDs via `--skip-min-elements`).\n\n")
	w("| Element | ID | Scope | %s | %s |\n", r.LabelA, r.LabelB)
	w("|---------|----|-------|%s|%s|\n", dashes(r.LabelA), dashes(r.LabelB))
	for _, row := range m.Rows {
		w("| %s | `%s` | %s | %s | %s |\n", row.Element, row.ID, row.Scope, minCell(row.Scope, row.A), minCell(row.Scope, row.B))
	}
	w("\n**Elements fully met:** %s **%d/%d**  ·  %s **%d/%d**\n\n",
		r.LabelA, m.PassedA, m.Total, r.LabelB, m.PassedB, m.Total)
	w("---\n\n")
}

func minCell(scope string, res compare.MinElementResult) string {
	var detail string
	switch {
	case scope == "component":
		detail = fmt.Sprintf("%d/%d (%.1f%%)", res.Present, res.Total, res.Rate)
		if res.Unknown > 0 {
			detail += fmt.Sprintf(", %d unknown", res.Unknown)
		}
	case res.Value == "":
		detail = "missing"
	default:
		detail = strings.ReplaceAll(trunc(res.Value, 48), "|", "\\|")
	}
	return minIcon(res.Status) + " " + detail
}

func minIcon(status string) string {
	switch status {
	case compare.MinPass:
		return "✅"
	case compare.MinWarn:
		return "⚠️"
	case compare.MinUnverified:
		return "❔"
	default:
		return "❌"
	}
}

func writeRecommendations(b *strings.Builder, r *compare.Report) {
	w := func(format string, a ...any) { fmt.Fprintf(b, format, a...) }
	w("## Recommendations\n\n")
	recs := buildRecommendations(r)
	if len(recs) == 0 {
		w("No significant issues detected — both SBOMs are of comparable quality.\n\n")
		return
	}
	for i, rec := range recs {
		w("%d. %s\n", i+1, rec)
	}
	w("\n")
}
