package compare

import (
	"strings"

	"github.com/seebom-labs/BOMcompare/pkg/sbom"
)

// FindingType enumerates the Lieberman-framework finding categories.
type FindingType string

const (
	MissingComponent FindingType = "MISSING_COMPONENT"
	PhantomComponent FindingType = "PHANTOM_COMPONENT"
	VersionMismatch  FindingType = "VERSION_MISMATCH"
	PurlMismatch     FindingType = "PURL_MISMATCH"
	FalsePositive    FindingType = "FALSE_POSITIVE"
	LicenseGap       FindingType = "LICENSE_GAP"
)

// Severity grades a finding for triage/CI gating.
type Severity string

const (
	SevInfo Severity = "info"
	SevLow  Severity = "low"
	SevMed  Severity = "medium"
	SevHigh Severity = "high"
)

// Finding is a single classified discrepancy.
type Finding struct {
	Type     FindingType `json:"type"`
	Severity Severity    `json:"severity"`
	// Side indicates where the issue is observed: "A", "B", or "both".
	Side    string `json:"side"`
	Package string `json:"package,omitempty"`
	Detail  string `json:"detail"`
}

// classifyFindings turns the analyzed report + package sets into discrete
// findings per the benchmark framework.
func classifyFindings(r *Report, s *Sets) []Finding {
	var out []Finding

	// MISSING_COMPONENT: packages present in one SBOM but not the other. We treat
	// runtime-scoped uniques as more severe than test-scoped ones. The label and
	// context passed are those of the SBOM the package IS present in.
	for _, p := range s.OnlyB {
		out = append(out, missingFinding(p, "A", r.LabelB, r.ContextB))
	}
	for _, p := range s.OnlyA {
		out = append(out, missingFinding(p, "B", r.LabelA, r.ContextA))
	}

	// VERSION_MISMATCH: same package, different version.
	for _, d := range r.Versions.Mismatches {
		out = append(out, Finding{
			Type:     VersionMismatch,
			Severity: SevHigh,
			Side:     "both",
			Package:  d.Name,
			Detail:   r.LabelA + "=" + d.VersionA + " vs " + r.LabelB + "=" + d.VersionB,
		})
	}

	// PURL_MISMATCH: matched package whose purls differ in type/format (e.g.
	// pkg:generic vs pkg:golang for the same module).
	for _, pair := range s.Common {
		if pair.A.PURL == "" || pair.B.PURL == "" {
			continue
		}
		if pair.A.PURL == pair.B.PURL {
			continue
		}
		if pair.A.PURLType != pair.B.PURLType {
			out = append(out, Finding{
				Type:     PurlMismatch,
				Severity: SevLow,
				Side:     "both",
				Package:  pair.A.Name,
				Detail:   r.LabelA + ": " + pair.A.PURL + "  |  " + r.LabelB + ": " + pair.B.PURL,
			})
		}
	}

	// LICENSE_GAP: matched/common packages with no resolvable license at all, on
	// either side.
	for _, pair := range s.Common {
		if effectiveLicense(pair.A) == "" {
			out = append(out, licenseGap(pair.A, "A", r.LabelA))
		}
		if effectiveLicense(pair.B) == "" {
			out = append(out, licenseGap(pair.B, "B", r.LabelB))
		}
	}

	// PHANTOM_COMPONENT / FALSE_POSITIVE: heuristic. A phantom is a package that
	// looks unreal — empty/NOASSERTION version AND no purl AND no checksum. A
	// false positive is a package whose name and purl module path disagree
	// fundamentally (different last segment), suggesting wrong identity.
	for i := range r.A.Packages {
		if f, ok := phantomOrFalse(&r.A.Packages[i], "A", r.LabelA); ok {
			out = append(out, f)
		}
	}
	for i := range r.B.Packages {
		if f, ok := phantomOrFalse(&r.B.Packages[i], "B", r.LabelB); ok {
			out = append(out, f)
		}
	}

	return out
}

func missingFinding(p *sbom.NormalizedPackage, missingFromSide, presentTool, presentCtx string) Finding {
	sev := SevMed
	detail := "present in " + presentTool + " but absent here"
	if p.IsTestScoped {
		sev = SevLow
		detail += " (test-scoped dependency)"
	}
	if p.IsStdlib {
		detail += " (Go standard library)"
	}
	if p.IsMainModule {
		detail += " (main module — may be a purl/identity difference rather than a true omission)"
	}
	// A binary SBOM legitimately omits source-only transitive deps; downgrade.
	if presentCtx == "source" && !p.IsMainModule && !p.IsStdlib {
		sev = SevLow
		detail += "; expected when comparing a binary SBOM against a source SBOM"
	}
	return Finding{
		Type:     MissingComponent,
		Severity: sev,
		Side:     missingFromSide,
		Package:  p.Name + "@" + p.Version,
		Detail:   detail,
	}
}

func licenseGap(p *sbom.NormalizedPackage, side, tool string) Finding {
	return Finding{
		Type:     LicenseGap,
		Severity: SevMed,
		Side:     side,
		Package:  p.Name + "@" + p.Version,
		Detail:   tool + " has neither licenseConcluded nor licenseDeclared resolved",
	}
}

func phantomOrFalse(p *sbom.NormalizedPackage, side, tool string) (Finding, bool) {
	noVersion := normVersion(p.Version) == "" && sbom.PURLVersion(p.PURL) == ""
	if p.PURL == "" && !p.HasSHA256 && noVersion && !p.IsMainModule {
		return Finding{
			Type:     PhantomComponent,
			Severity: SevMed,
			Side:     side,
			Package:  p.Name,
			Detail:   tool + ": package has no purl, no checksum and no version — likely spurious",
		}, true
	}
	// False-positive identity heuristic: name vs purl module last-segment differ.
	if p.PURL != "" && p.ModulePath != "" {
		nameSeg := normName(lastSegment(normName(p.Name)))
		purlSeg := lastSegment(p.ModulePath)
		if nameSeg != "" && purlSeg != "" && nameSeg != purlSeg &&
			!strings.Contains(p.ModulePath, normName(p.Name)) &&
			!strings.Contains(normName(p.Name), purlSeg) {
			return Finding{
				Type:     FalsePositive,
				Severity: SevLow,
				Side:     side,
				Package:  p.Name,
				Detail:   tool + ": package name '" + p.Name + "' disagrees with purl identity '" + p.PURL + "'",
			}, true
		}
	}
	return Finding{}, false
}

// CountByType tallies findings by type for summary rendering.
func CountByType(findings []Finding) map[FindingType]int {
	m := map[FindingType]int{}
	for _, f := range findings {
		m[f.Type]++
	}
	return m
}

// CountBySide tallies a given finding type per side.
func CountBySideForType(findings []Finding, t FindingType) (a, b, both int) {
	for _, f := range findings {
		if f.Type != t {
			continue
		}
		switch f.Side {
		case "A":
			a++
		case "B":
			b++
		default:
			both++
		}
	}
	return a, b, both
}
