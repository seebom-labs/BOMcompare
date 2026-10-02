package compare

import (
	"sort"
	"strings"

	"github.com/seebom-labs/BOMcompare/pkg/sbom"
)

// Licenses captures license resolution rates per SBOM and a cross-comparison of
// common packages. It deliberately tracks declared and concluded separately
// because tools disagree on which field to populate (mikebom uses declared,
// syft uses concluded).
type Licenses struct {
	DeclaredResolvedA  int `json:"declaredResolvedA"`
	DeclaredResolvedB  int `json:"declaredResolvedB"`
	ConcludedResolvedA int `json:"concludedResolvedA"`
	ConcludedResolvedB int `json:"concludedResolvedB"`

	DeclaredRateA  float64 `json:"declaredRateA"`
	DeclaredRateB  float64 `json:"declaredRateB"`
	ConcludedRateA float64 `json:"concludedRateA"`
	ConcludedRateB float64 `json:"concludedRateB"`

	// EffectiveRate is the best-of(declared, concluded) coverage — the practical
	// "do we know the license at all" number.
	EffectiveRateA float64 `json:"effectiveRateA"`
	EffectiveRateB float64 `json:"effectiveRateB"`

	// Distribution of the effective license expression (top entries).
	TopLicensesA []LicenseCount `json:"topLicensesA"`
	TopLicensesB []LicenseCount `json:"topLicensesB"`

	// Cross-comparison over common packages.
	CommonChecked int           `json:"commonChecked"`
	Identical     int           `json:"identical"`
	Differing     int           `json:"differing"`
	IdenticalRate float64       `json:"identicalRate"`
	Differences   []LicenseDiff `json:"differences"`

	// Notes flags structural observations (e.g. concluded all NOASSERTION).
	Notes []string `json:"notes,omitempty"`

	StarsA int `json:"starsA"`
	StarsB int `json:"starsB"`
}

// LicenseCount is a license expression with its frequency.
type LicenseCount struct {
	License string `json:"license"`
	Count   int    `json:"count"`
}

// LicenseDiff records a differing license expression for a common package.
type LicenseDiff struct {
	Name     string `json:"name"`
	LicenseA string `json:"licenseA"`
	LicenseB string `json:"licenseB"`
}

func resolved(s string) bool {
	s = strings.TrimSpace(s)
	return s != "" && !strings.EqualFold(s, sbom.NoAssertion) && !strings.EqualFold(s, sbom.None)
}

// effectiveLicense returns the concluded license if resolved, else declared.
func effectiveLicense(p *sbom.NormalizedPackage) string {
	if resolved(p.LicenseConcluded) {
		return p.LicenseConcluded
	}
	if resolved(p.LicenseDeclared) {
		return p.LicenseDeclared
	}
	return ""
}

func analyzeLicenses(a, b *sbom.Parsed, s *Sets) Licenses {
	l := Licenses{}
	l.DeclaredResolvedA, l.ConcludedResolvedA, l.TopLicensesA = licenseStats(a)
	l.DeclaredResolvedB, l.ConcludedResolvedB, l.TopLicensesB = licenseStats(b)

	l.DeclaredRateA = pct(l.DeclaredResolvedA, len(a.Packages))
	l.DeclaredRateB = pct(l.DeclaredResolvedB, len(b.Packages))
	l.ConcludedRateA = pct(l.ConcludedResolvedA, len(a.Packages))
	l.ConcludedRateB = pct(l.ConcludedResolvedB, len(b.Packages))

	effA, effB := 0, 0
	for i := range a.Packages {
		if effectiveLicense(&a.Packages[i]) != "" {
			effA++
		}
	}
	for i := range b.Packages {
		if effectiveLicense(&b.Packages[i]) != "" {
			effB++
		}
	}
	l.EffectiveRateA = pct(effA, len(a.Packages))
	l.EffectiveRateB = pct(effB, len(b.Packages))

	// Structural notes mirroring the manual comparison's key insight.
	if l.ConcludedResolvedA == 0 && l.DeclaredResolvedA > 0 {
		l.Notes = append(l.Notes, a.ToolLabel+" populates licenseDeclared but leaves licenseConcluded as NOASSERTION (data present in the declared field).")
	}
	if l.ConcludedResolvedB == 0 && l.DeclaredResolvedB > 0 {
		l.Notes = append(l.Notes, b.ToolLabel+" populates licenseDeclared but leaves licenseConcluded as NOASSERTION (data present in the declared field).")
	}
	if l.DeclaredResolvedA == 0 && l.ConcludedResolvedA > 0 {
		l.Notes = append(l.Notes, a.ToolLabel+" populates licenseConcluded directly (declared not used).")
	}
	if l.DeclaredResolvedB == 0 && l.ConcludedResolvedB > 0 {
		l.Notes = append(l.Notes, b.ToolLabel+" populates licenseConcluded directly (declared not used).")
	}

	// Cross-comparison over common packages using effective expressions.
	for _, pair := range s.Common {
		ea := normLicense(effectiveLicense(pair.A))
		eb := normLicense(effectiveLicense(pair.B))
		if ea == "" || eb == "" {
			continue
		}
		l.CommonChecked++
		if ea == eb {
			l.Identical++
			continue
		}
		l.Differing++
		if len(l.Differences) < 200 {
			l.Differences = append(l.Differences, LicenseDiff{
				Name:     pair.A.Name,
				LicenseA: effectiveLicense(pair.A),
				LicenseB: effectiveLicense(pair.B),
			})
		}
	}
	l.IdenticalRate = pct(l.Identical, l.CommonChecked)

	l.StarsA = coverageStarsPct(l.EffectiveRateA)
	l.StarsB = coverageStarsPct(l.EffectiveRateB)
	return l
}

// licenseStats counts declared/concluded resolution and computes the top
// effective-license distribution.
func licenseStats(p *sbom.Parsed) (declared, concluded int, top []LicenseCount) {
	dist := map[string]int{}
	for i := range p.Packages {
		pk := &p.Packages[i]
		if resolved(pk.LicenseDeclared) {
			declared++
		}
		if resolved(pk.LicenseConcluded) {
			concluded++
		}
		if eff := effectiveLicense(pk); eff != "" {
			dist[eff]++
		}
	}
	for lic, n := range dist {
		top = append(top, LicenseCount{License: lic, Count: n})
	}
	sort.Slice(top, func(i, j int) bool {
		if top[i].Count == top[j].Count {
			return top[i].License < top[j].License
		}
		return top[i].Count > top[j].Count
	})
	if len(top) > 12 {
		top = top[:12]
	}
	return declared, concluded, top
}

// normLicense normalizes a license expression for equality comparison: upper
// case, collapse whitespace, sort AND-joined terms so ordering doesn't matter.
func normLicense(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	up := strings.ToUpper(s)
	if !strings.Contains(up, " AND ") {
		return strings.Join(strings.Fields(up), " ")
	}
	parts := strings.Split(up, " AND ")
	for i := range parts {
		parts[i] = strings.Join(strings.Fields(parts[i]), " ")
	}
	sort.Strings(parts)
	return strings.Join(parts, " AND ")
}
