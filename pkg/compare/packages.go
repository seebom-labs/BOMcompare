package compare

import (
	"sort"
	"strings"

	"github.com/seebom-labs/BOMcompare/pkg/sbom"
)

// Completeness captures package coverage between the two SBOMs.
type Completeness struct {
	TotalA int `json:"totalA"`
	TotalB int `json:"totalB"`
	Common int `json:"common"`

	OnlyACount int `json:"onlyACount"`
	OnlyBCount int `json:"onlyBCount"`

	// Test-scoped breakdown of the unique sets (helps explain "extra" packages).
	OnlyATestScoped int `json:"onlyATestScoped"`
	OnlyBTestScoped int `json:"onlyBTestScoped"`

	OnlyA []PkgRef `json:"onlyA"`
	OnlyB []PkgRef `json:"onlyB"`

	StarsA int `json:"starsA"`
	StarsB int `json:"starsB"`
}

// PkgRef is a compact package descriptor for report output.
type PkgRef struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	PURL      string `json:"purl,omitempty"`
	TestScope bool   `json:"testScope,omitempty"`
}

func toRef(p *sbom.NormalizedPackage) PkgRef {
	return PkgRef{Name: p.Name, Version: p.Version, PURL: p.PURL, TestScope: p.IsTestScoped}
}

func analyzeCompleteness(a, b *sbom.Parsed, s *Sets) Completeness {
	c := Completeness{
		TotalA: len(a.Packages),
		TotalB: len(b.Packages),
		Common: len(s.Common),
	}
	for _, p := range s.OnlyA {
		c.OnlyA = append(c.OnlyA, toRef(p))
		if p.IsTestScoped {
			c.OnlyATestScoped++
		}
	}
	for _, p := range s.OnlyB {
		c.OnlyB = append(c.OnlyB, toRef(p))
		if p.IsTestScoped {
			c.OnlyBTestScoped++
		}
	}
	c.OnlyACount = len(c.OnlyA)
	c.OnlyBCount = len(c.OnlyB)
	sortRefs(c.OnlyA)
	sortRefs(c.OnlyB)

	// Score: more total coverage scores higher; the smaller set is penalized
	// relative to the larger. A perfect overlap ties at 5.
	c.StarsA = coverageStars(c.TotalA, c.TotalB)
	c.StarsB = coverageStars(c.TotalB, c.TotalA)
	return c
}

// coverageStars rewards the SBOM with broader coverage. Equal counts → 5/5 both.
func coverageStars(self, other int) int {
	if self == 0 {
		return 1
	}
	if other == 0 || self >= other {
		return 5
	}
	ratio := float64(self) / float64(other)
	switch {
	case ratio >= 0.95:
		return 5
	case ratio >= 0.8:
		return 4
	case ratio >= 0.6:
		return 3
	case ratio >= 0.4:
		return 2
	default:
		return 1
	}
}

// ---- shared normalization helpers ----

// normName lowercases and trims a package name for matching.
func normName(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// normVersion strips a leading 'v' and surrounding whitespace so "v1.2.3" and
// "1.2.3" compare equal.
func normVersion(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || strings.EqualFold(s, sbom.NoAssertion) || strings.EqualFold(s, sbom.None) {
		return ""
	}
	return strings.TrimPrefix(s, "v")
}

// lastSegment returns the final path component of a module path.
func lastSegment(modulePath string) string {
	if modulePath == "" {
		return ""
	}
	if i := strings.LastIndexByte(modulePath, '/'); i >= 0 {
		return modulePath[i+1:]
	}
	return modulePath
}

func sortRefs(refs []PkgRef) {
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].Name == refs[j].Name {
			return refs[i].Version < refs[j].Version
		}
		return refs[i].Name < refs[j].Name
	})
}

// pct computes a safe percentage (0 when denom is 0).
func pct(num, denom int) float64 {
	if denom == 0 {
		return 0
	}
	return float64(num) / float64(denom) * 100
}

// coverageStarsPct maps a 0-100 coverage percentage to 1-5 stars.
func coverageStarsPct(p float64) int {
	switch {
	case p >= 95:
		return 5
	case p >= 80:
		return 4
	case p >= 60:
		return 3
	case p >= 30:
		return 2
	default:
		return 1
	}
}
