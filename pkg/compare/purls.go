package compare

import (
	"sort"
	"strings"

	"github.com/seebom-labs/BOMcompare/pkg/sbom"
)

// PURLQuality summarizes package URL identity quality for one comparison.
type PURLQuality struct {
	WithPURLA int     `json:"withPurlA"`
	WithPURLB int     `json:"withPurlB"`
	PURLRateA float64 `json:"purlRateA"`
	PURLRateB float64 `json:"purlRateB"`

	TypeDistA []TypeCount `json:"typeDistA"`
	TypeDistB []TypeCount `json:"typeDistB"`

	ZeroVersionA int `json:"zeroVersionA"`
	ZeroVersionB int `json:"zeroVersionB"`

	QualifiersA int `json:"qualifiersA"`
	QualifiersB int `json:"qualifiersB"`

	MainModuleA PkgRef `json:"mainModuleA"`
	MainModuleB PkgRef `json:"mainModuleB"`
	// MainPURLNote flags when the main module purl uses a non-specific type such
	// as pkg:generic instead of the ecosystem type.
	MainPURLNote string `json:"mainPurlNote,omitempty"`

	StarsA int `json:"starsA"`
	StarsB int `json:"starsB"`
}

// TypeCount is a purl type with its frequency.
type TypeCount struct {
	Type  string `json:"type"`
	Count int    `json:"count"`
}

func analyzePURLs(a, b *sbom.Parsed) PURLQuality {
	q := PURLQuality{}
	q.WithPURLA, q.TypeDistA, q.ZeroVersionA, q.QualifiersA, q.MainModuleA = purlStats(a)
	q.WithPURLB, q.TypeDistB, q.ZeroVersionB, q.QualifiersB, q.MainModuleB = purlStats(b)
	q.PURLRateA = pct(q.WithPURLA, len(a.Packages))
	q.PURLRateB = pct(q.WithPURLB, len(b.Packages))

	noteA := mainPurlIssue(q.MainModuleA, a.ToolLabel)
	noteB := mainPurlIssue(q.MainModuleB, b.ToolLabel)
	switch {
	case noteA != "" && noteB != "":
		q.MainPURLNote = noteA + " " + noteB
	case noteA != "":
		q.MainPURLNote = noteA
	default:
		q.MainPURLNote = noteB
	}

	q.StarsA = purlStars(q.PURLRateA, q.MainModuleA, q.ZeroVersionA, len(a.Packages))
	q.StarsB = purlStars(q.PURLRateB, q.MainModuleB, q.ZeroVersionB, len(b.Packages))
	return q
}

func purlStats(p *sbom.Parsed) (withPurl int, dist []TypeCount, zeroVer, qualifiers int, main PkgRef) {
	types := map[string]int{}
	for i := range p.Packages {
		pk := &p.Packages[i]
		if pk.PURL == "" {
			continue
		}
		withPurl++
		types[pk.PURLType]++
		if sbom.PURLVersion(pk.PURL) == "" {
			zeroVer++
		}
		if sbom.PURLHasQualifiers(pk.PURL) {
			qualifiers++
		}
		if pk.IsMainModule && main.Name == "" {
			main = toRef(pk)
		}
	}
	// If the document never flagged a main module, leave main empty.
	for t, n := range types {
		dist = append(dist, TypeCount{Type: t, Count: n})
	}
	sort.Slice(dist, func(i, j int) bool {
		if dist[i].Count == dist[j].Count {
			return dist[i].Type < dist[j].Type
		}
		return dist[i].Count > dist[j].Count
	})
	return withPurl, dist, zeroVer, qualifiers, main
}

// mainPurlIssue returns a note when the main module purl is non-specific.
func mainPurlIssue(main PkgRef, tool string) string {
	if main.PURL == "" {
		return ""
	}
	if strings.HasPrefix(main.PURL, "pkg:generic/") {
		return tool + "'s main module purl is non-specific (" + main.PURL +
			") — an ecosystem-typed purl (e.g. pkg:golang/<module>) is more actionable for vulnerability matching."
	}
	return ""
}

func purlStars(rate float64, main PkgRef, zeroVer, total int) int {
	stars := coverageStarsPct(rate)
	// Penalize a non-specific main module purl by one star.
	if strings.HasPrefix(main.PURL, "pkg:generic/") && stars > 1 {
		stars--
	}
	// Penalize heavy zero-version purls.
	if total > 0 && pct(zeroVer, total) > 25 && stars > 1 {
		stars--
	}
	return stars
}

// ---- CPE coverage ----

// CPECoverage summarizes CPE presence and density.
type CPECoverage struct {
	TotalCPEsA int `json:"totalCpesA"`
	TotalCPEsB int `json:"totalCpesB"`

	PkgsWithCPEA int `json:"pkgsWithCpeA"`
	PkgsWithCPEB int `json:"pkgsWithCpeB"`

	PkgCPERateA float64 `json:"pkgCpeRateA"`
	PkgCPERateB float64 `json:"pkgCpeRateB"`

	AvgPerPkgA float64 `json:"avgPerPkgA"`
	AvgPerPkgB float64 `json:"avgPerPkgB"`

	// WellFormed counts CPEs matching the cpe:2.3:a:vendor:product:version shape.
	WellFormedA int `json:"wellFormedA"`
	WellFormedB int `json:"wellFormedB"`

	StarsA int `json:"starsA"`
	StarsB int `json:"starsB"`
}

func analyzeCPEs(a, b *sbom.Parsed) CPECoverage {
	c := CPECoverage{}
	c.TotalCPEsA, c.PkgsWithCPEA, c.WellFormedA = cpeStats(a)
	c.TotalCPEsB, c.PkgsWithCPEB, c.WellFormedB = cpeStats(b)

	c.PkgCPERateA = pct(c.PkgsWithCPEA, len(a.Packages))
	c.PkgCPERateB = pct(c.PkgsWithCPEB, len(b.Packages))
	if c.PkgsWithCPEA > 0 {
		c.AvgPerPkgA = float64(c.TotalCPEsA) / float64(c.PkgsWithCPEA)
	}
	if c.PkgsWithCPEB > 0 {
		c.AvgPerPkgB = float64(c.TotalCPEsB) / float64(c.PkgsWithCPEB)
	}
	c.StarsA = coverageStarsPct(c.PkgCPERateA)
	c.StarsB = coverageStarsPct(c.PkgCPERateB)
	return c
}

func cpeStats(p *sbom.Parsed) (total, withCPE, wellFormed int) {
	for i := range p.Packages {
		n := len(p.Packages[i].CPEs)
		if n == 0 {
			continue
		}
		withCPE++
		total += n
		for _, cpe := range p.Packages[i].CPEs {
			if isWellFormedCPE(cpe) {
				wellFormed++
			}
		}
	}
	return total, withCPE, wellFormed
}

// isWellFormedCPE checks for a cpe:2.3 string with the expected number of
// colon-separated fields and no obviously broken vendor/product (e.g. escaped
// slashes from a Go module path, which NVD will not match).
func isWellFormedCPE(cpe string) bool {
	if !strings.HasPrefix(cpe, "cpe:2.3:") {
		return false
	}
	if strings.Count(cpe, ":") < 6 {
		return false
	}
	// A module-path-style CPE embeds an escaped slash in vendor/product.
	if strings.Contains(cpe, "\\/") {
		return false
	}
	return true
}
