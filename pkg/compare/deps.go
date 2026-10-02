package compare

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/seebom-labs/BOMcompare/pkg/sbom"
)

// DepGraph summarizes the dependency relationship graph for one comparison.
type DepGraph struct {
	TotalA int `json:"totalA"`
	TotalB int `json:"totalB"`

	TypeDistA []TypeCount `json:"typeDistA"`
	TypeDistB []TypeCount `json:"typeDistB"`

	TestEdgesA int `json:"testEdgesA"`
	TestEdgesB int `json:"testEdgesB"`

	// MaxDepth is the longest dependency chain length following
	// DEPENDS_ON / DEPENDENCY_OF / CONTAINS edges from the root.
	MaxDepthA int `json:"maxDepthA"`
	MaxDepthB int `json:"maxDepthB"`

	HasTestLabelingA bool `json:"hasTestLabelingA"`
	HasTestLabelingB bool `json:"hasTestLabelingB"`

	StarsA int `json:"starsA"`
	StarsB int `json:"starsB"`
}

func analyzeDeps(a, b *sbom.Parsed) DepGraph {
	d := DepGraph{}
	d.TotalA, d.TypeDistA, d.TestEdgesA, d.MaxDepthA = depStats(a)
	d.TotalB, d.TypeDistB, d.TestEdgesB, d.MaxDepthB = depStats(b)
	d.HasTestLabelingA = d.TestEdgesA > 0
	d.HasTestLabelingB = d.TestEdgesB > 0

	d.StarsA = depStars(d.TotalA, d.TotalB, len(a.Packages), d.HasTestLabelingA, d.MaxDepthA)
	d.StarsB = depStars(d.TotalB, d.TotalA, len(b.Packages), d.HasTestLabelingB, d.MaxDepthB)
	return d
}

func depStats(p *sbom.Parsed) (total int, dist []TypeCount, testEdges, maxDepth int) {
	types := map[string]int{}
	for _, r := range p.Relationships {
		total++
		t := strings.ToUpper(r.RelationshipType)
		types[t]++
		if t == "TEST_DEPENDENCY_OF" {
			testEdges++
		}
	}
	for t, n := range types {
		dist = append(dist, TypeCount{Type: t, Count: n})
	}
	sort.Slice(dist, func(i, j int) bool {
		if dist[i].Count == dist[j].Count {
			return dist[i].Type < dist[j].Type
		}
		return dist[i].Count > dist[j].Count
	})
	maxDepth = graphDepth(p)
	return total, dist, testEdges, maxDepth
}

// forwardDepEdges are relationship types where SPDXElementID depends on /
// incorporates RelatedSPDXElement (SPDX 2 names plus the SPDX 3 names as
// normalized to UPPER_SNAKE by the SPDX 3 loader).
var forwardDepEdges = map[string]bool{
	"DEPENDS_ON": true, "CONTAINS": true, "GENERATED_FROM": true,
	"STATIC_LINK": true, "DYNAMIC_LINK": true,
	"HAS_STATIC_LINK": true, "HAS_DYNAMIC_LINK": true,
	"HAS_OPTIONAL_DEPENDENCY": true, "HAS_PROVIDED_DEPENDENCY": true,
	"HAS_OPTIONAL_COMPONENT": true,
}

// reverseDepEdges are "X <type> Y" relationships meaning Y depends on X.
var reverseDepEdges = map[string]bool{
	"DEPENDENCY_OF": true, "TEST_DEPENDENCY_OF": true, "DEV_DEPENDENCY_OF": true,
	"BUILD_DEPENDENCY_OF": true, "OPTIONAL_DEPENDENCY_OF": true,
	"RUNTIME_DEPENDENCY_OF": true, "PROVIDED_DEPENDENCY_OF": true,
	"CONTAINED_BY": true,
}

// IsDependencyEdge reports whether a relationship type expresses a
// dependency/containment edge between components.
func IsDependencyEdge(relType string) bool {
	t := strings.ToUpper(relType)
	return forwardDepEdges[t] || reverseDepEdges[t]
}

// graphDepth computes the longest dependency chain via a DFS over forward edges
// (forwardDepEdges) plus reversed *_DEPENDENCY_OF edges (reverseDepEdges),
// starting from elements that are described by the document. It is cycle-safe.
func graphDepth(p *sbom.Parsed) int {
	adj := map[string][]string{}
	add := func(from, to string) {
		if from == "" || to == "" {
			return
		}
		adj[from] = append(adj[from], to)
	}
	roots := map[string]bool{}
	for _, r := range p.Relationships {
		t := strings.ToUpper(r.RelationshipType)
		switch {
		case t == "DESCRIBES":
			roots[r.RelatedSPDXElement] = true
			add(r.SPDXElementID, r.RelatedSPDXElement)
		case forwardDepEdges[t]:
			add(r.SPDXElementID, r.RelatedSPDXElement)
		case reverseDepEdges[t]:
			// reverse direction: related depends-on element
			add(r.RelatedSPDXElement, r.SPDXElementID)
		}
	}
	if len(roots) == 0 {
		// Fall back to all package nodes as potential roots.
		for i := range p.Packages {
			roots[p.Packages[i].SPDXID] = true
		}
	}

	memo := map[string]int{}
	visiting := map[string]bool{}
	var depth func(node string) int
	depth = func(node string) int {
		if d, ok := memo[node]; ok {
			return d
		}
		if visiting[node] {
			return 0 // cycle guard
		}
		visiting[node] = true
		best := 0
		for _, next := range adj[node] {
			if d := depth(next); d > best {
				best = d
			}
		}
		visiting[node] = false
		memo[node] = best + 1
		return memo[node]
	}

	max := 0
	for root := range roots {
		if d := depth(root); d > max {
			max = d
		}
	}
	// Depth in "edges" rather than "nodes".
	if max > 0 {
		return max - 1
	}
	return 0
}

func depStars(self, other, pkgCount int, hasTestLabel bool, depth int) int {
	if self == 0 {
		return 1
	}
	stars := 3
	// Density: edges per package. A flat graph (~1 edge/pkg) is weak; a rich
	// graph (>2 edges/pkg) is strong.
	if pkgCount > 0 {
		density := float64(self) / float64(pkgCount)
		switch {
		case density >= 3:
			stars = 5
		case density >= 1.5:
			stars = 4
		case density >= 0.9:
			stars = 3
		default:
			stars = 2
		}
	}
	// Relative richness vs the other SBOM.
	if other > 0 && self >= 2*other && stars < 5 {
		stars++
	}
	if hasTestLabel && stars < 5 {
		stars++
	}
	if depth <= 1 && stars > 2 {
		stars-- // a flat one-level graph loses a star
	}
	if stars > 5 {
		stars = 5
	}
	if stars < 1 {
		stars = 1
	}
	return stars
}

// ---- Suppliers ----

// Suppliers summarizes supplier/originator attribution coverage.
type Suppliers struct {
	WithSupplierA int     `json:"withSupplierA"`
	WithSupplierB int     `json:"withSupplierB"`
	RateA         float64 `json:"rateA"`
	RateB         float64 `json:"rateB"`
	StarsA        int     `json:"starsA"`
	StarsB        int     `json:"starsB"`
}

func analyzeSuppliers(a, b *sbom.Parsed) Suppliers {
	s := Suppliers{}
	s.WithSupplierA = supplierCount(a)
	s.WithSupplierB = supplierCount(b)
	s.RateA = pct(s.WithSupplierA, len(a.Packages))
	s.RateB = pct(s.WithSupplierB, len(b.Packages))
	s.StarsA = coverageStarsPct(s.RateA)
	s.StarsB = coverageStarsPct(s.RateB)
	return s
}

func supplierCount(p *sbom.Parsed) int {
	n := 0
	for i := range p.Packages {
		sup := strings.TrimSpace(p.Packages[i].Supplier)
		if sup != "" && !strings.EqualFold(sup, sbom.NoAssertion) && !strings.EqualFold(sup, sbom.None) {
			n++
		}
	}
	return n
}

// ---- Checksums ----

// Checksums summarizes SHA256 integrity coverage.
type Checksums struct {
	WithSHA256A int     `json:"withSha256A"`
	WithSHA256B int     `json:"withSha256B"`
	RateA       float64 `json:"rateA"`
	RateB       float64 `json:"rateB"`
	StarsA      int     `json:"starsA"`
	StarsB      int     `json:"starsB"`
}

func analyzeChecksums(a, b *sbom.Parsed) Checksums {
	c := Checksums{}
	for i := range a.Packages {
		if a.Packages[i].HasSHA256 {
			c.WithSHA256A++
		}
	}
	for i := range b.Packages {
		if b.Packages[i].HasSHA256 {
			c.WithSHA256B++
		}
	}
	c.RateA = pct(c.WithSHA256A, len(a.Packages))
	c.RateB = pct(c.WithSHA256B, len(b.Packages))
	c.StarsA = coverageStarsPct(c.RateA)
	c.StarsB = coverageStarsPct(c.RateB)
	return c
}

// ---- Annotations ----

// Annotations summarizes annotation richness (transparency).
type Annotations struct {
	DocLevelA int `json:"docLevelA"`
	DocLevelB int `json:"docLevelB"`

	PkgWithAnnA int `json:"pkgWithAnnA"`
	PkgWithAnnB int `json:"pkgWithAnnB"`

	TotalPkgAnnA int `json:"totalPkgAnnA"`
	TotalPkgAnnB int `json:"totalPkgAnnB"`

	FieldsA []string `json:"fieldsA"`
	FieldsB []string `json:"fieldsB"`

	StarsA int `json:"starsA"`
	StarsB int `json:"starsB"`
}

func analyzeAnnotations(a, b *sbom.Parsed) Annotations {
	an := Annotations{}
	an.DocLevelA = len(a.DocAnnotations)
	an.DocLevelB = len(b.DocAnnotations)
	an.PkgWithAnnA, an.TotalPkgAnnA, an.FieldsA = annStats(a)
	an.PkgWithAnnB, an.TotalPkgAnnB, an.FieldsB = annStats(b)

	an.StarsA = annStars(an.DocLevelA, an.PkgWithAnnA, len(a.Packages), len(an.FieldsA))
	an.StarsB = annStars(an.DocLevelB, an.PkgWithAnnB, len(b.Packages), len(an.FieldsB))
	return an
}

func annStats(p *sbom.Parsed) (pkgWith, total int, fields []string) {
	fieldSet := map[string]bool{}
	for i := range p.Packages {
		anns := p.Packages[i].Annotations
		if len(anns) > 0 {
			pkgWith++
			total += len(anns)
		}
		for _, a := range anns {
			if f := annotationField(a.Comment); f != "" {
				fieldSet[f] = true
			}
		}
	}
	for _, a := range p.DocAnnotations {
		if f := annotationField(a.Comment); f != "" {
			fieldSet[f] = true
		}
	}
	for f := range fieldSet {
		fields = append(fields, f)
	}
	sort.Strings(fields)
	return pkgWith, total, fields
}

// annotationField extracts the "field" key from a structured annotation comment,
// if present.
func annotationField(comment string) string {
	var payload sbom.AnnotationPayload
	if json.Unmarshal([]byte(comment), &payload) == nil && payload.Field != "" {
		return payload.Field
	}
	return ""
}

func annStars(doc, pkgWith, total, fieldCount int) int {
	if doc == 0 && pkgWith == 0 {
		return 1
	}
	cov := pct(pkgWith, total)
	stars := coverageStarsPct(cov)
	if fieldCount >= 5 && stars < 5 {
		stars++
	}
	if doc > 0 && stars < 5 {
		stars++
	}
	if stars > 5 {
		stars = 5
	}
	return stars
}
