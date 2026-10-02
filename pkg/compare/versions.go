package compare

import "github.com/seebom-labs/BOMcompare/pkg/sbom"

// Versions reports version agreement across the common package set.
type Versions struct {
	CommonChecked int           `json:"commonChecked"`
	Match         int           `json:"match"`
	Mismatch      int           `json:"mismatch"`
	MatchRate     float64       `json:"matchRate"`
	Mismatches    []VersionDiff `json:"mismatches"`

	StarsA int `json:"starsA"`
	StarsB int `json:"starsB"`
}

// VersionDiff records a single same-package version disagreement.
type VersionDiff struct {
	Name     string `json:"name"`
	VersionA string `json:"versionA"`
	VersionB string `json:"versionB"`
	PURLA    string `json:"purlA,omitempty"`
	PURLB    string `json:"purlB,omitempty"`
}

func analyzeVersions(s *Sets) Versions {
	v := Versions{}
	for _, pair := range s.Common {
		// Resolve effective versions (fall back to purl version).
		va := effectiveVersion(pair.A)
		vb := effectiveVersion(pair.B)
		if va == "" && vb == "" {
			continue
		}
		v.CommonChecked++
		if normVersion(va) == normVersion(vb) {
			v.Match++
			continue
		}
		v.Mismatch++
		v.Mismatches = append(v.Mismatches, VersionDiff{
			Name:     pair.A.Name,
			VersionA: va,
			VersionB: vb,
			PURLA:    pair.A.PURL,
			PURLB:    pair.B.PURL,
		})
	}
	v.MatchRate = pct(v.Match, v.CommonChecked)
	// Both SBOMs share the same overlap, so both earn the same version score.
	stars := coverageStarsPct(v.MatchRate)
	if v.CommonChecked == 0 {
		stars = 3 // neutral when there is no overlap to judge
	}
	v.StarsA, v.StarsB = stars, stars
	return v
}

func effectiveVersion(p *sbom.NormalizedPackage) string {
	if p.Version != "" {
		return p.Version
	}
	return sbom.PURLVersion(p.PURL)
}
