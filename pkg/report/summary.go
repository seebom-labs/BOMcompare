package report

import (
	"fmt"
	"strings"

	"github.com/seebom-labs/BOMcompare/pkg/compare"
)

// RenderSummary produces just the scorecard table plus the composite score line.
func RenderSummary(r *compare.Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "SBOM Comparison Summary\n")
	fmt.Fprintf(&b, "A: %s   [%s] (%s)\n", r.LabelA, r.FormatA, r.ContextA)
	fmt.Fprintf(&b, "B: %s   [%s] (%s)\n\n", r.LabelB, r.FormatB, r.ContextB)

	// Column widths.
	catW := len("Category")
	for _, row := range r.Scorecard {
		if len(row.Category) > catW {
			catW = len(row.Category)
		}
	}
	fmt.Fprintf(&b, "%-*s  %-7s  %-5s  %-5s  %s\n", catW, "Category", "Weight", "A", "B", "Winner")
	fmt.Fprintf(&b, "%s\n", strings.Repeat("-", catW+34))
	for _, row := range r.Scorecard {
		fmt.Fprintf(&b, "%-*s  %-7s  %-5s  %-5s  %s\n",
			catW, row.Category, trunc(row.Weight, 7),
			starsAscii(row.StarsA), starsAscii(row.StarsB),
			winnerOf(row.StarsA, row.StarsB, "A", "B"))
	}
	fmt.Fprintf(&b, "%s\n", strings.Repeat("-", catW+34))
	fmt.Fprintf(&b, "%-*s  %-7s  %-5.1f  %-5.1f  %s\n",
		catW, "OVERALL (weighted)", "", r.Overall.ScoreA, r.Overall.ScoreB,
		overallWinner(r))

	fmt.Fprintf(&b, "\nFindings: ")
	counts := compare.CountByType(r.Findings)
	if len(counts) == 0 {
		fmt.Fprintf(&b, "none\n")
	} else {
		var parts []string
		for _, t := range findingOrder {
			if n := counts[t]; n > 0 {
				parts = append(parts, fmt.Sprintf("%s=%d", t, n))
			}
		}
		fmt.Fprintf(&b, "%s\n", strings.Join(parts, "  "))
	}
	m := r.MinimumElements
	fmt.Fprintf(&b, "CISA 2026 minimum elements met: A %d/%d   B %d/%d\n", m.PassedA, m.Total, m.PassedB, m.Total)
	fmt.Fprintf(&b, "Differences: %v   Significant: %v\n", r.Overall.HasDiff, r.Overall.Significant)
	return b.String()
}

// starsAscii renders stars as N/5 for fixed-width terminal tables.
func starsAscii(n int) string {
	return fmt.Sprintf("%d/5", n)
}

func overallWinner(r *compare.Report) string {
	switch r.Overall.Winner {
	case r.LabelA:
		return "A"
	case r.LabelB:
		return "B"
	default:
		return "tie"
	}
}

var findingOrder = []compare.FindingType{
	compare.MissingComponent,
	compare.PhantomComponent,
	compare.VersionMismatch,
	compare.PurlMismatch,
	compare.FalsePositive,
	compare.LicenseGap,
}
