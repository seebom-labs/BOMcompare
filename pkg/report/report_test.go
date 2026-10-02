package report

import (
	"strings"
	"testing"

	"github.com/seebom-labs/BOMcompare/pkg/compare"
	"github.com/seebom-labs/BOMcompare/pkg/sbom"
)

func mustLoad(t *testing.T, path string) *sbom.Parsed {
	t.Helper()
	p, err := sbom.Load(path)
	if err != nil {
		t.Fatalf("load %s: %v", path, err)
	}
	return p
}

func report(t *testing.T) *compare.Report {
	t.Helper()
	a := mustLoad(t, "../../testdata/source.spdx.json")
	b := mustLoad(t, "../../testdata/binary.spdx.json")
	return compare.Run(a, b, compare.DefaultOptions())
}

func TestRenderMarkdownContainsSections(t *testing.T) {
	out := RenderMarkdown(report(t))
	for _, want := range []string{
		"# SBOM Comparison Report",
		"## Executive Summary",
		"## 1. Completeness",
		"## 3. License Coverage",
		"## 9. Findings Classification",
		"## 10. Summary Scorecard",
		"## Recommendations",
		"mikebom v0.1.0-alpha.47",
		"syft v1.42.3",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown output missing %q", want)
		}
	}
}

func TestRenderJSONValid(t *testing.T) {
	out, err := RenderJSON(report(t))
	if err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	if !strings.Contains(out, "\"overall\"") || !strings.Contains(out, "\"scorecard\"") {
		t.Error("JSON output missing expected top-level keys")
	}
}

func TestRenderSummaryHasScorecard(t *testing.T) {
	out := RenderSummary(report(t))
	for _, want := range []string{"Completeness", "OVERALL (weighted)", "Findings:"} {
		if !strings.Contains(out, want) {
			t.Errorf("summary output missing %q", want)
		}
	}
}

func TestRenderDispatch(t *testing.T) {
	r := report(t)
	for _, f := range []Format{FormatMarkdown, FormatJSON, FormatSummary} {
		out, err := Render(r, f)
		if err != nil {
			t.Errorf("Render(%s): %v", f, err)
		}
		if strings.TrimSpace(out) == "" {
			t.Errorf("Render(%s) produced empty output", f)
		}
	}
}
