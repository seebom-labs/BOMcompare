package report

import (
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/seebom-labs/BOMcompare/pkg/compare"
	"github.com/seebom-labs/BOMcompare/pkg/sbom"
)

// updateGolden regenerates the golden files instead of asserting against them.
// Run: go test ./pkg/report -run TestGolden -update
var updateGolden = flag.Bool("update", false, "update golden report files")

// dateStamp matches the "Generated YYYY-MM-DD by" line emitted by the markdown
// renderer (time.Now()), so golden output stays stable across days.
var dateStamp = regexp.MustCompile(`Generated \d{4}-\d{2}-\d{2} by`)

func stripVolatile(s string) string {
	return dateStamp.ReplaceAllString(s, "Generated <DATE> by")
}

func loadGolden(t *testing.T, path string) *sbom.Parsed {
	t.Helper()
	p, err := sbom.Load(path)
	if err != nil {
		t.Fatalf("load %s: %v", path, err)
	}
	return p
}

// TestGolden renders every supported format for a set of representative SBOM
// pairs and compares the full output against checked-in golden files. This pins
// the end-to-end behavior of the scoring heuristics, finding classification and
// all three renderers; any intentional change must be reviewed by regenerating
// the goldens with -update.
func TestGolden(t *testing.T) {
	const fixtures = "../../testdata"
	cases := []struct {
		name   string
		a, b   string
		format Format
		golden string
	}{
		// Source vs binary (rich SPDX, context note, findings).
		{"source-vs-binary/markdown", "source.spdx.json", "binary.spdx.json", FormatMarkdown, "source-vs-binary.md.golden"},
		{"source-vs-binary/json", "source.spdx.json", "binary.spdx.json", FormatJSON, "source-vs-binary.json.golden"},
		{"source-vs-binary/summary", "source.spdx.json", "binary.spdx.json", FormatSummary, "source-vs-binary.summary.golden"},

		// Cross-standard SPDX vs CycloneDX (exercises the cross-standard note).
		{"cross-standard/markdown", "binary.spdx.json", "binary.cdx.json", FormatMarkdown, "cross-standard.md.golden"},
		{"cross-standard/json", "binary.spdx.json", "binary.cdx.json", FormatJSON, "cross-standard.json.golden"},
		{"cross-standard/summary", "binary.spdx.json", "binary.cdx.json", FormatSummary, "cross-standard.summary.golden"},

		// Version mismatch (exercises VERSION_MISMATCH rendering + gating).
		{"version-mismatch/markdown", "source-version-mismatch.spdx.json", "binary.spdx.json", FormatMarkdown, "version-mismatch.md.golden"},
		{"version-mismatch/summary", "source-version-mismatch.spdx.json", "binary.spdx.json", FormatSummary, "version-mismatch.summary.golden"},

		// SPDX 3.0 JSON-LD source SBOM vs CycloneDX XML binary SBOM.
		{"spdx3-vs-cdx-xml/markdown", "source.spdx3.json", "binary.cdx.xml", FormatMarkdown, "spdx3-vs-cdx-xml.md.golden"},
		{"spdx3-vs-cdx-xml/summary", "source.spdx3.json", "binary.cdx.xml", FormatSummary, "spdx3-vs-cdx-xml.summary.golden"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := loadGolden(t, filepath.Join(fixtures, c.a))
			b := loadGolden(t, filepath.Join(fixtures, c.b))
			r := compare.Run(a, b, compare.DefaultOptions())

			out, err := Render(r, c.format)
			if err != nil {
				t.Fatalf("render %s: %v", c.format, err)
			}
			got := stripVolatile(out)

			goldenPath := filepath.Join("testdata", c.golden)
			if *updateGolden {
				if err := os.MkdirAll("testdata", 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(goldenPath, []byte(got), 0o644); err != nil {
					t.Fatalf("write golden: %v", err)
				}
				return
			}

			want, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("read golden %s (run `go test ./pkg/report -run TestGolden -update` to create): %v", goldenPath, err)
			}
			if got != string(want) {
				t.Errorf("rendered output differs from %s.\nIf this change is intentional, regenerate with:\n  go test ./pkg/report -run TestGolden -update\n\n--- got ---\n%s", c.golden, got)
			}
		})
	}
}
