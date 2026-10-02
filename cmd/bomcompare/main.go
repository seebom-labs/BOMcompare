// Command bomcompare compares two SBOMs (SPDX 2.x JSON/tag-value, SPDX 3.0
// JSON-LD, CycloneDX JSON/XML) and produces a structured quality diff report
// (markdown, JSON or summary).
//
// Exit codes:
//
//	0  success, no significant differences (or --exit-on-diff not set)
//	1  error (bad args, unreadable/invalid SBOM)
//	2  significant differences found AND --exit-on-diff set
//	3  CISA 2026 minimum elements not met AND --require-min-elements set
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"

	"github.com/seebom-labs/BOMcompare/pkg/compare"
	"github.com/seebom-labs/BOMcompare/pkg/report"
	"github.com/seebom-labs/BOMcompare/pkg/sbom"
)

// version is set at release build time via -ldflags "-X main.version=...".
// Without it, the module version from `go install ...@vX.Y.Z` is used.
var version = ""

// Exit codes.
const (
	exitOK          = 0
	exitError       = 1
	exitDiff        = 2
	exitMinElements = 3
)

func buildVersion() string {
	if version != "" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("bomcompare", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		fileA      = fs.String("a", "", "path to first SBOM (SPDX or CycloneDX; or first positional arg)")
		fileB      = fs.String("b", "", "path to second SBOM (SPDX or CycloneDX; or second positional arg)")
		format     = fs.String("format", "markdown", "output format: markdown | json | summary")
		out        = fs.String("o", "", "write report to this file instead of stdout")
		exitOnDiff = fs.Bool("exit-on-diff", false, "exit with code 2 if significant differences are found (CI gating)")
		threshold  = fs.Int("diff-threshold", 1, "minimum number of runtime-unique packages that counts as a significant diff")
		showVer    = fs.Bool("version", false, "print version and exit")
		requireMin = fs.String("require-min-elements", "", "exit with code 3 unless the given SBOM(s) meet the CISA 2026 minimum elements: a | b | both")
		skipMin    = fs.String("skip-min-elements", "", "comma-separated minimum-element IDs to ignore for --require-min-elements (e.g. hash,generation-context)")
	)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "bomcompare %s — compare two SBOMs (SPDX or CycloneDX)\n\n", buildVersion())
		fmt.Fprintf(stderr, "Usage:\n  bomcompare [flags] <sbom-a> <sbom-b>\n\n")
		fmt.Fprintf(stderr, "Supported formats (auto-detected): SPDX 2.x JSON, SPDX tag-value,\n")
		fmt.Fprintf(stderr, "SPDX 3.0 JSON-LD, CycloneDX JSON, CycloneDX XML (1.4-1.7).\n")
		fmt.Fprintf(stderr, "The two inputs may be in different formats.\n\n")
		fmt.Fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
		fmt.Fprintf(stderr, "\nExamples:\n")
		fmt.Fprintf(stderr, "  bomcompare a.spdx.json b.spdx.json\n")
		fmt.Fprintf(stderr, "  bomcompare mikebom.spdx.json syft.cdx.json   # cross-format\n")
		fmt.Fprintf(stderr, "  bomcompare --format summary a.spdx b.cdx.xml\n")
		fmt.Fprintf(stderr, "  bomcompare --format json -o report.json a.spdx.json b.cdx.json\n")
		fmt.Fprintf(stderr, "  bomcompare --exit-on-diff old.spdx.json new.spdx.json   # CI gate\n")
		fmt.Fprintf(stderr, "  bomcompare --require-min-elements b --skip-min-elements hash old.spdx.json new.cdx.json\n")
		fmt.Fprintf(stderr, "\nMinimum-element IDs: %s\n", strings.Join(compare.MinElementIDs(), ", "))
		fmt.Fprintf(stderr, "\nExit codes: 0 ok, 1 error, 2 significant differences (--exit-on-diff),\n")
		fmt.Fprintf(stderr, "3 minimum elements not met (--require-min-elements).\n")
	}

	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *showVer {
		fmt.Fprintf(stdout, "bomcompare %s\n", buildVersion())
		return 0
	}

	// Resolve inputs: flags take precedence, else positional args.
	pathA, pathB := *fileA, *fileB
	pos := fs.Args()
	if pathA == "" && len(pos) > 0 {
		pathA = pos[0]
	}
	if pathB == "" && len(pos) > 1 {
		pathB = pos[1]
	}
	if pathA == "" || pathB == "" {
		fmt.Fprintln(stderr, "error: two SBOM files are required")
		fs.Usage()
		return 1
	}

	f, err := parseFormat(*format)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	gateSides, err := parseGateSides(*requireMin)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	skip, err := parseSkipIDs(*skipMin)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	a, err := sbom.Load(pathA)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	b, err := sbom.Load(pathB)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	opts := compare.DefaultOptions()
	if *threshold >= 0 {
		opts.SignificantThreshold = *threshold
	}
	rep := compare.Run(a, b, opts)

	rendered, err := report.Render(rep, f)
	if err != nil {
		fmt.Fprintf(stderr, "error: rendering report: %v\n", err)
		return 1
	}

	if *out != "" {
		if err := os.WriteFile(*out, []byte(rendered), 0o644); err != nil {
			fmt.Fprintf(stderr, "error: writing %s: %v\n", *out, err)
			return 1
		}
		fmt.Fprintf(stderr, "report written to %s\n", *out)
	} else {
		fmt.Fprintln(stdout, rendered)
	}

	if *exitOnDiff && rep.Overall.Significant {
		return exitDiff
	}
	if !minElementsMet(rep, gateSides, skip, stderr) {
		return exitMinElements
	}
	return exitOK
}

// parseGateSides maps --require-min-elements to the sides to check.
func parseGateSides(s string) ([]string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "none":
		return nil, nil
	case "a":
		return []string{"A"}, nil
	case "b":
		return []string{"B"}, nil
	case "both", "ab":
		return []string{"A", "B"}, nil
	default:
		return nil, fmt.Errorf("unknown --require-min-elements value %q (use a, b or both)", s)
	}
}

// parseSkipIDs validates --skip-min-elements against the known element IDs.
func parseSkipIDs(s string) (map[string]bool, error) {
	known := map[string]bool{}
	for _, id := range compare.MinElementIDs() {
		known[id] = true
	}
	skip := map[string]bool{}
	for _, id := range strings.Split(s, ",") {
		id = strings.ToLower(strings.TrimSpace(id))
		if id == "" {
			continue
		}
		if !known[id] {
			return nil, fmt.Errorf("unknown minimum-element ID %q (valid: %s)", id, strings.Join(compare.MinElementIDs(), ", "))
		}
		skip[id] = true
	}
	return skip, nil
}

// minElementsMet reports whether every gated side meets the CISA minimum
// elements, printing the failing elements to stderr.
func minElementsMet(rep *compare.Report, sides []string, skip map[string]bool, stderr io.Writer) bool {
	ok := true
	for _, side := range sides {
		failing := rep.MinimumElements.Failing(side, skip)
		if len(failing) == 0 {
			continue
		}
		ok = false
		label := rep.LabelA
		if side == "B" {
			label = rep.LabelB
		}
		ids := make([]string, len(failing))
		for i, r := range failing {
			ids[i] = r.ID
		}
		fmt.Fprintf(stderr, "minimum elements not met by %s (%s): %s\n", side, label, strings.Join(ids, ", "))
	}
	return ok
}

func parseFormat(s string) (report.Format, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "markdown", "md":
		return report.FormatMarkdown, nil
	case "json":
		return report.FormatJSON, nil
	case "summary", "table":
		return report.FormatSummary, nil
	default:
		return "", fmt.Errorf("unknown format %q (use markdown, json or summary)", s)
	}
}
