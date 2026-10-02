package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/seebom-labs/BOMcompare/pkg/report"
)

func TestParseFormat(t *testing.T) {
	cases := []struct {
		in   string
		want report.Format
		err  bool
	}{
		{"", report.FormatMarkdown, false},
		{"markdown", report.FormatMarkdown, false},
		{"MD", report.FormatMarkdown, false},
		{"json", report.FormatJSON, false},
		{" Summary ", report.FormatSummary, false},
		{"table", report.FormatSummary, false},
		{"xml", "", true},
	}
	for _, c := range cases {
		got, err := parseFormat(c.in)
		if c.err {
			if err == nil {
				t.Errorf("parseFormat(%q) expected error", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseFormat(%q) unexpected error: %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("parseFormat(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestRunVersion(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--version"}, &out, &errb); code != 0 {
		t.Fatalf("--version exit = %d, want 0", code)
	}
	if !strings.Contains(out.String(), "bomcompare") {
		t.Errorf("--version stdout = %q, want a version line", out.String())
	}
}

func TestRunMissingArgs(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(nil, &out, &errb); code != 1 {
		t.Fatalf("no args exit = %d, want 1", code)
	}
	if !strings.Contains(errb.String(), "two SBOM files are required") {
		t.Errorf("expected a usage error, got %q", errb.String())
	}
}

func TestRunBadFormat(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"--format", "xml", "testdata/a", "testdata/b"}, &out, &errb)
	if code != 1 {
		t.Fatalf("bad format exit = %d, want 1", code)
	}
}

func TestRunHappyPath(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{
		"--format", "summary",
		"../../testdata/source.spdx.json", // path normalization still resolves
		"../../testdata/binary.spdx.json",
	}, &out, &errb)
	if code != 0 {
		t.Fatalf("happy path exit = %d, want 0 (stderr=%q)", code, errb.String())
	}
	if !strings.Contains(out.String(), "OVERALL (weighted)") {
		t.Errorf("summary output missing scorecard: %q", out.String())
	}
}

func TestRunExitOnDiff(t *testing.T) {
	var out, errb bytes.Buffer
	// A version mismatch is always significant → exit code 2 when gating.
	code := run([]string{
		"--exit-on-diff",
		"../../testdata/source-version-mismatch.spdx.json",
		"../../testdata/binary.spdx.json",
	}, &out, &errb)
	if code != 2 {
		t.Fatalf("--exit-on-diff with a version mismatch exit = %d, want 2", code)
	}
}

func TestRunRequireMinElements(t *testing.T) {
	src, bin := "../../testdata/source.spdx3.json", "../../testdata/binary.spdx.json"
	cases := []struct {
		name     string
		args     []string
		wantCode int
		wantErr  string
	}{
		{"off by default", nil, exitOK, ""},
		{"a fails on hash", []string{"--require-min-elements", "a"}, exitMinElements, "not met by A (mikebom v0.1.0-alpha.47): hash"},
		{"both reports each side", []string{"--require-min-elements", "both"}, exitMinElements, "not met by B (syft v1.42.3): generation-context, hash"},
		{"skip makes a pass", []string{"--require-min-elements", "a", "--skip-min-elements", " Hash "}, exitOK, ""},
		{"b still fails with hash skipped", []string{"--require-min-elements", "b", "--skip-min-elements", "hash"}, exitMinElements, "generation-context"},
		{"unknown side", []string{"--require-min-elements", "c"}, exitError, "use a, b or both"},
		{"unknown id", []string{"--require-min-elements", "a", "--skip-min-elements", "nope"}, exitError, `unknown minimum-element ID "nope"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			args := append(append([]string{"--format", "summary"}, c.args...), src, bin)
			if code := run(args, &out, &errb); code != c.wantCode {
				t.Fatalf("exit = %d, want %d (stderr=%q)", code, c.wantCode, errb.String())
			}
			if c.wantErr != "" && !strings.Contains(errb.String(), c.wantErr) {
				t.Errorf("stderr = %q, want it to contain %q", errb.String(), c.wantErr)
			}
		})
	}
}

func TestExitOnDiffTakesPrecedence(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{
		"--format", "summary", "--exit-on-diff", "--require-min-elements", "both",
		"../../testdata/source-version-mismatch.spdx.json", "../../testdata/binary.spdx.json",
	}, &out, &errb)
	if code != exitDiff {
		t.Fatalf("exit = %d, want %d", code, exitDiff)
	}
}

func TestBuildVersion(t *testing.T) {
	old := version
	defer func() { version = old }()
	version = "1.2.3"
	if got := buildVersion(); got != "1.2.3" {
		t.Errorf("buildVersion() = %q, want ldflags value", got)
	}
	version = ""
	if got := buildVersion(); got == "" {
		t.Error("buildVersion() must never be empty")
	}
}
