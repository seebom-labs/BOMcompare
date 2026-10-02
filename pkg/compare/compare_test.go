package compare

import (
	"testing"

	"github.com/seebom-labs/BOMcompare/pkg/sbom"
)

// load is a test helper that parses a fixture and fails on error.
func load(t *testing.T, path string) *sbom.Parsed {
	t.Helper()
	p, err := sbom.Load(path)
	if err != nil {
		t.Fatalf("load %s: %v", path, err)
	}
	return p
}

func TestToolLabelAndContext(t *testing.T) {
	a := load(t, "../../testdata/source.spdx.json")
	b := load(t, "../../testdata/binary.spdx.json")

	if a.ToolName != "mikebom" {
		t.Errorf("source tool name = %q, want mikebom", a.ToolName)
	}
	if a.ToolLabel != "mikebom v0.1.0-alpha.47" {
		t.Errorf("source label = %q, want mikebom v0.1.0-alpha.47", a.ToolLabel)
	}
	if b.ToolName != "syft" {
		t.Errorf("binary tool name = %q, want syft", b.ToolName)
	}
	if b.ToolLabel != "syft v1.42.3" {
		t.Errorf("binary label = %q, want syft v1.42.3", b.ToolLabel)
	}
	if a.Context != "source" {
		t.Errorf("source context = %q, want source", a.Context)
	}
	if b.Context != "binary" {
		t.Errorf("binary context = %q, want binary", b.Context)
	}
}

func TestCompletenessAndCrossTypeMatch(t *testing.T) {
	a := load(t, "../../testdata/source.spdx.json")
	b := load(t, "../../testdata/binary.spdx.json")
	r := Run(a, b, DefaultOptions())

	c := r.Completeness
	if c.TotalA != 4 {
		t.Errorf("TotalA = %d, want 4", c.TotalA)
	}
	if c.TotalB != 3 {
		t.Errorf("TotalB = %d, want 3", c.TotalB)
	}
	// cobra matches exactly; demo matches across pkg:generic <-> pkg:golang.
	if c.Common != 2 {
		t.Errorf("Common = %d, want 2 (cobra + cross-type demo)", c.Common)
	}
	// Source-unique: yaml (transitive) + testify (test). stdlib is binary-unique.
	if c.OnlyACount != 2 {
		t.Errorf("OnlyACount = %d, want 2", c.OnlyACount)
	}
	if c.OnlyBCount != 1 {
		t.Errorf("OnlyBCount = %d, want 1 (stdlib)", c.OnlyBCount)
	}
	// Only testify is test-scoped; the main module must NOT be flagged test.
	if c.OnlyATestScoped != 1 {
		t.Errorf("OnlyATestScoped = %d, want 1 (testify only)", c.OnlyATestScoped)
	}
}

func TestContextNotePresent(t *testing.T) {
	a := load(t, "../../testdata/source.spdx.json")
	b := load(t, "../../testdata/binary.spdx.json")
	r := Run(a, b, DefaultOptions())
	if r.ContextNote == "" {
		t.Error("expected a source-vs-binary context note, got empty")
	}
}

func TestVersionAccuracy(t *testing.T) {
	a := load(t, "../../testdata/source.spdx.json")
	b := load(t, "../../testdata/binary.spdx.json")
	r := Run(a, b, DefaultOptions())
	if r.Versions.Mismatch != 0 {
		t.Errorf("version mismatches = %d, want 0", r.Versions.Mismatch)
	}
	if r.Versions.CommonChecked == 0 {
		t.Error("expected at least one common package version checked")
	}
}

func TestLicenseFieldPlacement(t *testing.T) {
	a := load(t, "../../testdata/source.spdx.json")
	b := load(t, "../../testdata/binary.spdx.json")
	r := Run(a, b, DefaultOptions())

	// mikebom (A) uses declared, leaves concluded NOASSERTION.
	if r.Licenses.ConcludedResolvedA != 0 {
		t.Errorf("A concluded resolved = %d, want 0", r.Licenses.ConcludedResolvedA)
	}
	if r.Licenses.DeclaredResolvedA == 0 {
		t.Error("A declared resolved = 0, want >0")
	}
	// syft (B) uses concluded, leaves declared NOASSERTION.
	if r.Licenses.DeclaredResolvedB != 0 {
		t.Errorf("B declared resolved = %d, want 0", r.Licenses.DeclaredResolvedB)
	}
	if r.Licenses.ConcludedResolvedB == 0 {
		t.Error("B concluded resolved = 0, want >0")
	}
	// Cobra: Apache-2.0 declared in A == Apache-2.0 concluded in B → identical.
	if r.Licenses.Identical == 0 {
		t.Error("expected at least one identical license expression on the overlap")
	}
}

func TestFindingsClassification(t *testing.T) {
	a := load(t, "../../testdata/source.spdx.json")
	b := load(t, "../../testdata/binary.spdx.json")
	r := Run(a, b, DefaultOptions())

	counts := CountByType(r.Findings)
	if counts[MissingComponent] == 0 {
		t.Error("expected MISSING_COMPONENT findings")
	}
	// demo main module: pkg:generic/demo vs pkg:golang/.../demo → PURL_MISMATCH.
	if counts[PurlMismatch] == 0 {
		t.Error("expected a PURL_MISMATCH finding for the main module")
	}
	// syft main module has neither concluded nor declared license → LICENSE_GAP.
	if counts[LicenseGap] == 0 {
		t.Error("expected a LICENSE_GAP finding")
	}
}

func TestSupplierAndAnnotationDelta(t *testing.T) {
	a := load(t, "../../testdata/source.spdx.json")
	b := load(t, "../../testdata/binary.spdx.json")
	r := Run(a, b, DefaultOptions())

	// mikebom populates suppliers; syft uses NOASSERTION.
	if r.Suppliers.WithSupplierA == 0 {
		t.Error("A supplier coverage = 0, want >0")
	}
	if r.Suppliers.WithSupplierB != 0 {
		t.Errorf("B supplier coverage = %d, want 0 (all NOASSERTION)", r.Suppliers.WithSupplierB)
	}
	// mikebom annotates; syft does not.
	if r.Annotations.PkgWithAnnA == 0 {
		t.Error("A package annotations = 0, want >0")
	}
	if r.Annotations.PkgWithAnnB != 0 {
		t.Errorf("B package annotations = %d, want 0", r.Annotations.PkgWithAnnB)
	}
}

func TestDependencyGraphAndDepth(t *testing.T) {
	a := load(t, "../../testdata/source.spdx.json")
	b := load(t, "../../testdata/binary.spdx.json")
	r := Run(a, b, DefaultOptions())

	// Source has a 2-level chain main->cobra->yaml plus a test edge.
	if !r.Deps.HasTestLabelingA {
		t.Error("expected test labeling in source SBOM")
	}
	if r.Deps.HasTestLabelingB {
		t.Error("did not expect test labeling in binary SBOM")
	}
	if r.Deps.MaxDepthA < 2 {
		t.Errorf("source max depth = %d, want >=2", r.Deps.MaxDepthA)
	}
}

func TestOverallScoreFavorsRicherSBOM(t *testing.T) {
	a := load(t, "../../testdata/source.spdx.json")
	b := load(t, "../../testdata/binary.spdx.json")
	r := Run(a, b, DefaultOptions())

	if r.Overall.ScoreA <= r.Overall.ScoreB {
		t.Errorf("expected source score (%.1f) > binary score (%.1f)", r.Overall.ScoreA, r.Overall.ScoreB)
	}
	if r.Overall.Winner != a.ToolLabel {
		t.Errorf("winner = %q, want %q", r.Overall.Winner, a.ToolLabel)
	}
	// Source-vs-binary: large package delta is expected, so not "significant".
	if r.Overall.Significant {
		t.Error("source-vs-binary delta should not be flagged significant for CI")
	}
}

func TestIdenticalSBOMsTie(t *testing.T) {
	a := load(t, "../../testdata/source.spdx.json")
	b := load(t, "../../testdata/source.spdx.json")
	r := Run(a, b, DefaultOptions())

	if r.Overall.Winner != "tie" {
		t.Errorf("identical SBOMs winner = %q, want tie", r.Overall.Winner)
	}
	if r.Completeness.OnlyACount != 0 || r.Completeness.OnlyBCount != 0 {
		t.Errorf("identical SBOMs should have no unique packages, got A=%d B=%d",
			r.Completeness.OnlyACount, r.Completeness.OnlyBCount)
	}
	if r.Overall.HasDiff {
		t.Error("identical SBOMs should report no differences")
	}
}

func TestVersionMismatchDetected(t *testing.T) {
	// source-version-mismatch bumps cobra to v1.9.9; the binary SBOM still has
	// cobra v1.8.0. The pair must be detected as common with a version mismatch,
	// NOT reported as two separate missing components, and must gate CI.
	a := load(t, "../../testdata/source-version-mismatch.spdx.json")
	b := load(t, "../../testdata/binary.spdx.json")
	r := Run(a, b, DefaultOptions())

	if r.Versions.Mismatch != 1 {
		t.Fatalf("version mismatches = %d, want 1", r.Versions.Mismatch)
	}
	if len(r.Versions.Mismatches) != 1 || r.Versions.Mismatches[0].Name != "github.com/spf13/cobra" {
		t.Errorf("unexpected mismatch detail: %+v", r.Versions.Mismatches)
	}
	if CountByType(r.Findings)[VersionMismatch] != 1 {
		t.Error("expected exactly one VERSION_MISMATCH finding")
	}
	// A version mismatch is always CI-significant, even across source/binary.
	if !r.Overall.Significant {
		t.Error("version mismatch should be flagged significant for CI gating")
	}
}
