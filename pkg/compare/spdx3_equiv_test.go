package compare

import (
	"reflect"
	"strings"
	"testing"

	"github.com/seebom-labs/BOMcompare/pkg/sbom"
)

// TestSPDX3MatchesSPDX2Analysis verifies that the SPDX 3 JSON-LD fixture,
// which encodes the same content as source.spdx.json, yields the same
// analysis against the binary SBOM.
func TestSPDX3MatchesSPDX2Analysis(t *testing.T) {
	b := load(t, "../../testdata/binary.spdx.json")
	r2 := Run(load(t, "../../testdata/source.spdx.json"), b, DefaultOptions())
	r3 := Run(load(t, "../../testdata/source.spdx3.json"), b, DefaultOptions())

	if r3.FormatA != sbom.FormatSPDX3JSONLD {
		t.Fatalf("FormatA = %q, want %q", r3.FormatA, sbom.FormatSPDX3JSONLD)
	}
	if r2.LabelA != r3.LabelA || r2.ContextA != r3.ContextA {
		t.Errorf("label/context differ: spdx2=(%q,%q) spdx3=(%q,%q)", r2.LabelA, r2.ContextA, r3.LabelA, r3.ContextA)
	}
	if !reflect.DeepEqual(r2.Completeness, r3.Completeness) {
		t.Errorf("completeness differs:\nspdx2=%+v\nspdx3=%+v", r2.Completeness, r3.Completeness)
	}
	if !reflect.DeepEqual(r2.Scorecard, r3.Scorecard) {
		t.Errorf("scorecard differs:\nspdx2=%+v\nspdx3=%+v", r2.Scorecard, r3.Scorecard)
	}
	if !reflect.DeepEqual(r2.Findings, r3.Findings) {
		t.Errorf("findings differ:\nspdx2=%+v\nspdx3=%+v", r2.Findings, r3.Findings)
	}
	if r2.Overall != r3.Overall {
		t.Errorf("overall differs: spdx2=%+v spdx3=%+v", r2.Overall, r3.Overall)
	}
}

func TestIdentityCompatible(t *testing.T) {
	type id struct{ purl, typ, path string }
	mk := func(i id) *sbom.NormalizedPackage {
		return &sbom.NormalizedPackage{PURL: i.purl, PURLType: i.typ, ModulePath: i.path}
	}
	cases := []struct {
		a, b id
		want bool
	}{
		{id{"pkg:golang/github.com/pkg/errors@v0.9.1", "golang", "github.com/pkg/errors"},
			id{"pkg:golang/github.com/go-errors/errors@v1.0.0", "golang", "github.com/go-errors/errors"}, false},
		{id{"pkg:npm/debug@4.3.4", "npm", "debug"}, id{"pkg:pypi/debug@1.0.0", "pypi", "debug"}, false},
		{id{"pkg:golang/github.com/spf13/cobra@v1.8.0", "golang", "github.com/spf13/cobra"},
			id{"pkg:golang/github.com/spf13/cobra@v1.8.0", "golang", "github.com/spf13/cobra"}, true},
		{id{"pkg:deb/debian/openssl@3.0", "deb", "debian/openssl"}, id{"pkg:deb/ubuntu/openssl@3.0", "deb", "ubuntu/openssl"}, true},
		{id{"pkg:generic/demo@1.0", "generic", "demo"}, id{"pkg:golang/example.com/demo@1.0", "golang", "example.com/demo"}, true},
		{id{"", "", "debug"}, id{"pkg:npm/debug@4.3.4", "npm", "debug"}, true},
	}
	for _, c := range cases {
		if got := identityCompatible(mk(c.a), mk(c.b)); got != c.want {
			t.Errorf("identityCompatible(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// TestMissingComponentNamesPresentSide checks that a MISSING_COMPONENT finding
// attributes the package to the SBOM that actually contains it.
func TestMissingComponentNamesPresentSide(t *testing.T) {
	a := load(t, "../../testdata/source.spdx.json")
	b := load(t, "../../testdata/binary.spdx.json")
	r := Run(a, b, DefaultOptions())
	seen := 0
	for _, f := range r.Findings {
		if f.Type != MissingComponent {
			continue
		}
		seen++
		present := r.LabelA
		if f.Side == "A" {
			present = r.LabelB
		}
		if !strings.Contains(f.Detail, "present in "+present) {
			t.Errorf("%s missing from %s: detail %q should name %q", f.Package, f.Side, f.Detail, present)
		}
	}
	if seen == 0 {
		t.Fatal("expected MISSING_COMPONENT findings")
	}
}
