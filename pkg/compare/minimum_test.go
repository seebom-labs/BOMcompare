package compare

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/seebom-labs/BOMcompare/pkg/sbom"
)

func minRow(t *testing.T, m MinimumElements, element string) MinElementRow {
	t.Helper()
	for _, r := range m.Rows {
		if r.Element == element {
			return r
		}
	}
	t.Fatalf("minimum element %q not found", element)
	return MinElementRow{}
}

func TestMinimumElementsSPDX(t *testing.T) {
	r := Run(load(t, "../../testdata/source.spdx.json"), load(t, "../../testdata/source.spdx3.json"), DefaultOptions())
	m := r.MinimumElements
	if m.Total != len(minDocChecks)+len(minComponentChecks) {
		t.Errorf("Total = %d", m.Total)
	}

	gc := minRow(t, m, "Generation Context")
	// SPDX 2 only has package-level tier annotations; SPDX 3 declares sbomType.
	if gc.A.Status != MinFail || gc.A.Value != "not declared (inferred: source)" {
		t.Errorf("SPDX 2 generation context = %+v", gc.A)
	}
	if gc.B.Status != MinPass || gc.B.Value != "source" {
		t.Errorf("SPDX 3 generation context = %+v", gc.B)
	}

	for _, el := range []string{"SBOM Author", "Data Format Name", "Data Format Version", "Timestamp", "Tool Name", "Tool Version", "SBOM Version"} {
		row := minRow(t, m, el)
		if row.A.Status != MinPass || row.B.Status != MinPass {
			t.Errorf("%s: A=%+v B=%+v, want pass", el, row.A, row.B)
		}
	}
	if v := minRow(t, m, "Data Format Version").B.Value; v != "SPDX-3.0.1" {
		t.Errorf("SPDX 3 format version = %q", v)
	}
	if s := minRow(t, m, "Author Signature").A.Status; s != MinUnverified {
		t.Errorf("signature status = %q, want unverified", s)
	}

	hash := minRow(t, m, "Component Hash (value + algorithm)")
	if hash.A.Status != MinFail || hash.A.Present != 3 || hash.A.Total != 4 {
		t.Errorf("hash = %+v, want fail 3/4", hash.A)
	}
	if d := minRow(t, m, "Dependency Relationship"); d.A.Status != MinPass || d.B.Status != MinPass {
		t.Errorf("dependency relationship: A=%+v B=%+v", d.A, d.B)
	}
	if m.PassedA != m.PassedB-1 {
		t.Errorf("PassedA=%d PassedB=%d, want SPDX 3 to pass exactly one more (generation context)", m.PassedA, m.PassedB)
	}
}

func TestMinimumElementsCycloneDX(t *testing.T) {
	const doc = `{
  "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 3,
  "serialNumber": "urn:uuid:11111111-2222-3333-4444-555555555555",
  "metadata": {
    "timestamp": "2026-08-01T00:00:00Z",
    "lifecycles": [{"phase": "build"}],
    "authors": [{"name": "Jane Doe"}],
    "tools": {"components": [{"type": "application", "name": "builder", "version": "2.0"}]},
    "component": {"bom-ref": "app", "type": "application", "name": "app", "version": "1.0",
      "purl": "pkg:golang/example.com/app@1.0", "supplier": {"name": "Example Inc"},
      "hashes": [{"alg": "SHA-256", "content": "aa"}],
      "licenses": [{"license": {"id": "MIT"}}]}
  },
  "components": [
    {"bom-ref": "lib", "type": "library", "name": "lib", "version": "2.0",
     "purl": "pkg:golang/example.com/lib@2.0", "manufacturer": {"name": "Lib Org"},
     "hashes": [{"alg": "SHA-256", "content": "bb"}],
     "licenses": [{"license": {"id": "Apache-2.0"}}]},
    {"bom-ref": "orphan", "type": "library", "name": "orphan"}
  ],
  "dependencies": [{"ref": "app", "dependsOn": ["lib"]}, {"ref": "lib"}],
  "signature": {"algorithm": "ES256", "value": "abc"}
}`
	path := filepath.Join(t.TempDir(), "bom.cdx.json")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := sbom.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	m := analyzeMinimumElements(p, p)

	want := map[string]string{
		"SBOM Author":                        MinPass,
		"Author Signature":                   MinPass,
		"Generation Context":                 MinPass,
		"Tool Version":                       MinPass,
		"SBOM Version":                       MinPass,
		"Component Producer":                 MinFail, // orphan has none
		"Component Version":                  MinFail,
		"Software Identifiers":               MinFail,
		"Component Hash (value + algorithm)": MinFail,
		"License":                            MinFail,
		"Dependency Relationship":            MinFail, // orphan is not in the graph
		"Component Name":                     MinPass,
	}
	for el, status := range want {
		if got := minRow(t, m, el).A; got.Status != status {
			t.Errorf("%s = %+v, want %s", el, got, status)
		}
	}
	if d := minRow(t, m, "Dependency Relationship").A; d.Present != 2 || d.Total != 3 {
		t.Errorf("dependency coverage = %d/%d, want 2/3 (lib declared via empty dependsOn)", d.Present, d.Total)
	}
	if v := minRow(t, m, "Generation Context").A.Value; v != "build" {
		t.Errorf("generation context = %q, want build", v)
	}
}

func TestMinimumElementsDeclaredUnknownWarns(t *testing.T) {
	p := &sbom.Parsed{Format: sbom.FormatSPDXJSON, Packages: []sbom.NormalizedPackage{
		{SPDXID: "a", Name: "a", LicenseConcluded: sbom.NoAssertion, LicenseDeclared: sbom.NoAssertion},
		{SPDXID: "b", Name: "b", LicenseDeclared: "MIT"},
	}}
	var lic componentCheck
	for _, c := range minComponentChecks {
		if c.element == "License" {
			lic = c
		}
	}
	got := componentCoverage(p, nil, lic)
	if got.Status != MinWarn || got.Present != 1 || got.Unknown != 1 {
		t.Errorf("license coverage = %+v, want warn 1 present + 1 unknown", got)
	}
	// CycloneDX has no NOASSERTION token; the normalized placeholder is a gap.
	p.Format = sbom.FormatCycloneDXJSON
	if got := componentCoverage(p, nil, lic); got.Status != MinFail || got.Unknown != 0 {
		t.Errorf("CycloneDX license coverage = %+v, want fail without unknowns", got)
	}
}

func TestMinElementIDsUniqueAndInReport(t *testing.T) {
	ids := MinElementIDs()
	seen := map[string]bool{}
	for _, id := range ids {
		if id == "" || seen[id] {
			t.Errorf("empty or duplicate ID %q", id)
		}
		seen[id] = true
	}
	r := Run(load(t, "../../testdata/source.spdx.json"), load(t, "../../testdata/binary.spdx.json"), DefaultOptions())
	if len(r.MinimumElements.Rows) != len(ids) {
		t.Fatalf("rows = %d, ids = %d", len(r.MinimumElements.Rows), len(ids))
	}
	for i, row := range r.MinimumElements.Rows {
		if row.ID != ids[i] {
			t.Errorf("row %d ID = %q, want %q", i, row.ID, ids[i])
		}
	}
}

func TestMinimumElementsFailing(t *testing.T) {
	m := MinimumElements{Rows: []MinElementRow{
		{ID: "hash", A: MinElementResult{Status: MinFail}, B: MinElementResult{Status: MinPass}},
		{ID: "license", A: MinElementResult{Status: MinWarn}, B: MinElementResult{Status: MinFail}},
		{ID: "signature", A: MinElementResult{Status: MinUnverified}, B: MinElementResult{Status: MinUnverified}},
	}}
	ids := func(rows []MinElementRow) []string {
		var out []string
		for _, r := range rows {
			out = append(out, r.ID)
		}
		return out
	}
	if got := ids(m.Failing("A", nil)); len(got) != 1 || got[0] != "hash" {
		t.Errorf("Failing(A) = %v, want [hash] (warn/unverified must not fail)", got)
	}
	if got := ids(m.Failing("B", nil)); len(got) != 1 || got[0] != "license" {
		t.Errorf("Failing(B) = %v, want [license]", got)
	}
	if got := m.Failing("A", map[string]bool{"hash": true}); len(got) != 0 {
		t.Errorf("Failing(A, skip hash) = %v, want none", ids(got))
	}
}
