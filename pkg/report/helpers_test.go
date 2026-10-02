package report

import (
	"testing"
	"unicode/utf8"

	"github.com/seebom-labs/BOMcompare/pkg/compare"
	"github.com/seebom-labs/BOMcompare/pkg/sbom"
)

func TestTruncRuneSafe(t *testing.T) {
	cases := []struct {
		s    string
		n    int
		want string
	}{
		{"hello", 10, "hello"},
		{"hello", 5, "hello"},
		{"hello", 3, "he…"},
		{"hello", 1, "h"},
		{"x", 0, ""},
		{"héllo", 3, "hé…"}, // must not split the multibyte 'é'
	}
	for _, c := range cases {
		got := trunc(c.s, c.n)
		if got != c.want {
			t.Errorf("trunc(%q,%d) = %q, want %q", c.s, c.n, got, c.want)
		}
		if !utf8.ValidString(got) {
			t.Errorf("trunc(%q,%d) produced invalid UTF-8: %q", c.s, c.n, got)
		}
	}
}

func TestStars(t *testing.T) {
	if got := stars(3); utf8.RuneCountInString(got) != 3 {
		t.Errorf("stars(3) has %d glyphs, want 3", utf8.RuneCountInString(got))
	}
	if got := stars(7); utf8.RuneCountInString(got) != 5 {
		t.Errorf("stars(7) clamps to 5, got %d", utf8.RuneCountInString(got))
	}
	if got := stars(-1); got != "" {
		t.Errorf("stars(-1) = %q, want empty", got)
	}
}

func TestWinnerOf(t *testing.T) {
	if got := winnerOf(3, 2, "A", "B"); got != "A" {
		t.Errorf("winnerOf(3,2) = %q, want A", got)
	}
	if got := winnerOf(2, 3, "A", "B"); got != "B" {
		t.Errorf("winnerOf(2,3) = %q, want B", got)
	}
	if got := winnerOf(2, 2, "A", "B"); got != "—" {
		t.Errorf("winnerOf(2,2) = %q, want —", got)
	}
}

func TestDeltaSuffix(t *testing.T) {
	if got := deltaSuffix(4, 0); got != " (+4)" {
		t.Errorf("deltaSuffix(4,0) = %q, want ' (+4)'", got)
	}
	if got := deltaSuffix(8, 4); got != " (+100%)" {
		t.Errorf("deltaSuffix(8,4) = %q, want ' (+100%%)'", got)
	}
}

func TestMatchStr(t *testing.T) {
	if got := matchStr(0, 0); got != "n/a" {
		t.Errorf("matchStr(0,0) = %q, want n/a", got)
	}
	if got := matchStr(100, 5); got != "✅ 100% match" {
		t.Errorf("matchStr(100,5) = %q", got)
	}
	if got := matchStr(50, 5); got != "50.0% match" {
		t.Errorf("matchStr(50,5) = %q", got)
	}
}

func TestCrossStandard(t *testing.T) {
	if !crossStandard(sbom.FormatSPDXJSON, sbom.FormatCycloneDXJSON) {
		t.Error("SPDX vs CycloneDX should be cross-standard")
	}
	if crossStandard(sbom.FormatSPDXJSON, sbom.FormatSPDXTagValue) {
		t.Error("two SPDX serializations are the same standard")
	}
	if crossStandard("unknown", sbom.FormatSPDXJSON) {
		t.Error("unknown format should not count as cross-standard")
	}
}

func TestMergedTypesOrdering(t *testing.T) {
	a := []compare.TypeCount{{Type: "DEPENDS_ON", Count: 2}, {Type: "DESCRIBES", Count: 1}}
	b := []compare.TypeCount{{Type: "DEPENDS_ON", Count: 3}}
	got := mergedTypes(a, b)
	if len(got) != 2 || got[0] != "DEPENDS_ON" {
		t.Errorf("mergedTypes = %v, want DEPENDS_ON first", got)
	}
	if countOf(a, "DEPENDS_ON") != 2 || countOf(a, "MISSING") != 0 {
		t.Error("countOf returned wrong totals")
	}
}

func TestBiggerFloatTieWithinEpsilon(t *testing.T) {
	r := &compare.Report{LabelA: "A", LabelB: "B"}
	if got := biggerFloat(4.0, 4.02, r); got != "Tie" {
		t.Errorf("biggerFloat within epsilon = %q, want Tie", got)
	}
	if got := biggerFloat(4.5, 4.0, r); got != "A" {
		t.Errorf("biggerFloat(4.5,4.0) = %q, want A", got)
	}
}
