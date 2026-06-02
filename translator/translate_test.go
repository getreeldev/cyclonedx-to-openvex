package translator

import (
	"os"
	"strings"
	"testing"

	"github.com/getreeldev/cyclonedx-to-openvex/openvex"
)

func loadSample(t *testing.T) (openvex.Document, Report) {
	t.Helper()
	f, err := os.Open("../testdata/sample.cdx.json")
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()
	doc, rep, err := FromCycloneDX(f, Options{})
	if err != nil {
		t.Fatalf("FromCycloneDX: %v", err)
	}
	return doc, rep
}

func find(doc openvex.Document, cve string) *openvex.Statement {
	for i := range doc.Statements {
		if doc.Statements[i].Vulnerability.Name == cve {
			return &doc.Statements[i]
		}
	}
	return nil
}

func TestFromCycloneDX_Default(t *testing.T) {
	doc, rep := loadSample(t)

	if doc.Context != openvex.ContextURL {
		t.Errorf("@context: got %q", doc.Context)
	}
	if doc.Timestamp != "2026-05-08T12:05:36Z" {
		t.Errorf("timestamp should come from metadata: got %q", doc.Timestamp)
	}

	// 5 analysed; 3 emit, 2 skip (false_positive w/o justification; not_affected w/o product).
	if rep.Considered != 5 || rep.StatementsEmitted != 3 || rep.Skipped != 2 {
		t.Errorf("report counts: considered=%d emitted=%d skipped=%d (want 5/3/2)", rep.Considered, rep.StatementsEmitted, rep.Skipped)
	}
	if rep.Lossy != 1 || rep.Contested != 0 {
		t.Errorf("fidelity counts: lossy=%d contested=%d (want 1/0)", rep.Lossy, rep.Contested)
	}

	// Lossy justification mapping, with provenance in status_notes.
	s := find(doc, "CVE-2022-42898")
	if s == nil {
		t.Fatal("CVE-2022-42898 not emitted")
	}
	if s.Status != "not_affected" || s.Justification != "vulnerable_code_cannot_be_controlled_by_adversary" {
		t.Errorf("42898 mapping: status=%q justification=%q", s.Status, s.Justification)
	}
	if s.Products[0].ID != "pkg:deb/debian/libk5crypto3@1.18.3-6%2Bdeb11u2?arch=amd64&distro=debian-11.5" {
		t.Errorf("42898 product not resolved from bom-ref: %q", s.Products[0].ID)
	}
	for _, want := range []string{"converted_from=cyclonedx-vex", "original_justification=requires_environment", "fidelity=lossy"} {
		if !strings.Contains(s.StatusNotes, want) {
			t.Errorf("42898 status_notes missing %q: got %q", want, s.StatusNotes)
		}
	}

	// Exact justification mapping with a direct PURL ref.
	if s := find(doc, "CVE-2023-0001"); s == nil || s.Justification != "vulnerable_code_not_in_execute_path" {
		t.Errorf("0001 exact justification mapping wrong: %+v", s)
	}
	// resolved -> fixed, no justification needed.
	if s := find(doc, "CVE-2023-0002"); s == nil || s.Status != "fixed" || s.Justification != "" {
		t.Errorf("0002 resolved->fixed wrong: %+v", s)
	}
	// false_positive without justification can't be valid not_affected -> skipped.
	if s := find(doc, "CVE-2023-0003"); s != nil {
		t.Error("0003 (false_positive, no justification) should have been skipped")
	}
	// not_affected with no affects -> no product -> skipped.
	if s := find(doc, "CVE-2023-0004"); s != nil {
		t.Error("0004 (no product) should have been skipped")
	}
}

func TestFromCycloneDX_RejectLossy(t *testing.T) {
	f, err := os.Open("../testdata/sample.cdx.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	doc, rep, err := FromCycloneDX(f, Options{RejectLossy: true})
	if err != nil {
		t.Fatal(err)
	}
	// The lossy 42898 is now skipped; only the two exact mappings emit.
	if rep.StatementsEmitted != 2 || rep.Lossy != 0 {
		t.Errorf("reject-lossy: emitted=%d lossy=%d (want 2/0)", rep.StatementsEmitted, rep.Lossy)
	}
	if find(doc, "CVE-2022-42898") != nil {
		t.Error("lossy 42898 should be rejected under RejectLossy")
	}
}
