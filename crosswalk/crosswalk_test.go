package crosswalk

import (
	"os"
	"testing"
)

// TestYAMLInSync guards the source-of-truth invariant: the committed
// crosswalk.yaml must equal MarshalYAML() output. If this fails, regenerate:
//
//	go run ./cmd/cyclonedx-to-openvex -dump-crosswalk > crosswalk/crosswalk.yaml
func TestYAMLInSync(t *testing.T) {
	committed, err := os.ReadFile("crosswalk.yaml")
	if err != nil {
		t.Fatalf("read crosswalk.yaml: %v", err)
	}
	if got := MarshalYAML(); string(got) != string(committed) {
		t.Fatalf("crosswalk.yaml is stale — regenerate with `go run ./cmd/cyclonedx-to-openvex -dump-crosswalk > crosswalk/crosswalk.yaml`")
	}
}

func TestLookups(t *testing.T) {
	// A few anchor points from #609.
	if e, ok := LookupJustification("code_not_reachable"); !ok || e.OpenVEX != "vulnerable_code_not_in_execute_path" || e.Fidelity != Exact {
		t.Errorf("code_not_reachable: got %+v ok=%v", e, ok)
	}
	if e, ok := LookupJustification("requires_environment"); !ok || e.OpenVEX != "vulnerable_code_cannot_be_controlled_by_adversary" || e.Fidelity != Lossy || !e.ReverseAmbiguous {
		t.Errorf("requires_environment: got %+v ok=%v", e, ok)
	}
	if e, ok := LookupStatus("exploitable"); !ok || e.OpenVEX != "affected" {
		t.Errorf("exploitable: got %+v ok=%v", e, ok)
	}
	if _, ok := LookupJustification("not_a_real_value"); ok {
		t.Error("unknown justification should not resolve")
	}
}

// Every justification target must be a value OpenVEX actually defines — a typo
// here would emit invalid OpenVEX. (Status targets likewise.)
func TestTargetsAreValidOpenVEX(t *testing.T) {
	validJust := map[string]bool{
		"component_not_present": true, "vulnerable_code_not_present": true,
		"vulnerable_code_not_in_execute_path": true, "inline_mitigations_already_exist": true,
		"vulnerable_code_cannot_be_controlled_by_adversary": true,
	}
	validStatus := map[string]bool{
		"not_affected": true, "affected": true, "fixed": true, "under_investigation": true,
	}
	for _, e := range Entries {
		switch e.Kind {
		case KindJustification:
			if !validJust[e.OpenVEX] {
				t.Errorf("justification target %q is not a valid OpenVEX justification", e.OpenVEX)
			}
		case KindStatus:
			if !validStatus[e.OpenVEX] {
				t.Errorf("status target %q is not a valid OpenVEX status", e.OpenVEX)
			}
		}
	}
}
