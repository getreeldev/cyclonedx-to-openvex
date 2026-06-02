// Package crosswalk holds the CycloneDX <-> OpenVEX vocabulary mapping: how
// CycloneDX VEX analysis.state / analysis.justification values map onto the
// CISA "Minimum Requirements for VEX" labels, which OpenVEX implements verbatim.
//
// The Go map (Entries) is the source of truth. crosswalk.yaml — the canonical,
// publishable artifact (the one intended for CycloneDX/specification#609) — is
// generated from it by MarshalYAML and kept in sync by a parity test, so there
// is no YAML parser and no third-party dependency anywhere in the module.
//
// Primary direction is CycloneDX -> OpenVEX: deterministic (each source value
// resolves to exactly one target), though lossy where CycloneDX carries more
// granularity than CISA's five justifications. The reverse (OpenVEX ->
// CycloneDX) is NOT 1:1 — a single OpenVEX value can originate from several
// CycloneDX values — so those entries are flagged ReverseAmbiguous and must
// not be auto-applied in reverse without a human choice.
package crosswalk

import (
	"fmt"
	"strings"
)

// Spec/version metadata. Bumped when the underlying enums or a contested cell
// changes; the Specs pins let a consumer see at a glance what this revision
// was authored against.
const (
	Version                = "0.1.0"
	Anchor                 = "CISA Minimum Requirements for VEX (2023-04)"
	CanonicalSerialization = "OpenVEX 0.2.0"
	SpecCycloneDX          = "1.6"
	SpecOpenVEX            = "0.2.0"
	SpecCISA               = "2023-04"
)

// Sources are the references the mapping is seeded from.
var Sources = []string{
	"https://github.com/CycloneDX/specification/discussions/609",
	"https://www.cisa.gov/sites/default/files/2023-04/minimum-requirements-for-vex-508c.pdf",
}

// Fidelity records how much is lost translating a CycloneDX value to OpenVEX.
type Fidelity string

const (
	// Exact: 1:1, no semantic loss.
	Exact Fidelity = "exact"
	// Lossy: deterministic target, but source detail is discarded
	// (CycloneDX is finer-grained than CISA's enum).
	Lossy Fidelity = "lossy"
	// Contested: no community consensus yet; a default is chosen, see Note.
	Contested Fidelity = "contested"
)

// Kind distinguishes a status mapping from a justification mapping.
type Kind string

const (
	KindStatus        Kind = "status"
	KindJustification Kind = "justification"
)

// Entry is one CycloneDX -> OpenVEX mapping.
type Entry struct {
	Kind      Kind
	CycloneDX string   // CycloneDX analysis.state or analysis.justification value
	OpenVEX   string   // OpenVEX (= CISA) status or justification value
	Fidelity  Fidelity // exact | lossy | contested
	// ReverseAmbiguous is true when several CycloneDX values collapse onto this
	// OpenVEX value, so OpenVEX -> CycloneDX cannot be derived from this entry.
	ReverseAmbiguous bool
	Note             string
}

// Entries is the full crosswalk — the source of truth. Order is stable so the
// emitted crosswalk.yaml is deterministic.
var Entries = []Entry{
	// --- status: CycloneDX analysis.state -> OpenVEX status ---
	{Kind: KindStatus, CycloneDX: "not_affected", OpenVEX: "not_affected", Fidelity: Exact},
	{Kind: KindStatus, CycloneDX: "exploitable", OpenVEX: "affected", Fidelity: Exact},
	{Kind: KindStatus, CycloneDX: "in_triage", OpenVEX: "under_investigation", Fidelity: Exact},
	{Kind: KindStatus, CycloneDX: "resolved", OpenVEX: "fixed", Fidelity: Exact},
	{Kind: KindStatus, CycloneDX: "resolved_with_pedigree", OpenVEX: "fixed", Fidelity: Lossy,
		Note: "OpenVEX has no pedigree concept; the proof-of-fix provenance is dropped."},
	{Kind: KindStatus, CycloneDX: "false_positive", OpenVEX: "not_affected", Fidelity: Contested,
		Note: "CycloneDX state carries no justification, but OpenVEX requires one for not_affected. A bare false_positive cannot become valid OpenVEX; convert only when a justification is also supplied, else fall back to under_investigation. #609 leans component_not_present but marks it uncertain."},

	// --- justification: CycloneDX analysis.justification -> OpenVEX justification ---
	{Kind: KindJustification, CycloneDX: "code_not_present", OpenVEX: "vulnerable_code_not_present", Fidelity: Exact},
	{Kind: KindJustification, CycloneDX: "code_not_reachable", OpenVEX: "vulnerable_code_not_in_execute_path", Fidelity: Exact},
	{Kind: KindJustification, CycloneDX: "protected_by_mitigating_control", OpenVEX: "inline_mitigations_already_exist", Fidelity: Exact},
	{Kind: KindJustification, CycloneDX: "protected_by_compiler", OpenVEX: "inline_mitigations_already_exist", Fidelity: Lossy,
		Note: "Not enumerated in #609; compiler hardening is an inline mitigation. Proposed."},
	{Kind: KindJustification, CycloneDX: "protected_at_runtime", OpenVEX: "vulnerable_code_cannot_be_controlled_by_adversary", Fidelity: Contested, ReverseAmbiguous: true,
		Note: "#609 groups this under cannot_be_controlled, but runtime protection (ASLR, sandbox) is arguably inline_mitigations_already_exist. Open cell."},
	{Kind: KindJustification, CycloneDX: "protected_at_perimeter", OpenVEX: "vulnerable_code_cannot_be_controlled_by_adversary", Fidelity: Lossy, ReverseAmbiguous: true},
	{Kind: KindJustification, CycloneDX: "requires_configuration", OpenVEX: "vulnerable_code_cannot_be_controlled_by_adversary", Fidelity: Lossy, ReverseAmbiguous: true},
	{Kind: KindJustification, CycloneDX: "requires_dependency", OpenVEX: "vulnerable_code_cannot_be_controlled_by_adversary", Fidelity: Lossy, ReverseAmbiguous: true},
	{Kind: KindJustification, CycloneDX: "requires_environment", OpenVEX: "vulnerable_code_cannot_be_controlled_by_adversary", Fidelity: Lossy, ReverseAmbiguous: true},
}

// LookupStatus returns the mapping for a CycloneDX analysis.state value.
func LookupStatus(cyclonedxState string) (Entry, bool) {
	return lookup(KindStatus, cyclonedxState)
}

// LookupJustification returns the mapping for a CycloneDX analysis.justification value.
func LookupJustification(cyclonedxJustification string) (Entry, bool) {
	return lookup(KindJustification, cyclonedxJustification)
}

func lookup(kind Kind, cdx string) (Entry, bool) {
	for _, e := range Entries {
		if e.Kind == kind && e.CycloneDX == cdx {
			return e, true
		}
	}
	return Entry{}, false
}

// MarshalYAML emits the canonical crosswalk.yaml. Hand-rolled (stdlib only) so
// the module pulls in no YAML dependency; the committed crosswalk.yaml is this
// output, verified by the parity test.
func MarshalYAML() []byte {
	var b strings.Builder
	b.WriteString("# crosswalk.yaml — VEX vocabulary crosswalk\n")
	b.WriteString("# GENERATED from crosswalk.Entries (crosswalk/crosswalk.go) — edit there, not here.\n")
	b.WriteString("# Run: go run ./cmd/cyclonedx-to-openvex -dump-crosswalk > crosswalk/crosswalk.yaml\n")
	b.WriteString("#\n")
	b.WriteString("# Maps CycloneDX VEX (analysis.state / analysis.justification) onto the CISA\n")
	b.WriteString("# \"Minimum Requirements for VEX\" labels, which OpenVEX implements verbatim.\n")
	b.WriteString("# Primary direction CycloneDX -> OpenVEX is deterministic (lossy where noted).\n")
	b.WriteString("# reverse_ambiguous entries must not be auto-applied OpenVEX -> CycloneDX.\n\n")

	fmt.Fprintf(&b, "version: %s\n", quote(Version))
	fmt.Fprintf(&b, "anchor: %s\n", quote(Anchor))
	fmt.Fprintf(&b, "canonical_serialization: %s\n", quote(CanonicalSerialization))
	b.WriteString("specs:\n")
	fmt.Fprintf(&b, "  cyclonedx: %s\n", quote(SpecCycloneDX))
	fmt.Fprintf(&b, "  openvex: %s\n", quote(SpecOpenVEX))
	fmt.Fprintf(&b, "  cisa: %s\n", quote(SpecCISA))
	b.WriteString("sources:\n")
	for _, s := range Sources {
		fmt.Fprintf(&b, "  - %s\n", quote(s))
	}
	b.WriteString("fidelity_legend:\n")
	fmt.Fprintf(&b, "  exact: %s\n", quote("1:1, no semantic loss"))
	fmt.Fprintf(&b, "  lossy: %s\n", quote("deterministic target, but source detail is discarded"))
	fmt.Fprintf(&b, "  contested: %s\n", quote("no community consensus yet; default chosen, see note"))

	writeSection(&b, "status", KindStatus)
	writeSection(&b, "justification", KindJustification)
	return []byte(b.String())
}

func writeSection(b *strings.Builder, name string, kind Kind) {
	fmt.Fprintf(b, "\n%s:\n", name)
	for _, e := range Entries {
		if e.Kind != kind {
			continue
		}
		fmt.Fprintf(b, "  - cyclonedx: %s\n", quote(e.CycloneDX))
		fmt.Fprintf(b, "    openvex: %s\n", quote(e.OpenVEX))
		fmt.Fprintf(b, "    fidelity: %s\n", quote(string(e.Fidelity)))
		if e.ReverseAmbiguous {
			b.WriteString("    reverse_ambiguous: true\n")
		}
		if e.Note != "" {
			fmt.Fprintf(b, "    note: %s\n", quote(e.Note))
		}
	}
}

// quote renders a string as a YAML double-quoted scalar — always quoted, so
// the emitter never has to reason about which bare scalars are safe.
func quote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}
