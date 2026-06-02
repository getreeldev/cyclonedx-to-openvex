// Package openvex holds the minimal OpenVEX 0.2.0 output types this library
// emits. Only the fields the translator populates are modelled — consumers
// that need the full spec can re-marshal. Stdlib JSON tags only.
package openvex

// ContextURL is the OpenVEX 0.2.0 @context every emitted document carries.
const ContextURL = "https://openvex.dev/ns/v0.2.0"

// Document is an OpenVEX 0.2.0 document.
type Document struct {
	Context    string      `json:"@context"`
	ID         string      `json:"@id,omitempty"`
	Author     string      `json:"author"`
	Timestamp  string      `json:"timestamp,omitempty"`
	Version    int         `json:"version"`
	Statements []Statement `json:"statements"`
}

// Statement is one OpenVEX statement.
type Statement struct {
	Vulnerability Vulnerability `json:"vulnerability"`
	Products      []Product     `json:"products"`
	Status        string        `json:"status"`
	Justification string        `json:"justification,omitempty"`
	// StatusNotes carries conversion provenance as `key=value; key=value`
	// (converted_from, original_state, original_justification, fidelity) so the
	// mapping travels inside the document rather than as a side-channel report.
	StatusNotes     string `json:"status_notes,omitempty"`
	ImpactStatement string `json:"impact_statement,omitempty"`
}

// Vulnerability identifies the CVE a statement is about.
type Vulnerability struct {
	Name string `json:"name"`
}

// Product is a product/component identifier (PURL or CPE) in @id form.
type Product struct {
	ID string `json:"@id"`
}

// OpenVEX status values (= CISA Minimum Requirements labels).
const (
	StatusNotAffected        = "not_affected"
	StatusAffected           = "affected"
	StatusFixed              = "fixed"
	StatusUnderInvestigation = "under_investigation"
)
