// Package translator converts a CycloneDX BOM's embedded VEX (analysis.state /
// analysis.justification) into an OpenVEX 0.2.0 document, applying the
// vocabulary crosswalk and recording per-statement provenance in status_notes.
//
// Direction is CycloneDX -> OpenVEX only (the deterministic direction; see the
// crosswalk package). Conversion never invents data: where a mapping is lossy
// or contested it still produces a valid OpenVEX statement but records the
// original value and fidelity, and Options.RejectLossy makes the caller's
// "OpenVEX-strict" choice — skip anything not an exact mapping.
package translator

import (
	"fmt"
	"io"
	"strings"

	"github.com/getreeldev/cyclonedx-to-openvex/crosswalk"
	"github.com/getreeldev/cyclonedx-to-openvex/cyclonedx"
	"github.com/getreeldev/cyclonedx-to-openvex/openvex"
)

// DefaultAuthor is the OpenVEX author stamped on converted documents when the
// caller does not set Options.Author.
const DefaultAuthor = "cyclonedx-to-openvex"

// Options tunes a conversion.
type Options struct {
	// Author is the OpenVEX document author. Defaults to DefaultAuthor.
	Author string
	// RejectLossy, when true, skips any statement whose status or justification
	// mapping is not exact (lossy/contested), recording it in the Report rather
	// than emitting a degraded verdict. This is the "OpenVEX-strict" mode.
	RejectLossy bool
}

// Outcome classifies what happened to one CycloneDX vulnerability.
type Outcome string

const (
	OutcomeConverted Outcome = "converted"
	OutcomeSkipped   Outcome = "skipped"
)

// Record is one line of the conversion Report.
type Record struct {
	CVE      string
	Outcome  Outcome
	Fidelity crosswalk.Fidelity // worst fidelity applied (converted rows)
	Detail   string             // human-readable reason / remap summary
}

// Report summarises a conversion. It is the structured companion to the
// in-document status_notes — useful for CLI/programmatic callers.
type Report struct {
	Considered        int // vulnerabilities carrying an analysis.state
	StatementsEmitted int
	Lossy             int // converted statements with a lossy mapping
	Contested         int // converted statements with a contested mapping
	Skipped           int
	Records           []Record
}

// FromCycloneDX reads a CycloneDX BOM and returns the converted OpenVEX
// document plus a conversion Report.
func FromCycloneDX(r io.Reader, opts Options) (openvex.Document, Report, error) {
	bom, err := cyclonedx.Parse(r)
	if err != nil {
		return openvex.Document{}, Report{}, err
	}
	doc, rep := convert(bom, opts)
	return doc, rep, nil
}

// Convert converts an already-parsed BOM, returning the document and Report.
func Convert(bom *cyclonedx.BOM, opts Options) (openvex.Document, Report) {
	return convert(bom, opts)
}

func convert(bom *cyclonedx.BOM, opts Options) (openvex.Document, Report) {
	author := opts.Author
	if author == "" {
		author = DefaultAuthor
	}
	doc := openvex.Document{
		Context: openvex.ContextURL,
		Author:  author,
		Version: 1,
	}
	if bom.Metadata != nil {
		doc.Timestamp = bom.Metadata.Timestamp
	}

	byRef := componentIndex(bom.Components)
	var rep Report

	for _, v := range bom.Vulnerabilities {
		if v.Analysis == nil || v.Analysis.State == "" {
			continue // not a VEX statement
		}
		rep.Considered++

		stmt, fidelity, skipReason := buildStatement(v, byRef, opts)
		if skipReason != "" {
			rep.Skipped++
			rep.Records = append(rep.Records, Record{CVE: v.ID, Outcome: OutcomeSkipped, Detail: skipReason})
			continue
		}
		doc.Statements = append(doc.Statements, stmt)
		rep.StatementsEmitted++
		switch fidelity {
		case crosswalk.Lossy:
			rep.Lossy++
		case crosswalk.Contested:
			rep.Contested++
		}
		rep.Records = append(rep.Records, Record{
			CVE: v.ID, Outcome: OutcomeConverted, Fidelity: fidelity,
			Detail: stmt.StatusNotes,
		})
	}
	return doc, rep
}

// buildStatement maps one vulnerability. Returns the statement, the worst
// fidelity applied, and a non-empty skipReason when it cannot/should not emit.
func buildStatement(v cyclonedx.Vulnerability, byRef map[string]string, opts Options) (openvex.Statement, crosswalk.Fidelity, string) {
	statusEntry, ok := crosswalk.LookupStatus(v.Analysis.State)
	if !ok {
		return openvex.Statement{}, "", fmt.Sprintf("unknown CycloneDX state %q", v.Analysis.State)
	}

	worst := statusEntry.Fidelity
	notes := []string{
		"converted_from=cyclonedx-vex",
		"original_state=" + v.Analysis.State,
	}

	var justification string
	if v.Analysis.Justification != "" {
		jEntry, ok := crosswalk.LookupJustification(v.Analysis.Justification)
		if !ok {
			return openvex.Statement{}, "", fmt.Sprintf("unknown CycloneDX justification %q", v.Analysis.Justification)
		}
		justification = jEntry.OpenVEX
		notes = append(notes, "original_justification="+v.Analysis.Justification)
		worst = worseFidelity(worst, jEntry.Fidelity)
	}

	// OpenVEX requires a justification for not_affected. CycloneDX can assert
	// not_affected (or false_positive -> not_affected) without one; we cannot
	// fabricate it, so skip and report rather than emit an invalid statement.
	if statusEntry.OpenVEX == openvex.StatusNotAffected && justification == "" {
		return openvex.Statement{}, "", fmt.Sprintf("not_affected without a mappable justification (CycloneDX state %q)", v.Analysis.State)
	}

	if opts.RejectLossy && worst != crosswalk.Exact {
		return openvex.Statement{}, "", fmt.Sprintf("mapping is %s (reject-lossy on): state=%q justification=%q", worst, v.Analysis.State, v.Analysis.Justification)
	}

	products := resolveProducts(v.Affects, byRef)
	if len(products) == 0 {
		return openvex.Statement{}, "", "no resolvable product identifier (affects[].ref)"
	}

	notes = append(notes, "fidelity="+string(worst))
	stmt := openvex.Statement{
		Vulnerability:   openvex.Vulnerability{Name: v.ID},
		Products:        products,
		Status:          statusEntry.OpenVEX,
		Justification:   justification,
		StatusNotes:     strings.Join(notes, "; "),
		ImpactStatement: v.Analysis.Detail,
	}
	return stmt, worst, ""
}

// componentIndex maps each component's bom-ref to its best identifier.
func componentIndex(comps []cyclonedx.Component) map[string]string {
	m := make(map[string]string, len(comps))
	for _, c := range comps {
		if c.BOMRef != "" {
			if id := c.Identifier(); id != "" {
				m[c.BOMRef] = id
			}
		}
	}
	return m
}

// resolveProducts turns affects[].ref into OpenVEX products: resolve a bom-ref
// to its component identifier, or accept a ref that is itself a PURL/CPE.
func resolveProducts(affects []cyclonedx.Affect, byRef map[string]string) []openvex.Product {
	var out []openvex.Product
	seen := make(map[string]bool)
	for _, a := range affects {
		id := byRef[a.Ref]
		if id == "" && looksLikeIdentifier(a.Ref) {
			id = a.Ref
		}
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, openvex.Product{ID: id})
	}
	return out
}

func looksLikeIdentifier(s string) bool {
	return strings.HasPrefix(s, "pkg:") || strings.HasPrefix(s, "cpe:")
}

// worseFidelity returns the less-faithful of two fidelities
// (exact < lossy < contested).
func worseFidelity(a, b crosswalk.Fidelity) crosswalk.Fidelity {
	rank := map[crosswalk.Fidelity]int{crosswalk.Exact: 0, crosswalk.Lossy: 1, crosswalk.Contested: 2}
	if rank[b] > rank[a] {
		return b
	}
	return a
}
