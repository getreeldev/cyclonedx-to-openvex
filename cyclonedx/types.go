// Package cyclonedx models the subset of a CycloneDX 1.4+ BOM that carries VEX
// data: vulnerabilities[].analysis (state / justification) and the components
// the analysis applies to. Only the fields the translator reads are modelled.
package cyclonedx

import (
	"encoding/json"
	"fmt"
	"io"
)

// BOM is a CycloneDX bill of materials with (optionally) embedded VEX.
type BOM struct {
	BOMFormat       string          `json:"bomFormat"`
	SpecVersion     string          `json:"specVersion"`
	Metadata        *Metadata       `json:"metadata,omitempty"`
	Components      []Component     `json:"components,omitempty"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
}

// Metadata carries the document timestamp (used as the OpenVEX fallback).
type Metadata struct {
	Timestamp string `json:"timestamp,omitempty"`
}

// Component maps a bom-ref to a package identifier. affects[].ref values are
// resolved against these.
type Component struct {
	BOMRef string `json:"bom-ref,omitempty"`
	PURL   string `json:"purl,omitempty"`
	CPE    string `json:"cpe,omitempty"`
	Name   string `json:"name,omitempty"`
}

// Identifier returns the component's best machine identifier (PURL preferred,
// then CPE), or "" if it carries neither.
func (c Component) Identifier() string {
	if c.PURL != "" {
		return c.PURL
	}
	return c.CPE
}

// Vulnerability is one CycloneDX vulnerability with its VEX analysis.
type Vulnerability struct {
	ID       string    `json:"id"`
	Analysis *Analysis `json:"analysis,omitempty"`
	Affects  []Affect  `json:"affects,omitempty"`
}

// Analysis is the CycloneDX VEX assessment (analysis.state / .justification).
type Analysis struct {
	State         string   `json:"state,omitempty"`
	Justification string   `json:"justification,omitempty"`
	Response      []string `json:"response,omitempty"`
	Detail        string   `json:"detail,omitempty"`
}

// Affect references a component the vulnerability applies to. Ref is a bom-ref
// (resolved against Components) or a direct PURL/CPE.
type Affect struct {
	Ref string `json:"ref"`
}

// Parse decodes a CycloneDX BOM and confirms it is one.
func Parse(r io.Reader) (*BOM, error) {
	var bom BOM
	if err := json.NewDecoder(r).Decode(&bom); err != nil {
		return nil, fmt.Errorf("decode CycloneDX BOM: %w", err)
	}
	if bom.BOMFormat != "" && bom.BOMFormat != "CycloneDX" {
		return nil, fmt.Errorf("not a CycloneDX document (bomFormat=%q)", bom.BOMFormat)
	}
	return &bom, nil
}
