# cyclonedx-to-openvex

[![Go Reference](https://pkg.go.dev/badge/github.com/getreeldev/cyclonedx-to-openvex.svg)](https://pkg.go.dev/github.com/getreeldev/cyclonedx-to-openvex)

Go library + CLI that converts a CycloneDX BOM's embedded VEX (`vulnerabilities[].analysis`) into an [OpenVEX](https://openvex.dev) 0.2.0 document. Zero dependencies beyond the standard library.

The two formats use incompatible status/justification vocabularies, and CycloneDX is finer-grained than OpenVEX — so the conversion is deterministic but **lossy** in places. This library makes the loss explicit rather than hiding it:

- the mapping is a published, versioned spec file — [`crosswalk/crosswalk.yaml`](crosswalk/crosswalk.yaml) — with a **fidelity** flag (`exact` / `lossy` / `contested`) on every entry;
- every converted statement records its provenance in `status_notes`;
- `-reject-lossy` skips anything that isn't an exact mapping, for strict OpenVEX.

See [`docs/crosswalk.md`](docs/crosswalk.md) for the mapping model, fidelity, direction, and how the spec file is maintained.

## Install

```bash
go get github.com/getreeldev/cyclonedx-to-openvex
```

## Use

Library:

```go
import "github.com/getreeldev/cyclonedx-to-openvex/translator"

// r is any io.Reader of a CycloneDX BOM. report lists every mapping and skip.
doc, report, err := translator.FromCycloneDX(r, translator.Options{})
```

CLI:

```bash
cyclonedx-to-openvex < bom.cdx.json > out.openvex.json   # convert
cyclonedx-to-openvex -report < bom.cdx.json > out.json   # + report on stderr
cyclonedx-to-openvex -reject-lossy < bom.cdx.json        # strict: skip non-exact mappings
```

A `not_affected` carrying a CycloneDX justification, converted (note the preserved provenance):

```jsonc
// in:  state=not_affected, justification=requires_environment
{
  "vulnerability": { "name": "CVE-2022-42898" },
  "products": [ { "@id": "pkg:deb/debian/libk5crypto3@1.18.3-6%2Bdeb11u2?arch=amd64&distro=debian-11.5" } ],
  "status": "not_affected",
  "justification": "vulnerable_code_cannot_be_controlled_by_adversary",
  "status_notes": "converted_from=cyclonedx-vex; original_state=not_affected; original_justification=requires_environment; fidelity=lossy"
}
```

`requires_environment` has no exact OpenVEX equivalent, so it collapses to the nearest CISA bucket, flagged `lossy`, with the original kept in `status_notes`.

## License

Apache-2.0. The `crosswalk.yaml` data file is intended to be freely reusable.
