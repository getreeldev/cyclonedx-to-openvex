# The crosswalk

`crosswalk/crosswalk.yaml` is the canonical, publishable mapping between CycloneDX VEX vocabulary and OpenVEX. This document explains the model behind it.

## Anchor

The mapping is anchored on the [CISA Minimum Requirements for VEX](https://www.cisa.gov/resources-tools/resources/minimum-requirements-vulnerability-exploitability-exchange-vex) (April 2023) status and justification labels. **OpenVEX implements those labels verbatim**, so "CycloneDX → OpenVEX" is really "CycloneDX → CISA Minimum Requirements," with OpenVEX as the serialization. The entries are seeded from the community table in [CycloneDX/specification#609](https://github.com/CycloneDX/specification/discussions/609).

## Fidelity

CycloneDX has 9 justifications; CISA/OpenVEX has 5. The conversion is therefore deterministic but **lossy** in places. Every entry carries a fidelity flag:

| Fidelity | Meaning |
|---|---|
| `exact` | 1:1, no semantic loss |
| `lossy` | deterministic target, but source detail is discarded (CycloneDX was finer-grained) |
| `contested` | no community consensus yet; a default is chosen, see the entry's `note` |

A consumer can refuse `lossy`/`contested` mappings (`-reject-lossy`) to stay strictly faithful.

## Direction

`CycloneDX → OpenVEX` is the supported, deterministic direction. The reverse (`OpenVEX → CycloneDX`) is **not** 1:1 — five CycloneDX justifications (`requires_*`, `protected_at_*`) collapse onto OpenVEX's single `vulnerable_code_cannot_be_controlled_by_adversary`, so those entries are flagged `reverse_ambiguous` and must not be auto-applied in reverse without a human choice.

## A known constraint: `not_affected` needs a justification

OpenVEX requires a justification on every `not_affected` statement. CycloneDX can assert `not_affected` (or `false_positive`, which maps to `not_affected`) with no justification. The converter cannot fabricate one, so such statements are **skipped and reported** rather than emitted as invalid OpenVEX.

## Source of truth & regeneration

The Go map `crosswalk.Entries` (in `crosswalk/crosswalk.go`) is the source of truth. `crosswalk.yaml` is **generated** from it — there is no YAML parser anywhere in the module, which keeps it dependency-free. After editing the Go map, regenerate:

```bash
go run ./cmd/cyclonedx-to-openvex -dump-crosswalk > crosswalk/crosswalk.yaml
```

A parity test (`crosswalk/crosswalk_test.go`) fails the build if the committed file drifts from the Go map. The `specs:` header pins the CycloneDX / OpenVEX / CISA versions this revision was authored against — bump it when an underlying enum or a contested cell changes.

## Contested cells (open for input)

These have a default but no settled consensus — contributions welcome:

- `false_positive` → `not_affected` (CycloneDX state carries no justification; #609 leans `component_not_present` but marks it uncertain).
- `protected_at_runtime` → `vulnerable_code_cannot_be_controlled_by_adversary` (#609 groups it there, but runtime protection is arguably `inline_mitigations_already_exist`).
