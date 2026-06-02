// Command cyclonedx-to-openvex reads a CycloneDX BOM (with embedded VEX) from
// stdin and writes an OpenVEX 0.2.0 document to stdout. Conversion provenance
// rides in each statement's status_notes; a human-readable Report goes to
// stderr with -report.
//
// Examples:
//
//	cyclonedx-to-openvex < bom.cdx.json > out.openvex.json
//	cyclonedx-to-openvex -report < bom.cdx.json > out.openvex.json
//	cyclonedx-to-openvex -reject-lossy < bom.cdx.json > out.openvex.json   # OpenVEX-strict
//	cyclonedx-to-openvex -dump-crosswalk > crosswalk/crosswalk.yaml        # regenerate the spec file
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/getreeldev/cyclonedx-to-openvex/crosswalk"
	"github.com/getreeldev/cyclonedx-to-openvex/translator"
)

func main() {
	report := flag.Bool("report", false, "write a conversion report to stderr")
	rejectLossy := flag.Bool("reject-lossy", false, "skip statements whose mapping is not exact (OpenVEX-strict)")
	author := flag.String("author", "", "OpenVEX document author (default: cyclonedx-to-openvex)")
	dumpCrosswalk := flag.Bool("dump-crosswalk", false, "print the canonical crosswalk.yaml and exit")
	flag.Parse()

	if *dumpCrosswalk {
		os.Stdout.Write(crosswalk.MarshalYAML())
		return
	}

	doc, rep, err := translator.FromCycloneDX(os.Stdin, translator.Options{
		Author:      *author,
		RejectLossy: *rejectLossy,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	if *report {
		fmt.Fprintf(os.Stderr, "converted %d statement(s) from %d analysed vulnerabilit(ies): %d lossy, %d contested, %d skipped\n",
			rep.StatementsEmitted, rep.Considered, rep.Lossy, rep.Contested, rep.Skipped)
		for _, r := range rep.Records {
			fmt.Fprintf(os.Stderr, "  [%s] %s %s — %s\n", r.Outcome, r.CVE, r.Fidelity, r.Detail)
		}
	}
}
