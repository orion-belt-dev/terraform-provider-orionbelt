// Command orionbelt-evidence writes a compliance evidence report from a
// Terraform plan:
//
//	terraform show -json tfplan > plan.json
//	orionbelt-evidence -plan plan.json -repository acme/infra -commit "$SHA" > evidence.json
//
// It exits 0 whenever a report is written, compliant or not, so the report
// can be stored before a pipeline gates on its "compliant" field.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/orion-belt-dev/terraform-provider-orionbelt/internal/evidence"
)

func main() {
	planPath := flag.String("plan", "", "path to `terraform show -json` output (required)")
	repository := flag.String("repository", "", "repository the configuration came from")
	commit := flag.String("commit", "", "commit the plan was made from")
	runURL := flag.String("run-url", "", "URL of the CI run")
	flag.Parse()
	if flag.NArg() > 0 {
		fmt.Fprintln(os.Stderr, "orionbelt-evidence: unexpected arguments:", flag.Args())
		os.Exit(2)
	}

	if err := run(*planPath, evidence.Source{Repository: *repository, Commit: *commit, RunURL: *runURL}); err != nil {
		fmt.Fprintln(os.Stderr, "orionbelt-evidence:", err)
		os.Exit(1)
	}
}

func run(planPath string, src evidence.Source) error {
	if planPath == "" {
		return fmt.Errorf("-plan is required")
	}
	planJSON, err := os.ReadFile(planPath) //nolint:gosec // the path is the operator's own input
	if err != nil {
		return err
	}
	report, err := evidence.Build(planJSON, src, time.Now())
	if err != nil {
		return err
	}
	out := json.NewEncoder(os.Stdout)
	out.SetIndent("", "  ")
	return out.Encode(report)
}
