package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
)

func main() {
	benignPath := flag.String("benign", "internal/agentguard/testdata/benign_tool_calls.json", "benign tool-call replay cases")
	redteamPath := flag.String("redteam", "internal/agentguard/testdata/redteam_tool_calls.json", "redteam tool-call replay cases")
	outputPath := flag.String("output", "", "optional JSON report output path")
	flag.Parse()

	report, err := agentguard.ReplayCaseFiles(*benignPath, *redteamPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentguard replay failed: %v\n", err)
		os.Exit(1)
	}
	body, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal replay report: %v\n", err)
		os.Exit(1)
	}
	body = append(body, '\n')
	if *outputPath != "" {
		if err := os.WriteFile(*outputPath, body, 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "write replay report: %v\n", err)
			os.Exit(1)
		}
		return
	}
	fmt.Print(string(body))
}
