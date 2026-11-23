// alert-attribution-dryrun reads JSONL body_json objects from stdin and prints
// metadata-only proposed attribution. It has no database or mutation capability.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/alert"
	"os"
)

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 4*1024*1024)
	encoder := json.NewEncoder(os.Stdout)
	line := 0
	for scanner.Scan() {
		line++
		var body map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &body); err != nil {
			fmt.Fprintf(os.Stderr, "invalid body_json at line %d\n", line)
			os.Exit(1)
		}
		if err := encoder.Encode(alert.PreviewAlertBodyAttribution(body)); err != nil {
			fmt.Fprintln(os.Stderr, "failed to write preview")
			os.Exit(1)
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "failed to read JSONL input (maximum line 4 MiB)")
		os.Exit(1)
	}
}
