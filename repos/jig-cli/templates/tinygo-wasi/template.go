// Jig Block - TinyGo WASI Template
//
// This is a minimal template for creating Jig Blocks in Go with WASI support.
//
// Capabilities are injected by the runtime based on the block manifest.
// The block runs in a sandboxed WebAssembly environment with resource limits.

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Output represents the structured output of the block
type Output struct {
	Status    string `json:"status"`
	Message   string `json:"message"`
	Timestamp string `json:"timestamp"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Block execution failed: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// Your block logic goes here
	fmt.Println("Hello from Jig Block!")

	// Example: Create structured output
	output := Output{
		Status:    "ok",
		Message:   "Block executed successfully",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	// Write JSON output to stdout
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(output); err != nil {
		return fmt.Errorf("failed to encode output: %w", err)
	}

	return nil
}

// Metadata returns block metadata for runtime introspection
//
//export metadata
func metadata() *byte {
	meta := `{"version":"0.1.0","runtime":"wasi"}`
	return &[]byte(meta)[0]
}
