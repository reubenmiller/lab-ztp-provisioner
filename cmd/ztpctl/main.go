// ztpctl is the operator-facing CLI for the ZTP server.
//
// It is a thin wrapper over the /v1/admin REST API: list and approve pending
// devices, manage the allowlist, issue/revoke bootstrap tokens, and tail the
// audit log. All commands honour the ZTP_SERVER and ZTP_TOKEN environment
// variables.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func usage() {
	fmt.Fprintln(os.Stderr, `usage: ztpctl <command> [args]

env:
  ZTP_SERVER    base URL of the ZTP server (e.g. https://ztp.local:8443)
  ZTP_TOKEN     admin bearer token

commands:
  pending list
  pending approve <id>
  pending reject <id>
  devices list
  devices rm <device-id>
  allowlist list
  allowlist add <device-id> [mac=...] [serial=...] [note=...]
  allowlist rm <device-id>
  token issue [--device <id>] [--max-uses N] [--ttl SECONDS]
  token list
  token revoke <id>
  audit tail
  secrets seal <file> [--regex <re>] [--recipient <age1…>]…
  secrets edit <file> [--age-key-file <path>] [--recipient <age1…>]…
  secrets reveal <file> [--age-key-file <path>] --yes-show-secrets`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	// Dispatch the secrets subcommand suite separately because its
	// argument shape (file paths + --flags rather than fixed positions)
	// doesn't fit the join-args[1:3] pattern the rest of the CLI uses.
	if os.Args[1] == "secrets" {
		runSecrets(os.Args[2:])
		return
	}
	cmd := strings.Join(os.Args[1:3], " ")
	args := os.Args[3:]
	switch {
	case cmd == "pending list":
		do("GET", "/v1/admin/pending", nil)
	case strings.HasPrefix(cmd, "pending approve"):
		mustArg(args, "id")
		do("POST", "/v1/admin/pending/"+args[0]+"/approve", nil)
	case strings.HasPrefix(cmd, "pending reject"):
		mustArg(args, "id")
		do("POST", "/v1/admin/pending/"+args[0]+"/reject", nil)
	case cmd == "devices list":
		do("GET", "/v1/admin/devices", nil)
	case strings.HasPrefix(cmd, "devices rm"):
		mustArg(args, "device-id")
		do("DELETE", "/v1/admin/devices/"+args[0], nil)
	case cmd == "allowlist list":
		do("GET", "/v1/admin/allowlist", nil)
	case strings.HasPrefix(cmd, "allowlist add"):
		mustArg(args, "device-id")
		body := map[string]any{"DeviceID": args[0]}
		for _, kv := range args[1:] {
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				continue
			}
			switch k {
			case "mac":
				body["MAC"] = v
			case "serial":
				body["Serial"] = v
			case "note":
				body["Note"] = v
			}
		}
		do("POST", "/v1/admin/allowlist", body)
	case strings.HasPrefix(cmd, "allowlist rm"):
		mustArg(args, "device-id")
		do("DELETE", "/v1/admin/allowlist/"+args[0], nil)
	case strings.HasPrefix(cmd, "token issue"):
		body := parseTokenIssueArgs(args)
		do("POST", "/v1/admin/tokens", body)
	case cmd == "token list":
		do("GET", "/v1/admin/tokens", nil)
	case strings.HasPrefix(cmd, "token revoke"):
		mustArg(args, "id")
		do("DELETE", "/v1/admin/tokens/"+args[0], nil)
	case cmd == "audit tail":
		do("GET", "/v1/admin/audit", nil)
	default:
		usage()
		os.Exit(2)
	}
}

func mustArg(args []string, name string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "missing argument: %s\n", name)
		os.Exit(2)
	}
}

func parseTokenIssueArgs(args []string) map[string]any {
	body := map[string]any{}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--device":
			i++
			if i < len(args) {
				body["device_id"] = args[i]
			}
		case "--max-uses":
			i++
			if i < len(args) {
				var n int
				fmt.Sscanf(args[i], "%d", &n)
				body["max_uses"] = n
			}
		case "--ttl":
			i++
			if i < len(args) {
				var n int
				fmt.Sscanf(args[i], "%d", &n)
				body["ttl_seconds"] = n
			}
		}
	}
	return body
}

func do(method, path string, body any) {
	server := os.Getenv("ZTP_SERVER")
	if server == "" {
		fmt.Fprintln(os.Stderr, "ZTP_SERVER not set")
		os.Exit(1)
	}
	token := os.Getenv("ZTP_TOKEN")
	var reader io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, server+path, reader)
	if err != nil {
		fail(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fail(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		fmt.Fprintf(os.Stderr, "%s %s -> %d\n%s\n", method, path, resp.StatusCode, string(out))
		os.Exit(1)
	}
	if len(out) > 0 {
		// Pretty-print JSON if it looks like JSON.
		var generic any
		if err := json.Unmarshal(out, &generic); err == nil {
			pretty, _ := json.MarshalIndent(generic, "", "  ")
			fmt.Println(string(pretty))
			return
		}
		fmt.Println(string(out))
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
