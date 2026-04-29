// Command ztp-mdns-publish is a tiny standalone DNS-SD advertiser.
//
// It exists so a docker-compose stack (or a systemd unit on a bare host) can
// announce "_ztp._tcp" on the LAN even when the ZTP server itself is on a
// bridge network where multicast can't escape. Run it with
// `network_mode: host` on Linux/AWS so UDP 5353 reaches the LAN.
//
// On startup it can optionally hit /v1/server-info on a running server and
// copy `public_key` + `protocol_version` into the TXT records, so the
// advertisement is consistent with what the server itself would have
// published.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/mdns"
)

func main() {
	service := flag.String("service", "_ztp._tcp", "DNS-SD service type")
	port := flag.Int("port", 8080, "TCP port advertised in SRV record")
	host := flag.String("host", "", "hostname for SRV record (default: os.Hostname())")
	serverURL := flag.String("server-url", "", "ZTP server URL; if set, /v1/server-info is queried for TXT records")
	extraTxt := flag.String("txt", "", "comma-separated extra TXT records, e.g. 'env=prod,site=hq'")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	var info []string
	if *serverURL != "" {
		scheme := "http"
		if strings.HasPrefix(*serverURL, "https://") {
			scheme = "https"
		}
		info = append(info, "scheme="+scheme)
		i, err := fetchServerInfo(*serverURL, logger)
		if err != nil {
			logger.Warn("server-info fetch failed; advertising without server TXT records", "err", err)
		}
		info = append(info, i...)
	}
	if *extraTxt != "" {
		for _, kv := range strings.Split(*extraTxt, ",") {
			if kv = strings.TrimSpace(kv); kv != "" {
				info = append(info, kv)
			}
		}
	}

	pub, err := mdns.Publish(*service, *port, *host, info)
	if err != nil {
		logger.Error("publish", "err", err)
		os.Exit(1)
	}
	defer pub.Close()
	logger.Info("advertising", "service", *service, "port", *port, "txt", info)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	logger.Info("shutting down")
}

// fetchServerInfo polls /v1/server-info until it succeeds (with a short
// retry budget) so the publisher tolerates being started before the server.
func fetchServerInfo(base string, logger *slog.Logger) ([]string, error) {
	url := strings.TrimRight(base, "/") + "/v1/server-info"
	c := &http.Client{Timeout: 5 * time.Second}

	var lastErr error
	for i := 0; i < 30; i++ {
		resp, err := c.Get(url)
		if err != nil {
			lastErr = err
		} else {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode/100 == 2 {
				var si struct {
					ProtocolVersion string `json:"protocol_version"`
					PublicKey       string `json:"public_key"`
				}
				if err := json.Unmarshal(body, &si); err != nil {
					return nil, fmt.Errorf("decode server-info: %w", err)
				}
				out := make([]string, 0, 2)
				if si.ProtocolVersion != "" {
					out = append(out, "version="+si.ProtocolVersion)
				}
				if si.PublicKey != "" {
					out = append(out, "pubkey="+si.PublicKey)
				}
				return out, nil
			}
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
		}
		logger.Info("waiting for server-info", "url", url, "attempt", i+1, "err", lastErr)
		time.Sleep(2 * time.Second)
	}
	return nil, lastErr
}
