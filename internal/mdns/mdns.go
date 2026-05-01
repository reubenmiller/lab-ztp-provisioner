// Package mdns wraps DNS-SD advertisement / discovery for the ZTP server.
//
// The server uses Publish to announce "_ztp._tcp" on the LAN; agents whose
// -server flag is empty use Discover to find a server. The intent is to make
// LAN provisioning truly zero-config: power on a device, it asks "where is
// the ZTP server?", server answers, enrollment proceeds.
package mdns

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	hmdns "github.com/hashicorp/mdns"
	"github.com/miekg/dns"
)

// Publisher advertises the server on the LAN.
//
// On macOS a dns-sd subprocess is also spawned so that the registration is
// visible to mDNSResponder (and therefore to dns-sd -B, Finder, iOS, etc.).
// hashicorp/mdns alone only answers direct multicast queries from other Go
// agents; it does not touch the system daemon.
type Publisher struct {
	srv     *hmdns.Server
	bonjour bonjourProc // platform-specific mDNSResponder registration
}

// Publish starts a goroutine-backed advertiser. service should be like
// "_ztp._tcp" and port is the TCP port the server listens on. host is an
// optional host name (".local" suffix is appended if missing); if empty,
// os.Hostname() is used. info is a list of "key=value" TXT records.
func Publish(service string, port int, host string, info []string) (*Publisher, error) {
	if host == "" {
		h, err := os.Hostname()
		if err != nil {
			return nil, err
		}
		host = h
	}
	ips, _ := localIPs()
	cfg, err := hmdns.NewMDNSService(host, service, "", "", port, ips, info)
	if err != nil {
		return nil, fmt.Errorf("mdns service: %w", err)
	}
	srv, err := hmdns.NewServer(&hmdns.Config{Zone: cfg})
	if err != nil {
		return nil, fmt.Errorf("mdns server: %w", err)
	}
	p := &Publisher{srv: srv}
	// On macOS, also register with mDNSResponder so the service shows up in
	// dns-sd -B and is visible to the system resolver.
	p.bonjour = registerWithBonjour(service, port, host, info)
	return p, nil
}

// Close stops advertising.
func (p *Publisher) Close() error {
	if p == nil {
		return nil
	}
	p.bonjour.stop()
	if p.srv == nil {
		return nil
	}
	return p.srv.Shutdown()
}

// Entry is a discovered ZTP server.
type Entry struct {
	Host string
	Addr net.IP
	Port int
	Info []string
}

// URL returns the server's base URL using the SRV hostname (e.g.
// "https://ztp.local:8443") so that the HTTP Host header and TLS SNI are
// correct for Caddy virtual-host routing and certificate validation.
//
// The scheme is read from the "scheme=https/http" TXT record.
//
// NOTE: on devices where .local names are not resolvable via system DNS,
// call DialAddr() to get the raw "ip:port" and use it as a TCP dial override
// (e.g. http.Transport.DialContext) while keeping this URL for the request.
func (e Entry) URL() string {
	scheme := "http"
	for _, kv := range e.Info {
		if kv == "scheme=https" {
			scheme = "https"
			break
		}
	}
	host := strings.TrimSuffix(e.Host, ".")
	if host == "" {
		host = e.Addr.String()
	}
	return fmt.Sprintf("%s://%s:%d", scheme, host, e.Port)
}

// DialAddr returns the "ip:port" string that should be used for the TCP
// connection when the hostname in URL() is not resolvable via system DNS
// (e.g. a .local mDNS-only name on a device without nss-mdns). Pass this
// to the HTTP transport's DialContext to bypass DNS while keeping the
// URL hostname for Host header and TLS SNI.
func (e Entry) DialAddr() string {
	return net.JoinHostPort(e.Addr.String(), fmt.Sprint(e.Port))
}

// TLSServerName returns the hostname from the SRV record (e.g. "ztp.local"),
// stripped of its trailing dot. Kept for reference; prefer using URL() directly
// since Go derives the TLS ServerName from the URL hostname automatically.
func (e Entry) TLSServerName() string {
	return strings.TrimSuffix(e.Host, ".")
}

// Discover queries the LAN for the given service and returns the first
// answering entry, or an error if the timeout elapses.
func Discover(ctx context.Context, service string, timeout time.Duration) (*Entry, error) {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	ch := make(chan *hmdns.ServiceEntry, 4)
	params := hmdns.DefaultParams(service)
	params.Entries = ch
	params.Timeout = timeout
	params.DisableIPv6 = true

	done := make(chan error, 1)
	go func() { done <- hmdns.Query(params) }()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case err := <-done:
			return nil, fmt.Errorf("discover %s: %w", service, firstNonNil(err, errNotFound))
		case e := <-ch:
			if e == nil {
				continue
			}
			ip := e.AddrV4
			if ip == nil {
				ip = e.AddrV6
			}
			if ip == nil {
				continue
			}
			return &Entry{
				Host: e.Host,
				Addr: ip,
				Port: e.Port,
				Info: e.InfoFields,
			}, nil
		}
	}
}

var errNotFound = fmt.Errorf("no ZTP server announced on the LAN")

func firstNonNil(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

// ResolveHost performs an mDNS A query for the given hostname (e.g.
// "ztp.local") and returns the first answering IPv4 address. This is needed
// on systems where Go's pure resolver cannot reach the host through the
// system stub resolver — for example, when systemd-resolved's DNS stub does
// not answer .local queries from non-mDNS-enabled links, or when nss-mdns
// is not installed. Sends a multicast question to 224.0.0.251:5353 and
// reads answers until timeout.
func ResolveHost(ctx context.Context, host string, timeout time.Duration) (net.IP, error) {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return nil, fmt.Errorf("mdns: empty host")
	}

	mcast := &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("mdns: listen udp4: %w", err)
	}
	defer conn.Close()

	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(host), dns.TypeA)
	q.RecursionDesired = false
	wire, err := q.Pack()
	if err != nil {
		return nil, fmt.Errorf("mdns: pack query: %w", err)
	}
	if _, err := conn.WriteToUDP(wire, mcast); err != nil {
		return nil, fmt.Errorf("mdns: send query: %w", err)
	}

	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetReadDeadline(deadline); err != nil {
		return nil, err
	}

	want := strings.ToLower(dns.Fqdn(host))
	buf := make([]byte, 1500)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			return nil, fmt.Errorf("mdns: resolve %q: %w", host, err)
		}
		resp := new(dns.Msg)
		if err := resp.Unpack(buf[:n]); err != nil {
			continue
		}
		for _, rr := range append(resp.Answer, resp.Extra...) {
			a, ok := rr.(*dns.A)
			if !ok {
				continue
			}
			if strings.EqualFold(a.Hdr.Name, want) {
				return a.A, nil
			}
		}
	}
}

func localIPs() ([]net.IP, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	out := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLoopback() && ipn.IP.To4() != nil {
			out = append(out, ipn.IP)
		}
	}
	return out, nil
}
