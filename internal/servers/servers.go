package servers

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"
)

type Server struct {
	Name      string `json:"name"`
	User      string `json:"user"`
	Host      string `json:"host"`
	Password  string `json:"password"`
	PanelPort int    `json:"panel_port"`
}

func Path() string {
	base, err := os.UserConfigDir()
	if err != nil || base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "deadeye", "servers.json")
}

func Load() []Server {
	data, err := os.ReadFile(Path())
	if err != nil {
		return nil
	}
	var list []Server
	if json.Unmarshal(data, &list) != nil {
		return nil
	}
	return list
}

func Save(list []Server) error {
	if err := os.MkdirAll(filepath.Dir(Path()), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := Path() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, Path())
}

// SplitUserHost splits "root@1.2.3.4" into user and host.
func SplitUserHost(s string) (user, host string) {
	for i := 0; i < len(s); i++ {
		if s[i] == '@' {
			return s[:i], s[i+1:]
		}
	}
	return "root", s
}

// Tunnel is a local port forwarded over SSH to the panel on the server.
type Tunnel struct {
	client *ssh.Client
	ln     net.Listener
	port   int
}

func (t *Tunnel) Port() int { return t.port }

func (t *Tunnel) Close() {
	if t.ln != nil {
		_ = t.ln.Close()
	}
	if t.client != nil {
		_ = t.client.Close()
	}
}

// OpenTunnel connects to the server over SSH and forwards its panel to
// a free local port. The user never sees a connection window:
// only the final panel address.
func OpenTunnel(s Server, timeout time.Duration) (*Tunnel, error) {
	if s.PanelPort <= 0 {
		s.PanelPort = 8000
	}
	cfg := &ssh.ClientConfig{
		User:            s.User,
		Auth:            []ssh.AuthMethod{ssh.Password(s.Password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
	}
	client, err := ssh.Dial("tcp", net.JoinHostPort(s.Host, "22"), cfg)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	t := &Tunnel{
		client: client,
		ln:     ln,
		port:   ln.Addr().(*net.TCPAddr).Port,
	}
	go t.serve(net.JoinHostPort("127.0.0.1", strconv.Itoa(s.PanelPort)))
	return t, nil
}

func (t *Tunnel) serve(target string) {
	for {
		conn, err := t.ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			remote, err := t.client.Dial("tcp", target)
			if err != nil {
				return
			}
			defer remote.Close()
			go func() { _, _ = io.Copy(remote, conn) }()
			_, _ = io.Copy(conn, remote)
		}()
	}
}

// PanelURL is the address of the Marzban panel on the local tunnel.
func (t *Tunnel) PanelURL() string {
	return "http://127.0.0.1:" + strconv.Itoa(t.port) + "/dashboard"
}
