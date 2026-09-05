// The backend simulates a sleeping machine using real HTTP, TCP, UDP and SSH
// sockets. It wakes only on the expected magic packet and sleeps only after an
// authenticated SSH exec request. It never executes commands on the test host.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

var awake atomic.Bool
var wakes, shutdowns atomic.Int32

func main() {
	// These are actual host bind mounts. Ownership must be prepared inside the
	// container because the test runner need not be root or have UID 1000.
	for _, entry := range []struct {
		path, owner string
		mode        os.FileMode
	}{
		{"/fixtures", "CONFIG_UID", 0o755},
		{"/fixtures/config.toml", "CONFIG_UID", 0o644},
		{"/fixtures/ssh_key", "KEY_UID", 0o600},
	} {
		uid, err := strconv.Atoi(os.Getenv(entry.owner))
		must(err)
		must(os.Chown(entry.path, uid, uid))
		must(os.Chmod(entry.path, entry.mode))
	}

	udp, err := net.ListenPacket("udp", ":9009")
	must(err)
	go func() {
		mac := []byte{0x02, 0, 0, 0, 0, 1}
		want := append(bytes.Repeat([]byte{0xff}, 6), bytes.Repeat(mac, 16)...)
		packet := make([]byte, 2048)
		for {
			n, _, err := udp.ReadFrom(packet)
			must(err)
			if bytes.Equal(packet[:n], want) {
				wakes.Add(1)
				awake.Store(true)
			}
		}
	}()

	tcp, err := net.Listen("tcp", ":19090")
	must(err)
	go func() {
		for {
			conn, err := tcp.Accept()
			must(err)
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				body, err := io.ReadAll(conn)
				if err == nil && awake.Load() {
					_, _ = fmt.Fprintf(conn, "tcp:%s", body)
				}
			}()
		}
	}()

	allowed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(os.Getenv("SSH_PUBLIC_KEY")))
	must(err)
	_, private, err := ed25519.GenerateKey(rand.Reader)
	must(err)
	signer, err := ssh.NewSignerFromKey(private)
	must(err)
	sshConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if meta.User() == "doormouse" && bytes.Equal(key.Marshal(), allowed.Marshal()) {
				return nil, nil
			}
			return nil, fmt.Errorf("unexpected SSH identity")
		},
	}
	sshConfig.AddHostKey(signer)
	sshListener, err := net.Listen("tcp", ":2222")
	must(err)
	go func() {
		for {
			conn, err := sshListener.Accept()
			must(err)
			go serveSSH(conn, sshConfig)
		}
	}()

	http.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		if !awake.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	})
	http.HandleFunc("/state", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"awake": awake.Load(), "wakes": wakes.Load(), "shutdowns": shutdowns.Load(),
		})
	})
	http.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		if !awake.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("X-Backend", "doormouse-e2e")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.Copy(w, r.Body)
	})
	server := &http.Server{Addr: ":18080", ReadHeaderTimeout: 5 * time.Second}
	log.Print("backend ready")
	must(server.ListenAndServe())
}

func serveSSH(conn net.Conn, config *ssh.ServerConfig) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	server, channels, requests, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return
	}
	defer server.Close()
	go ssh.DiscardRequests(requests)
	for channel := range channels {
		if channel.ChannelType() != "session" {
			_ = channel.Reject(ssh.UnknownChannelType, "session required")
			continue
		}
		session, requests, err := channel.Accept()
		if err != nil {
			return
		}
		for request := range requests {
			var command struct{ Command string }
			if request.Type != "exec" || ssh.Unmarshal(request.Payload, &command) != nil || command.Command != "suspend" {
				_ = request.Reply(false, nil)
				continue
			}
			awake.Store(false)
			shutdowns.Add(1)
			_ = request.Reply(true, nil)
			_, _ = session.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
			break
		}
		_ = session.Close()
	}
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
