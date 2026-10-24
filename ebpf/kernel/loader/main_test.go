package main

import (
	"net"
	"net/http"
	"testing"
	"time"
)

func TestLocalAcceptConnect(t *testing.T) {
	loader, err := LoadAndAttach(bpfObjPath())
	if err != nil {
		t.Fatalf("LoadAndAttach: %v", err)
	}
	defer loader.Close()

	// Start a TCP server
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	serverAddr := ln.Addr().(*net.TCPAddr)
	t.Logf("Server listening on %s", serverAddr)

	// Accept one connection in background
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		conn.Write([]byte("hello"))
		conn.Close()
	}()

	// Connect as client
	conn, err := net.Dial("tcp", serverAddr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	buf := make([]byte, 16)
	conn.Read(buf)
	conn.Close()
	ln.Close()
	<-serverDone

	// Collect events
	events := collectEvents(t, loader, 2*time.Second)

	logEvents(t, events)

	// Find events for our server port
	var (
		gotClientOpen  bool
		gotServerOpen  bool
		gotClientClose bool
		gotServerClose bool
	)

	for _, e := range events {
		c := e.Conn
		rport := PortToHost(c.Rport)

		// Client connecting to server
		if rport == uint16(serverAddr.Port) && c.Role == 1 && e.EventType == 0 {
			gotClientOpen = true
			if IPStr(c.Raddr) != "127.0.0.1" {
				t.Errorf("client raddr: got %s, want 127.0.0.1", IPStr(c.Raddr))
			}
			if IPStr(c.Laddr) != "127.0.0.1" {
				t.Errorf("client laddr: got %s, want 127.0.0.1", IPStr(c.Laddr))
			}
		}

		// Server accepting connection
		if c.Lport == uint16(serverAddr.Port) && c.Role == 2 && e.EventType == 0 {
			gotServerOpen = true
			if IPStr(c.Laddr) != "127.0.0.1" {
				t.Errorf("server laddr: got %s, want 127.0.0.1", IPStr(c.Laddr))
			}
			if IPStr(c.Raddr) != "127.0.0.1" {
				t.Errorf("server raddr: got %s, want 127.0.0.1", IPStr(c.Raddr))
			}
		}

		// Close events
		if rport == uint16(serverAddr.Port) && c.Role == 1 && e.EventType == 1 {
			gotClientClose = true
		}
		if c.Lport == uint16(serverAddr.Port) && c.Role == 2 && e.EventType == 1 {
			gotServerClose = true
		}
	}

	if !gotClientOpen {
		t.Error("missing OPEN event with role=client")
	}
	if !gotServerOpen {
		t.Error("missing OPEN event with role=server")
	}
	if !gotClientClose {
		t.Error("missing CLOSE event with role=client")
	}
	if !gotServerClose {
		t.Error("missing CLOSE event with role=server")
	}
}

func TestRemoteConnect(t *testing.T) {
	loader, err := LoadAndAttach(bpfObjPath())
	if err != nil {
		t.Fatalf("LoadAndAttach: %v", err)
	}
	defer loader.Close()

	// Connect to httpbin.org:80 (no HTTPS redirect)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://httpbin.org/get")
	if err != nil {
		t.Fatalf("http request failed: %v", err)
	}
	resp.Body.Close()
	t.Logf("Got HTTP %d from httpbin.org", resp.StatusCode)

	// Wait for close events to arrive
	time.Sleep(500 * time.Millisecond)

	events := collectEvents(t, loader, 3*time.Second)

	logEvents(t, events)

	// Find connect to remote server on port 80
	var gotRemoteOpen bool
	var gotRemoteClose bool

	for _, e := range events {
		c := e.Conn
		rport := PortToHost(c.Rport)

		// Match any non-loopback, non-DNS connect on port 80 with role=client
		if rport == 80 && c.Role == 1 && IPStr(c.Raddr) != "127.0.0.1" {
			if e.EventType == 0 {
				gotRemoteOpen = true
				if c.Laddr == 0 {
					t.Error("remote connect: laddr is 0 (fexit/tcp_v4_connect didn't fire?)")
				} else {
					t.Logf("remote connect: laddr=%s:%d raddr=%s:%d", IPStr(c.Laddr), c.Lport, IPStr(c.Raddr), rport)
				}
			}
			if e.EventType == 1 {
				gotRemoteClose = true
			}
		}
	}

	if !gotRemoteOpen {
		t.Error("missing OPEN event for remote:80 with role=client")
	}
	if !gotRemoteClose {
		t.Error("missing CLOSE event for remote:80")
	}
}
