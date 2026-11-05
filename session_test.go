package milter

import (
	"bufio"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// rawPacket is a milter packet as bytes on the wire: length, code, data.
func rawPacket(code byte, data []byte) []byte {
	b := binary.BigEndian.AppendUint32(nil, uint32(len(data)+1))
	b = append(b, code)
	return append(b, data...)
}

// probeMilter records what reached the backend.
type probeMilter struct {
	NoOpMilter
	headers  *atomic.Int32
	macroLen *atomic.Int32
	panicOn  string
}

func (p probeMilter) Header(name, value string, m *Modifier) (Response, error) {
	if name == p.panicOn {
		panic("backend panic")
	}
	return RespContinue, nil
}

func (p probeMilter) Headers(h textproto.MIMEHeader, m *Modifier) (Response, error) {
	p.headers.Store(int32(len(h)))
	p.macroLen.Store(int32(len(m.Macros)))
	return RespContinue, nil
}

func (p probeMilter) Body(m *Modifier) (Response, error) { return RespContinue, nil }

type testServer struct {
	srv      *Server
	addr     string
	headers  atomic.Int32
	macroLen atomic.Int32
}

func startServer(t *testing.T, read time.Duration, panicOn string) *testServer {
	t.Helper()
	ts := &testServer{}
	ts.srv = &Server{
		NewMilter: func() Milter {
			return probeMilter{headers: &ts.headers, macroLen: &ts.macroLen, panicOn: panicOn}
		},
		ReadTimeout: read,
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ts.addr = ln.Addr().String()
	go func() { _ = ts.srv.Serve(ln) }()
	t.Cleanup(func() { _ = ts.srv.Close() })
	return ts
}

// closedWithin reports whether the server closes the connection within d.
func closedWithin(conn net.Conn, d time.Duration) bool {
	_ = conn.SetReadDeadline(time.Now().Add(d))
	_, err := io.Copy(io.Discard, conn)
	return err == nil
}

// alive: the server still takes a session and answers OPTNEG.
func alive(t *testing.T, addr string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("server gone: %v", err)
	}
	defer func() { _ = conn.Close() }()
	opt := binary.BigEndian.AppendUint32(nil, 6)
	opt = binary.BigEndian.AppendUint32(opt, 0)
	opt = binary.BigEndian.AppendUint32(opt, 0)
	if _, err := conn.Write(rawPacket('O', opt)); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var n uint32
	if err := binary.Read(conn, binary.BigEndian, &n); err != nil {
		t.Fatalf("no OPTNEG answer after the bad session: %v", err)
	}
}

// Each malformed packet ends its session without killing the server, and
// a huge length is refused before anything is allocated.
func TestMalformedPacketsCloseTheSessionOnly(t *testing.T) {
	logs := &syncBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	ts := startServer(t, 0, "")
	for _, tc := range []struct {
		name string
		wire []byte
	}{
		{"length 0", []byte{0, 0, 0, 0}},
		{"length over MaxPacketSize", binary.BigEndian.AppendUint32(nil, MaxPacketSize+1)},
		{"length 4 GiB", []byte{0xff, 0xff, 0xff, 0xff}},
		{"CONNECT without NUL", rawPacket('C', []byte("host-without-nul"))},
		{"CONNECT with nothing after the host", rawPacket('C', []byte("host\x00"))},
		{"CONNECT empty", rawPacket('C', nil)},
		{"MACRO empty", rawPacket('D', nil)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := net.Dial("tcp", ts.addr)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			if _, err := conn.Write(tc.wire); err != nil {
				t.Fatal(err)
			}
			if !closedWithin(conn, 2*time.Second) {
				t.Error("session not closed")
			}
			alive(t, ts.addr)
			// refused by a check, not by the recover that catches a panic
			if strings.Contains(logs.String(), "panicked") {
				t.Errorf("handled by a panic: %s", logs.String())
			}
		})
	}
}

// With a ReadTimeout a silent client loses its session; without one it would hold it.
func TestReadTimeoutClosesASilentSession(t *testing.T) {
	ts := startServer(t, 200*time.Millisecond, "")
	conn, err := net.Dial("tcp", ts.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if !closedWithin(conn, 2*time.Second) {
		t.Error("a silent session outlived the ReadTimeout")
	}
}

// A panic in the backend closes that session; the server serves the next one.
func TestBackendPanicClosesTheSessionOnly(t *testing.T) {
	ts := startServer(t, 0, "X-Boom")
	conn, err := net.Dial("tcp", ts.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write(rawPacket('L', []byte("X-Boom\x00v\x00"))); err != nil {
		t.Fatal(err)
	}
	if !closedWithin(conn, 2*time.Second) {
		t.Error("session not closed after the panic")
	}
	alive(t, ts.addr)
}

// Headers and macros of one message do not carry into the next on the same connection.
func TestStateResetsAfterEndOfBody(t *testing.T) {
	ts := startServer(t, 0, "")
	conn, err := net.Dial("tcp", ts.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	rd := bufio.NewReader(conn)
	reply := func() {
		var n uint32
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if err := binary.Read(rd, binary.BigEndian, &n); err != nil {
			t.Fatalf("no reply: %v", err)
		}
		_, _ = io.CopyN(io.Discard, rd, int64(n))
	}
	send := func(code byte, data string) {
		if _, err := conn.Write(rawPacket(code, []byte(data))); err != nil {
			t.Fatal(err)
		}
	}
	// first message: a macro and a header
	send('D', "Ni\x00Q1\x00")
	send('L', "Subject\x00one\x00")
	reply()
	send('N', "")
	reply()
	if ts.headers.Load() != 1 || ts.macroLen.Load() != 1 {
		t.Fatalf("first message: %d headers, %d macros; want 1 and 1", ts.headers.Load(), ts.macroLen.Load())
	}
	send('E', "")
	reply()
	// second message: no macro, no header
	send('N', "")
	reply()
	if ts.headers.Load() != 0 || ts.macroLen.Load() != 0 {
		t.Errorf("second message sees %d headers, %d macros of the first", ts.headers.Load(), ts.macroLen.Load())
	}
}

// Serve and Close race on the listener list: run under -race.
func TestServeAndCloseRace(t *testing.T) {
	for i := 0; i < 20; i++ {
		srv := &Server{NewMilter: func() Milter { return NoOpMilter{} }}
		var wg sync.WaitGroup
		for j := 0; j < 3; j++ {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			wg.Add(1)
			go func() { defer wg.Done(); _ = srv.Serve(ln) }()
		}
		time.Sleep(time.Millisecond)
		_ = srv.Close()
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("Serve did not return after Close")
		}
	}
}
