package platform

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestNewServer(t *testing.T) {
	handler := http.NewServeMux()

	srv := NewServer(":8080", handler)

	if srv.Addr != ":8080" {
		t.Errorf("expected addr :8080, got %q", srv.Addr)
	}
	if srv.Handler != handler {
		t.Error("expected the given handler to be used")
	}

	// A zero timeout means "no limit", which lets a slow client hold a
	// connection open forever (Slowloris).
	timeouts := map[string]time.Duration{
		"ReadHeaderTimeout": srv.ReadHeaderTimeout,
		"ReadTimeout":       srv.ReadTimeout,
		"WriteTimeout":      srv.WriteTimeout,
		"IdleTimeout":       srv.IdleTimeout,
	}
	for name, value := range timeouts {
		if value <= 0 {
			t.Errorf("%s must be greater than zero", name)
		}
	}
}

// startServe runs Serve on a random local port and returns its base URL and a
// channel that receives Serve's result.
func startServe(t *testing.T, ctx context.Context, handler http.Handler) (string, <-chan error) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, NewServer(ln.Addr().String(), handler), ln)
	}()

	return "http://" + ln.Addr().String(), done
}

func TestServeStopsWhenContextIsCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	url, done := startServe(t, ctx, NewHealthzHandler())

	resp, err := http.Get(url + "/")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("expected a clean shutdown, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after the context was canceled")
	}
}

func TestServeFinishesInFlightRequestsBeforeStopping(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	started := make(chan struct{})
	release := make(chan struct{})
	slow := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release // keep the request "in flight" until the test lets it go
		w.WriteHeader(http.StatusOK)
	})

	url, done := startServe(t, ctx, slow)

	status := make(chan int, 1)
	go func() {
		resp, err := http.Get(url + "/")
		if err != nil {
			status <- -1
			return
		}
		resp.Body.Close()
		status <- resp.StatusCode
	}()

	<-started
	cancel() // ask the server to stop while the request is still running

	select {
	case <-done:
		t.Fatal("Serve returned while a request was still in flight")
	case <-time.After(200 * time.Millisecond):
	}

	close(release)

	if got := <-status; got != http.StatusOK {
		t.Errorf("expected the in-flight request to finish with 200, got %d", got)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("expected a clean shutdown, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after the request finished")
	}
}
