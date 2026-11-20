package platform

import (
	"errors"
	"testing"
)

func TestListenAddr(t *testing.T) {
	tests := []struct {
		name    string
		port    string
		want    string
		wantErr bool
	}{
		{"empty uses the default", "", ":8080", false},
		{"valid port", "10000", ":10000", false},
		{"lowest valid port", "1", ":1", false},
		{"highest valid port", "65535", ":65535", false},
		{"not a number", "abc", "", true},
		{"zero", "0", "", true},
		{"negative", "-1", "", true},
		{"too big", "65536", "", true},
		{"has a host part", "127.0.0.1:8080", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ListenAddr(tt.port)

			if tt.wantErr {
				if !errors.Is(err, ErrInvalidPort) {
					t.Fatalf("expected ErrInvalidPort, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("ListenAddr(%q) = %q, want %q", tt.port, got, tt.want)
			}
		})
	}
}
