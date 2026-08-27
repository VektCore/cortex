package korvlabs

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vektcore/cortex/internal/application/ports"
	"github.com/vektcore/cortex/internal/domain/scan"
)

func TestPublish_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"id":  "scan-123",
			"url": "https://korvlabs.example/scans/scan-123",
		})
	}))
	defer srv.Close()

	p := New(srv.URL, "test-key")
	result := p.Publish(context.Background(), ports.PublishRequest{
		ScanID: scan.ID("abc123"),
		SARIF:  []byte(`{}`),
	})

	require.True(t, result.IsOk())
	receipt := result.MustGet()
	assert.Equal(t, "korvlabs", receipt.Publisher)
	assert.Equal(t, "https://korvlabs.example/scans/scan-123", receipt.Reference)
}

func TestPublish_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	p := New(srv.URL, "test-key")
	result := p.Publish(context.Background(), ports.PublishRequest{
		ScanID: scan.ID("abc123"),
		SARIF:  []byte(`{}`),
	})

	require.True(t, result.IsError())
	assert.ErrorContains(t, result.Error(), "500")
}

func TestPublish_InvalidURL(t *testing.T) {
	p := New("://bad", "test-key")
	result := p.Publish(context.Background(), ports.PublishRequest{
		ScanID: scan.ID("abc123"),
		SARIF:  []byte(`{}`),
	})

	require.True(t, result.IsError())
}

func TestPublish_NonJSONBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	p := New(srv.URL, "test-key")
	result := p.Publish(context.Background(), ports.PublishRequest{
		ScanID: scan.ID("abc123"),
		SARIF:  []byte(`{}`),
	})

	require.True(t, result.IsOk())
	receipt := result.MustGet()
	assert.Equal(t, "korvlabs", receipt.Publisher)
	assert.Equal(t, srv.URL+scanEndpointPath, receipt.Reference)
}

func TestPublish_ScanIDHeader(t *testing.T) {
	const wantScanID = "deadbeef12345678"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotScanID := r.Header.Get("X-Scan-ID")
		assert.Equal(t, wantScanID, gotScanID)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"id":  wantScanID,
			"url": "https://korvlabs.example/scans/" + wantScanID,
		})
	}))
	defer srv.Close()

	p := New(srv.URL, "test-key")
	result := p.Publish(context.Background(), ports.PublishRequest{
		ScanID: scan.ID(wantScanID),
		SARIF:  []byte(`{}`),
	})

	require.True(t, result.IsOk())
}
