package httpx

import (
	"context"
	"net/http"
	"testing"
)

func TestForwardHeaders(t *testing.T) {
	if h := HeadersFromContext(context.Background()); len(h) != 0 {
		t.Fatalf("empty context gave %v", h)
	}
	in := http.Header{}
	in.Set("Traceparent", "00-abc-def-01")
	in.Set("X-Request-Id", "r1")
	in.Set("Cookie", "secret")
	ctx := WithForwardHeaders(context.Background(), in)
	got := HeadersFromContext(ctx)
	if got.Get("Traceparent") != "00-abc-def-01" || got.Get("X-Request-ID") != "r1" {
		t.Errorf("headers = %v", got)
	}
	if got.Get("Cookie") != "" {
		t.Error("non-forwarded header kept")
	}
}
