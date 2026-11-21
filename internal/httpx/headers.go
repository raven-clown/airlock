// Package httpx holds airlock's HTTP plumbing: forwarded headers, the listener and health routes.
package httpx

import (
	"context"
	"net/http"
)

// Forwarded lists the headers passed on to HTTP backends on every call.
var Forwarded = []string{"Traceparent", "Tracestate", "X-Request-Id"}

type headersKey struct{}

// WithForwardHeaders stores the forwarded subset of h in ctx.
func WithForwardHeaders(ctx context.Context, h http.Header) context.Context {
	out := http.Header{}
	for _, k := range Forwarded {
		if v := h.Get(k); v != "" {
			out.Set(k, v)
		}
	}
	return context.WithValue(ctx, headersKey{}, out)
}

// WithTraceparent returns ctx with the forwarded traceparent replaced by tp, so a backend
// call continues the trace under airlock's own span. An empty tp changes nothing.
func WithTraceparent(ctx context.Context, tp string) context.Context {
	if tp == "" {
		return ctx
	}
	out := HeadersFromContext(ctx).Clone()
	if out == nil {
		out = http.Header{}
	}
	out.Set("Traceparent", tp)
	return context.WithValue(ctx, headersKey{}, out)
}

// HeadersFromContext returns the headers stored by WithForwardHeaders.
func HeadersFromContext(ctx context.Context) http.Header {
	h, _ := ctx.Value(headersKey{}).(http.Header)
	return h
}
