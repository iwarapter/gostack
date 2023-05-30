package mw

import (
	"net/http"
	"strings"
)

func XForwardedFor(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get the original client IP address from the request
		remoteIP := getOriginalClientIP(r)

		// Add or update the X-Forwarded-For header
		if forwardedFor := r.Header.Get("X-Forwarded-For"); forwardedFor != "" {
			// Append the original client IP to the existing header
			r.Header.Set("X-Forwarded-For", forwardedFor+", "+remoteIP)
		} else {
			// Set the X-Forwarded-For header with the original client IP
			r.Header.Set("X-Forwarded-For", remoteIP)
		}

		// Call the next handler in the chain
		next.ServeHTTP(w, r)
	})
}

func getOriginalClientIP(r *http.Request) string {
	// Get the X-Forwarded-For header value
	forwardedFor := r.Header.Get("X-Forwarded-For")

	// Split the header value by comma to get the original client IP
	ips := strings.Split(forwardedFor, ",")
	if len(ips) > 0 && ips[0] != "" {
		// Return the first IP as the original client IP
		return strings.TrimSpace(ips[0])
	}

	// If the X-Forwarded-For header is not set or empty, return the remote address
	return strings.Split(r.RemoteAddr, ":")[0]
}
