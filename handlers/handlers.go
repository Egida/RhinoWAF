package handlers

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
)

// Backend server URL
const backendURL = "http://localhost:9000"

// ReverseProxy handles proxying requests to the backend
var proxy *httputil.ReverseProxy

func init() {
	target, _ := url.Parse(backendURL)
	proxy = httputil.NewSingleHostReverseProxy(target)
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		fmt.Fprintf(w, "Backend unavailable: %v", err)
	}
}

// ProxyToBackend forwards requests to the backend application
func ProxyToBackend(w http.ResponseWriter, r *http.Request) {
	// Add headers to indicate the request passed through WAF
	r.Header.Set("X-Protected-By", "RhinoWAF-v2.0")
	r.Header.Set("X-WAF-Status", "PASSED")

	// Proxy the request
	proxy.ServeHTTP(w, r)
}

func Home(w http.ResponseWriter, r *http.Request) {
	ProxyToBackend(w, r)
}

func Login(w http.ResponseWriter, r *http.Request) {
	user := r.FormValue("user")
	_ = r.FormValue("pass") // Using pass variable to avoid unused warning
	fmt.Fprintf(w, "Login sanitized: %s", user)
}

func Echo(w http.ResponseWriter, r *http.Request) {
	msg := r.FormValue("msg")
	fmt.Fprintf(w, "Echo sanitized: %s", msg)
}

func Flood(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Flood endpoint.")
}

// API endpoints that proxy to backend
func APIHandler(w http.ResponseWriter, r *http.Request) {
	ProxyToBackend(w, r)
}

func AboutHandler(w http.ResponseWriter, r *http.Request) {
	ProxyToBackend(w, r)
}

func ContactHandler(w http.ResponseWriter, r *http.Request) {
	ProxyToBackend(w, r)
}
