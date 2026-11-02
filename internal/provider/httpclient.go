package provider

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// newHTTPClient builds the client used for every API call. It requires
// HTTPS unless insecureHTTP is set, enforces TLS 1.2 or later, and trusts
// only caPEM when it is given.
func newHTTPClient(rawURL, caPEM string, insecureHTTP bool, timeout time.Duration) (*http.Client, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("url %q is not an absolute URL", rawURL)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !insecureHTTP {
			return nil, errors.New("url uses http://; the API key would travel in clear text. Use https:// or set insecure_http = true for a local lab")
		}
	default:
		return nil, fmt.Errorf("url scheme must be https, got %q", u.Scheme)
	}
	if u.User != nil {
		return nil, errors.New("url must not contain credentials; use api_key")
	}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if caPEM != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(caPEM)) {
			return nil, errors.New("ca_cert_pem contains no PEM certificates")
		}
		tlsConfig.RootCAs = pool
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig

	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		// Never follow a redirect: it could carry the API key to another host.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}
