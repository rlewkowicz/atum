package provider

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxResponseBytes = 2 << 20
const maxDiagnosticBytes = 512

type terminalError struct{ message string }

func (e *terminalError) Error() string { return e.message }

func Conflict(format string, values ...any) error {
	return &terminalError{message: fmt.Sprintf(format, values...)}
}

func IsTerminal(err error) bool {
	var target *terminalError
	return errors.As(err, &target)
}

type Client struct {
	baseURL string
	auth    authentication
	http    *http.Client
}

type authenticationKind uint8

const (
	anonymousAuthentication authenticationKind = iota
	keycloakBearerAuthentication
	vaultTokenAuthentication
)

type authentication struct {
	kind  authenticationKind
	token string
}

func anonymous() authentication {
	return authentication{kind: anonymousAuthentication}
}

func keycloakBearer(token string) authentication {
	return authentication{kind: keycloakBearerAuthentication, token: token}
}

func vaultToken(token string) authentication {
	return authentication{kind: vaultTokenAuthentication, token: token}
}

func newClient(baseURL string, auth authentication, ca []byte) (*Client, error) {
	switch auth.kind {
	case anonymousAuthentication:
		if auth.token != "" {
			return nil, errors.New("anonymous provider authentication cannot carry a token")
		}
	case keycloakBearerAuthentication, vaultTokenAuthentication:
		if auth.token == "" {
			return nil, errors.New("authenticated provider client requires a token")
		}
	default:
		return nil, errors.New("unsupported provider authentication")
	}
	endpoint, err := url.Parse(baseURL)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" ||
		endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return nil, errors.New("provider endpoint must be an absolute HTTPS URL")
	}
	pool := x509.NewCertPool()
	if len(ca) == 0 || !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("provider CA bundle contains no certificate")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
	transport.MaxIdleConns = 8
	transport.MaxIdleConnsPerHost = 4
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		auth:    auth,
		http: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func (c *Client) CloseIdleConnections() { c.http.CloseIdleConnections() }

func (c *Client) JSON(ctx context.Context, method, path string, input, output any, accepted ...int) error {
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return fmt.Errorf("encode provider request: %w", err)
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return fmt.Errorf("create provider request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	c.authenticate(request)
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("%s: %w", operation(method, path), err)
	}
	defer response.Body.Close()
	ok := response.StatusCode >= 200 && response.StatusCode < 300
	if len(accepted) != 0 {
		ok = false
		for _, status := range accepted {
			if response.StatusCode == status {
				ok = true
				break
			}
		}
	}
	data, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if readErr != nil {
		return fmt.Errorf("read %s response: %w", operation(method, path), readErr)
	}
	if len(data) > maxResponseBytes {
		return fmt.Errorf("%s response exceeds %d bytes", operation(method, path), maxResponseBytes)
	}
	if !ok {
		return fmt.Errorf("%s returned HTTP %d", operation(method, path), response.StatusCode)
	}
	if output != nil && len(data) != 0 {
		if err := json.Unmarshal(data, output); err != nil {
			return fmt.Errorf("decode %s response: %w", operation(method, path), err)
		}
	}
	return nil
}

func (c *Client) authenticate(request *http.Request) {
	switch c.auth.kind {
	case keycloakBearerAuthentication:
		request.Header.Set("Authorization", "Bearer "+c.auth.token)
	case vaultTokenAuthentication:
		request.Header.Set("X-Vault-Token", c.auth.token)
	}
}

func (c *Client) Form(ctx context.Context, path string, values url.Values, output any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, strings.NewReader(values.Encode()))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("%s: %w", operation(http.MethodPost, path), err)
	}
	defer response.Body.Close()
	data, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if readErr != nil {
		return fmt.Errorf("read %s response: %w", operation(http.MethodPost, path), readErr)
	}
	if len(data) > maxResponseBytes {
		return fmt.Errorf("%s response exceeds %d bytes", operation(http.MethodPost, path), maxResponseBytes)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("%s returned HTTP %d", operation(http.MethodPost, path), response.StatusCode)
	}
	if err := json.Unmarshal(data, output); err != nil {
		return fmt.Errorf("decode %s response: %w", operation(http.MethodPost, path), err)
	}
	return nil
}

func operation(method, path string) string {
	value := method + " " + path
	value = strings.Map(func(character rune) rune {
		if character < ' ' || character == '\u007f' {
			return ' '
		}
		return character
	}, value)
	if len(value) > maxDiagnosticBytes {
		return value[:maxDiagnosticBytes]
	}
	return value
}
