// Package idanalyzer is the official Go client library for the ID Analyzer API v2.
//
// It targets the load-balanced api2.idanalyzer.com fleet (US, default) or
// api2-eu.idanalyzer.com (EU). Create a client with NewClient and use the
// service fields (Scanner, Biometric, AML, Contract, Transaction, Docupass,
// Profile, Webhook, Account).
package idanalyzer

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// regionEndpoints maps a region code to its API base URL.
var regionEndpoints = map[string]string{
	"us": "https://api2.idanalyzer.com",
	"eu": "https://api2-eu.idanalyzer.com",
}

// APIError is returned when the API responds with an error object.
type APIError struct {
	Code    string
	Message string
}

func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("idanalyzer api error (%s): %s", e.Code, e.Message)
	}
	return "idanalyzer api error: " + e.Message
}

// InvalidArgumentError is returned for invalid client-side arguments.
type InvalidArgumentError struct{ Message string }

func (e *InvalidArgumentError) Error() string { return e.Message }

func invalid(msg string) error { return &InvalidArgumentError{Message: msg} }

// Client is an ID Analyzer API v2 client.
type Client struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client

	Scanner     *ScannerService
	Biometric   *BiometricService
	AML         *AMLService
	Contract    *ContractService
	Transaction *TransactionService
	Docupass    *DocupassService
	Profile     *ProfileService
	Webhook     *WebhookService
	Account     *AccountService
}

// Option configures a Client.
type Option func(*Client) error

// WithRegion sets the API region ("us" or "eu"). Overrides IDANALYZER_REGION.
func WithRegion(region string) Option {
	return func(c *Client) error {
		base, ok := regionEndpoints[strings.ToLower(region)]
		if !ok {
			return invalid(fmt.Sprintf("invalid region %q, valid regions are: eu, us", region))
		}
		c.baseURL = base
		return nil
	}
}

// WithBaseURL overrides the API base URL entirely (e.g. for an on-premise ID Fort host).
func WithBaseURL(baseURL string) Option {
	return func(c *Client) error {
		c.baseURL = strings.TrimRight(baseURL, "/")
		return nil
	}
}

// WithHTTPClient sets a custom *http.Client.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) error {
		c.httpClient = h
		return nil
	}
}

// NewClient creates a new client. The API key falls back to the IDANALYZER_KEY
// environment variable. The region falls back to IDANALYZER_REGION (default "us").
func NewClient(apiKey string, opts ...Option) (*Client, error) {
	if apiKey == "" {
		apiKey = os.Getenv("IDANALYZER_KEY")
	}
	if apiKey == "" {
		return nil, invalid("API key required (pass it to NewClient or set IDANALYZER_KEY)")
	}

	c := &Client{
		apiKey:     apiKey,
		httpClient: &http.Client{Timeout: 80 * time.Second},
	}

	// Default region from env (or us).
	region := strings.ToLower(os.Getenv("IDANALYZER_REGION"))
	if region == "" {
		region = "us"
	}
	base, ok := regionEndpoints[region]
	if !ok {
		return nil, invalid(fmt.Sprintf("invalid IDANALYZER_REGION %q, valid regions are: eu, us", region))
	}
	c.baseURL = base

	for _, opt := range opts {
		if err := opt(c); err != nil {
			return nil, err
		}
	}

	c.Scanner = &ScannerService{c}
	c.Biometric = &BiometricService{c}
	c.AML = &AMLService{c}
	c.Contract = &ContractService{c}
	c.Transaction = &TransactionService{c}
	c.Docupass = &DocupassService{c}
	c.Profile = &ProfileService{c}
	c.Webhook = &WebhookService{c}
	c.Account = &AccountService{c}
	return c, nil
}

func (c *Client) endpoint(uri string) string {
	if len(uri) >= 4 && strings.EqualFold(uri[:4], "http") {
		return uri
	}
	return c.baseURL + "/" + uri
}

// doJSON issues a request with an optional JSON body and decodes the JSON response.
func (c *Client) doJSON(method, uri string, body map[string]any, query url.Values) (map[string]any, error) {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(b)
	}

	full := c.endpoint(uri)
	if len(query) > 0 {
		full += "?" + query.Encode()
	}

	req, err := http.NewRequest(method, full, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Api-Key", c.apiKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if len(data) > 0 {
		if err := json.Unmarshal(data, &out); err != nil {
			return nil, fmt.Errorf("idanalyzer: failed to decode response: %w", err)
		}
	}
	if out != nil {
		if e, ok := out["error"].(map[string]any); ok {
			ae := &APIError{}
			if m, ok := e["message"].(string); ok {
				ae.Message = m
			}
			if code, ok := e["code"]; ok {
				ae.Code = fmt.Sprintf("%v", code)
			}
			return out, ae
		}
	}
	return out, nil
}

// download issues a GET and writes the raw response body to dest.
func (c *Client) download(uri, dest string) error {
	req, err := http.NewRequest(http.MethodGet, c.endpoint(uri), nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Api-Key", c.apiKey)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}

// ParseInput accepts a file path, base64 string, URL, or (when allowCache) a
// "ref:" cache reference, and returns the value to send to the API.
func ParseInput(input string, allowCache bool) (string, error) {
	if allowCache && strings.HasPrefix(input, "ref:") {
		return input, nil
	}
	if u, err := url.ParseRequestURI(input); err == nil && (u.Scheme == "http" || u.Scheme == "https") {
		return input, nil
	}
	if info, err := os.Stat(input); err == nil && !info.IsDir() {
		data, err := os.ReadFile(input)
		if err != nil {
			return "", err
		}
		return base64.StdEncoding.EncodeToString(data), nil
	}
	if len(input) > 100 {
		return input, nil
	}
	return "", invalid("invalid input image, file not found or malformed URL")
}
