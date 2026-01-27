package oracle

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client is an HTTP client for the decryption oracle service.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a new oracle client.
func NewClient(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// NewClientWithHTTP creates a client with a custom HTTP client.
func NewClientWithHTTP(baseURL string, httpClient *http.Client) *Client {
	return &Client{
		baseURL:    baseURL,
		httpClient: httpClient,
	}
}

func (c *Client) post(ctx context.Context, path string, req, resp any) error {
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	defer httpResp.Body.Close()

	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if httpResp.StatusCode >= 400 {
		var errResp ErrorResponse
		if json.Unmarshal(respBody, &errResp) == nil && errResp.Error != "" {
			return fmt.Errorf("oracle error %d: %s", httpResp.StatusCode, errResp.Error)
		}
		return fmt.Errorf("oracle error %d: %s", httpResp.StatusCode, string(respBody))
	}

	if err := json.Unmarshal(respBody, resp); err != nil {
		return fmt.Errorf("unmarshal response: %w", err)
	}
	return nil
}

// Decrypt decrypts FHE-encrypted data.
func (c *Client) Decrypt(ctx context.Context, req *DecryptRequest) (*DecryptResponse, error) {
	var resp DecryptResponse
	if err := c.post(ctx, "/decrypt", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Reencrypt re-encrypts data for a user's public key.
func (c *Client) Reencrypt(ctx context.Context, req *ReencryptRequest) (*ReencryptResponse, error) {
	var resp ReencryptResponse
	if err := c.post(ctx, "/reencrypt", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// AssertIsNil checks if an encrypted value is nil.
func (c *Client) AssertIsNil(ctx context.Context, req *IsNilRequest) (*IsNilResponse, error) {
	var resp IsNilResponse
	if err := c.post(ctx, "/assert-is-nil", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
