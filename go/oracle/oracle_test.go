package oracle

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// mockService implements Service for testing.
type mockService struct{}

func (m *mockService) Decrypt(_ context.Context, req *DecryptRequest) (*DecryptResponse, error) {
	return &DecryptResponse{
		Decrypted: "42",
		Signature: "sig123",
	}, nil
}

func (m *mockService) Reencrypt(_ context.Context, req *ReencryptRequest) (*ReencryptResponse, error) {
	return &ReencryptResponse{
		Reencrypted: "reenc_data",
		Signature:   "sig456",
	}, nil
}

func (m *mockService) AssertIsNil(_ context.Context, req *IsNilRequest) (*IsNilResponse, error) {
	return &IsNilResponse{
		IsNil:     false,
		Signature: "sig789",
	}, nil
}

func TestJSONRoundTrip(t *testing.T) {
	original := FheEncrypted{
		Data: []byte{0x01, 0x02, 0x03, 0x04},
		Type: Uint64,
	}

	encoded, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded FheEncrypted
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !bytes.Equal(original.Data, decoded.Data) {
		t.Errorf("data mismatch: got %v, want %v", decoded.Data, original.Data)
	}
	if original.Type != decoded.Type {
		t.Errorf("type mismatch: got %v, want %v", decoded.Type, original.Type)
	}
}

func TestEncryptedTypeString(t *testing.T) {
	tests := []struct {
		t    EncryptedType
		want string
	}{
		{Uint8, "Uint8"},
		{Uint16, "Uint16"},
		{Uint32, "Uint32"},
		{Uint64, "Uint64"},
		{Uint128, "Uint128"},
		{Uint256, "Uint256"},
	}
	for _, tt := range tests {
		if got := tt.t.String(); got != tt.want {
			t.Errorf("EncryptedType(%d).String() = %q, want %q", tt.t, got, tt.want)
		}
	}
}

func TestHandler(t *testing.T) {
	mux := http.NewServeMux()
	h := NewHandler(&mockService{})
	h.RegisterRoutes(mux)

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := NewClient(srv.URL)

	t.Run("Decrypt", func(t *testing.T) {
		resp, err := client.Decrypt(context.Background(), &DecryptRequest{
			Encrypted: FheEncrypted{Data: []byte{1, 2, 3}, Type: Uint32},
		})
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
		if resp.Decrypted != "42" {
			t.Errorf("Decrypted = %q, want %q", resp.Decrypted, "42")
		}
	})

	t.Run("Reencrypt", func(t *testing.T) {
		resp, err := client.Reencrypt(context.Background(), &ReencryptRequest{
			Encrypted:     FheEncrypted{Data: []byte{1, 2, 3}, Type: Uint32},
			UserPublicKey: "pubkey",
		})
		if err != nil {
			t.Fatalf("Reencrypt: %v", err)
		}
		if resp.Reencrypted != "reenc_data" {
			t.Errorf("Reencrypted = %q, want %q", resp.Reencrypted, "reenc_data")
		}
	})

	t.Run("AssertIsNil", func(t *testing.T) {
		resp, err := client.AssertIsNil(context.Background(), &IsNilRequest{
			Encrypted: FheEncrypted{Data: []byte{1, 2, 3}, Type: Uint32},
		})
		if err != nil {
			t.Fatalf("AssertIsNil: %v", err)
		}
		if resp.IsNil != false {
			t.Errorf("IsNil = %v, want %v", resp.IsNil, false)
		}
	})
}
