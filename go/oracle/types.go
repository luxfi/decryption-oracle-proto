// Package oracle provides types and HTTP client for the decryption oracle service.
// Uses native Go structs with JSON encoding instead of protobuf/grpc.
package oracle

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// EncryptedType represents the FHE encrypted value type.
type EncryptedType int

const (
	Uint8   EncryptedType = 0
	Uint16  EncryptedType = 1
	Uint32  EncryptedType = 2
	Uint64  EncryptedType = 3
	Uint128 EncryptedType = 4
	Uint256 EncryptedType = 5
)

func (t EncryptedType) String() string {
	switch t {
	case Uint8:
		return "Uint8"
	case Uint16:
		return "Uint16"
	case Uint32:
		return "Uint32"
	case Uint64:
		return "Uint64"
	case Uint128:
		return "Uint128"
	case Uint256:
		return "Uint256"
	default:
		return fmt.Sprintf("EncryptedType(%d)", t)
	}
}

// FheEncrypted holds FHE-encrypted data.
type FheEncrypted struct {
	Data []byte        `json:"data"`
	Type EncryptedType `json:"type"`
}

// MarshalJSON encodes Data as base64.
func (f FheEncrypted) MarshalJSON() ([]byte, error) {
	type alias struct {
		Data string        `json:"data"`
		Type EncryptedType `json:"type"`
	}
	return json.Marshal(alias{
		Data: base64.StdEncoding.EncodeToString(f.Data),
		Type: f.Type,
	})
}

// UnmarshalJSON decodes Data from base64.
func (f *FheEncrypted) UnmarshalJSON(data []byte) error {
	type alias struct {
		Data string        `json:"data"`
		Type EncryptedType `json:"type"`
	}
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	decoded, err := base64.StdEncoding.DecodeString(a.Data)
	if err != nil {
		return fmt.Errorf("invalid base64 in data: %w", err)
	}
	f.Data = decoded
	f.Type = a.Type
	return nil
}

// DecryptRequest is a request to decrypt FHE-encrypted data.
type DecryptRequest struct {
	Encrypted FheEncrypted `json:"encrypted"`
	Proof     string       `json:"proof,omitempty"`
}

// DecryptResponse is the decryption result.
type DecryptResponse struct {
	Decrypted string `json:"decrypted"`
	Signature string `json:"signature"`
}

// ReencryptRequest is a request to re-encrypt data for a user's public key.
type ReencryptRequest struct {
	Encrypted     FheEncrypted `json:"encrypted"`
	UserPublicKey string       `json:"user_public_key"`
	Proof         string       `json:"proof,omitempty"`
}

// ReencryptResponse is the re-encryption result.
type ReencryptResponse struct {
	Reencrypted string `json:"reencrypted"`
	Signature   string `json:"signature"`
}

// IsNilRequest checks if an encrypted value is nil.
type IsNilRequest struct {
	Encrypted FheEncrypted `json:"encrypted"`
	Proof     string       `json:"proof,omitempty"`
}

// IsNilResponse is the nil-check result.
type IsNilResponse struct {
	IsNil     bool   `json:"is_nil"`
	Signature string `json:"signature"`
}

// ErrorResponse is returned on API errors.
type ErrorResponse struct {
	Error   string `json:"error"`
	Code    int    `json:"code,omitempty"`
	Details string `json:"details,omitempty"`
}
