//! Decryption oracle types with JSON serialization.
//!
//! Provides native Rust structs for the decryption oracle API,
//! using serde for JSON encoding instead of protobuf/grpc.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// FHE encrypted value type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum EncryptedType {
    Uint8 = 0,
    Uint16 = 1,
    Uint32 = 2,
    Uint64 = 3,
    Uint128 = 4,
    Uint256 = 5,
}

impl EncryptedType {
    pub fn as_str(&self) -> &'static str {
        match self {
            EncryptedType::Uint8 => "Uint8",
            EncryptedType::Uint16 => "Uint16",
            EncryptedType::Uint32 => "Uint32",
            EncryptedType::Uint64 => "Uint64",
            EncryptedType::Uint128 => "Uint128",
            EncryptedType::Uint256 => "Uint256",
        }
    }
}

/// FHE-encrypted data with type information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FheEncrypted {
    pub data: Vec<u8>,
    pub r#type: EncryptedType,
}

impl Serialize for FheEncrypted {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Helper {
            data: String,
            r#type: EncryptedType,
        }
        Helper {
            data: BASE64.encode(&self.data),
            r#type: self.r#type,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for FheEncrypted {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Helper {
            data: String,
            r#type: EncryptedType,
        }
        let h = Helper::deserialize(deserializer)?;
        let data = BASE64
            .decode(&h.data)
            .map_err(serde::de::Error::custom)?;
        Ok(FheEncrypted { data, r#type: h.r#type })
    }
}

/// Request to decrypt FHE-encrypted data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecryptRequest {
    pub encrypted: FheEncrypted,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub proof: String,
}

/// Decryption result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecryptResponse {
    pub decrypted: String,
    pub signature: String,
}

/// Request to re-encrypt data for a user's public key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReencryptRequest {
    pub encrypted: FheEncrypted,
    pub user_public_key: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub proof: String,
}

/// Re-encryption result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReencryptResponse {
    pub reencrypted: String,
    pub signature: String,
}

/// Request to check if an encrypted value is nil.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IsNilRequest {
    pub encrypted: FheEncrypted,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub proof: String,
}

/// Nil-check result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IsNilResponse {
    pub is_nil: bool,
    pub signature: String,
}

/// Error response from the oracle API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_roundtrip() {
        let original = FheEncrypted {
            data: vec![0x01, 0x02, 0x03, 0x04],
            r#type: EncryptedType::Uint64,
        };

        let json = serde_json::to_string(&original).unwrap();
        let decoded: FheEncrypted = serde_json::from_str(&json).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_decrypt_request() {
        let req = DecryptRequest {
            encrypted: FheEncrypted {
                data: vec![1, 2, 3],
                r#type: EncryptedType::Uint32,
            },
            proof: String::new(),
        };

        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains("proof")); // empty proof is skipped

        let decoded: DecryptRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req.encrypted, decoded.encrypted);
    }

    #[test]
    fn test_encrypted_type() {
        assert_eq!(EncryptedType::Uint8.as_str(), "Uint8");
        assert_eq!(EncryptedType::Uint256.as_str(), "Uint256");
    }
}
