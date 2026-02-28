use crate::error::{HermesError, Result};
use sp_core::crypto::AccountId32;
use subxt::dynamic::Value;

/// Base58 alphabet used by SS58 encoding.
const BASE58_CHARS: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// A mapped profile for an external Hippius node.
#[derive(Clone, Debug)]
pub struct AccountProfile {
    pub node_id: Vec<u8>,
    pub encryption_key: Vec<u8>,
}

impl scale_decode::IntoVisitor for AccountProfile {
    type Visitor = AccountProfileVisitor;
    fn into_visitor() -> Self::Visitor {
        AccountProfileVisitor
    }
}

pub struct AccountProfileVisitor;

impl scale_decode::Visitor for AccountProfileVisitor {
    type Value<'scale, 'info> = AccountProfile;
    type Error = scale_decode::Error;

    fn visit_composite<'scale, 'info>(
        self,
        value: &mut scale_decode::visitor::types::Composite<'scale, 'info>,
        _type_id: scale_decode::visitor::TypeId,
    ) -> std::result::Result<Self::Value<'scale, 'info>, Self::Error> {
        // A composite (struct) with two fields in order: node_id, encryption_key
        // Both are `Vec<u8>` which maps to `Vec<u8>` Decode.

        let node_id_val = value.next().ok_or_else(|| {
            scale_decode::Error::custom_string("Missing node_id field".to_string())
        })??;
        let node_id = node_id_val.decode_as_type::<Vec<u8>>()?;

        let encryption_key_val = value.next().ok_or_else(|| {
            scale_decode::Error::custom_string("Missing encryption_key field".to_string())
        })??;
        let encryption_key = encryption_key_val.decode_as_type::<Vec<u8>>()?;

        Ok(AccountProfile {
            node_id,
            encryption_key,
        })
    }
}

/// Validates that a string looks like a plausible SS58 address.
///
/// Checks length (46-48 chars) and Base58 character set. Does not verify the checksum
/// (that requires the full ss58-registry crate).
pub fn validate_ss58(address: &str) -> Result<()> {
    if address.is_empty() {
        return Err(HermesError::InvalidSs58("empty address".into()));
    }
    if address.len() < 46 || address.len() > 48 {
        return Err(HermesError::InvalidSs58(format!(
            "length {} outside valid range 46-48",
            address.len()
        )));
    }
    for (i, byte) in address.bytes().enumerate() {
        if !BASE58_CHARS.contains(&byte) {
            return Err(HermesError::InvalidSs58(format!(
                "invalid character '{}' at position {}",
                byte as char, i
            )));
        }
    }
    Ok(())
}

/// Resolves an SS58 address into an AccountProfile by querying the Hippius blockchain.
pub async fn resolve_profile(rpc_url: &str, ss58: &str) -> Result<AccountProfile> {
    validate_ss58(ss58)?;

    use sp_core::crypto::Ss58Codec;
    let account_id = AccountId32::from_ss58check(ss58)
        .map_err(|e| HermesError::Identity(format!("Invalid SS58 address format: {:?}", e)))?;

    let client = crate::online_client::connect(rpc_url).await?;

    // Create a dynamic storage query for AccountProfile::AccountProfiles(AccountId32)
    let storage_query = subxt::dynamic::storage(
        "AccountProfile",
        "AccountProfiles",
        vec![Value::from_bytes(<AccountId32 as AsRef<[u8; 32]>>::as_ref(
            &account_id,
        ))],
    );

    let result = client
        .storage()
        .at_latest()
        .await
        .map_err(|e| {
            HermesError::Identity(format!("Failed to target latest blockchain state: {}", e))
        })?
        .fetch(&storage_query)
        .await
        .map_err(|e| {
            HermesError::Identity(format!("Failed to query storage for AccountProfile: {}", e))
        })?;

    if let Some(encoded_profile) = result {
        let profile = encoded_profile.as_type::<AccountProfile>().map_err(|e| {
            HermesError::Identity(format!(
                "Failed to decode AccountProfile SCALE bytes: {}",
                e
            ))
        })?;
        Ok(profile)
    } else {
        Err(HermesError::Identity(format!(
            "No AccountProfile found on blockchain for SS58 '{}'",
            ss58
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_ss58_valid() {
        // Alice's well-known SS58 address (48 chars)
        assert!(validate_ss58("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY").is_ok());
    }

    #[test]
    fn test_validate_ss58_empty() {
        assert!(validate_ss58("").is_err());
    }

    #[test]
    fn test_validate_ss58_too_short() {
        assert!(validate_ss58("5GrwvaEF").is_err());
    }

    #[test]
    fn test_validate_ss58_invalid_chars() {
        // 'O' and '0' are not in Base58, but '0' is not in base58 either
        // Let's use a char definitely not in Base58: 'I', 'l', '0', 'O'
        let mut bad = String::from("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQ0");
        assert!(validate_ss58(&bad).is_err());

        bad = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQO".to_string();
        assert!(validate_ss58(&bad).is_err());
    }

    #[test]
    fn test_validate_ss58_46_chars() {
        // 46 chars is the minimum valid length
        let addr = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKut";
        assert_eq!(addr.len(), 46);
        assert!(validate_ss58(addr).is_ok());
    }
}
