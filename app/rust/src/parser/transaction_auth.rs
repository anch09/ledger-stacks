use nom::number::complete::le_u8;

use crate::check_canary;
use crate::parser::{
    error::ParserError,
    parser_common::{HashMode, SignerId},
    spending_condition::{
        SpendingConditionSigner, TransactionAuthField, TransactionSpendingCondition,
    },
};

// The sponsor sentinel length that includes:
// 21-byte pub_key hash
// 16-byte fee and nonce
// 66-byte signature and signature encoding
const SPONSOR_SENTINEL_LEN: usize = 21 + 16 + 66;

/// A Transaction's Authorization structure
///
/// this structure contains the address of the origin account,
/// signature(s) and signature threshold for the origin account
#[repr(C)]
#[derive(PartialEq, Clone)]
#[cfg_attr(test, derive(Debug))]
pub enum TransactionAuth<'a> {
    // 0x04
    Standard(TransactionSpendingCondition<'a>),
    // 0x05 the second account pays on behalf of the first account
    Sponsored(
        TransactionSpendingCondition<'a>,
        TransactionSpendingCondition<'a>,
    ),
}

impl<'a> TransactionAuth<'a> {
    #[inline(never)]
    pub fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&'a [u8], Self, ParserError> {
        let auth_type = le_u8(bytes)?;
        let auth = match auth_type.1 {
            0x04 => Self::standard_from_bytes(auth_type.0)?,
            0x05 => Self::sponsored_from_bytes(auth_type.0)?,
            _ => return Err(nom::Err::Error(ParserError::InvalidAuthType)),
        };
        Ok(auth)
    }

    #[inline(never)]
    fn standard_from_bytes(bytes: &'a [u8]) -> nom::IResult<&'a [u8], Self, ParserError> {
        let standard = TransactionSpendingCondition::from_bytes(bytes)?;
        check_canary!();
        Ok((standard.0, Self::Standard(standard.1)))
    }

    #[inline(never)]
    fn sponsored_from_bytes(bytes: &'a [u8]) -> nom::IResult<&'a [u8], Self, ParserError> {
        let standard = TransactionSpendingCondition::from_bytes(bytes)?;
        let sponsored = TransactionSpendingCondition::from_bytes(standard.0)?;
        check_canary!();
        Ok((sponsored.0, Self::Sponsored(standard.1, sponsored.1)))
    }

    #[inline(never)]
    pub fn is_standard_auth(&self) -> bool {
        matches!(*self, Self::Standard(_))
    }

    // check just for origin, meaning we support standard transaction only
    pub fn is_multisig(&self) -> bool {
        match self {
            Self::Standard(origin) => origin.is_multisig(),
            Self::Sponsored(origin, _) => origin.is_multisig(),
        }
    }

    // check just for origin, meaning we support standard transaction only
    pub fn hash_mode(&self) -> Result<HashMode, ParserError> {
        match self {
            Self::Standard(origin) => origin.hash_mode(),
            Self::Sponsored(origin, _) => origin.hash_mode(),
        }
    }

    // check just for origin, meaning we support standard transaction only
    pub fn num_auth_fields(&self) -> Option<u32> {
        match self {
            Self::Standard(origin) => origin.num_auth_fields(),
            Self::Sponsored(origin, _) => origin.num_auth_fields(),
        }
    }

    // check just for origin, meaning we support standard transaction only
    pub fn get_auth_field(&self, index: u32) -> Option<Result<TransactionAuthField<'_>, ParserError>> {
        match self {
            Self::Standard(origin) => origin.get_auth_field(index),
            Self::Sponsored(origin, _) => origin.get_auth_field(index),
        }
    }

    #[inline(always)]
    pub fn origin(&self) -> &SpendingConditionSigner<'_> {
        match self {
            Self::Standard(ref origin) | Self::Sponsored(ref origin, _) => &origin.signer,
        }
    }

    #[inline(always)]
    pub fn sponsor(&self) -> Option<&SpendingConditionSigner<'_>> {
        match self {
            Self::Sponsored(_, ref sponsor) => Some(&sponsor.signer),
            _ => None,
        }
    }

    pub fn num_spending_conditions(&self) -> u8 {
        if self.is_standard_auth() {
            1
        } else {
            2
        }
    }

    pub fn origin_fee(&self) -> u64 {
        match self {
            Self::Standard(ref origin) => origin.fee(),
            Self::Sponsored(ref origin, _) => origin.fee(),
        }
    }

    pub fn origin_nonce(&self) -> u64 {
        match self {
            Self::Standard(ref origin) => origin.nonce(),
            Self::Sponsored(ref origin, _) => origin.nonce(),
        }
    }

    pub fn sponsor_fee(&self) -> Option<u64> {
        match self {
            Self::Standard(_) => None,
            Self::Sponsored(_, ref sponsor) => Some(sponsor.fee()),
        }
    }

    pub fn sponsor_nonce(&self) -> Option<u64> {
        match self {
            Self::Standard(_) => None,
            Self::Sponsored(_, ref sponsor) => Some(sponsor.nonce()),
        }
    }

    pub fn check_signer(&self, signer_pk: &[u8]) -> SignerId {
        match self {
            Self::Standard(ref origin) => {
                // Multisig support just for non sponsored transactions
                if signer_pk == origin.signer_pub_key_hash() || origin.is_multisig() {
                    return SignerId::Origin;
                }
            }
            Self::Sponsored(ref origin, ref sponsor) => {
                if signer_pk == origin.signer_pub_key_hash() {
                    return SignerId::Origin;
                } else if signer_pk == sponsor.signer_pub_key_hash() {
                    return SignerId::Sponsor;
                }
            }
        }
        SignerId::Invalid
    }

    pub fn initial_sighash_auth(&self, buf: &mut [u8]) -> Result<usize, ParserError> {
        match self {
            Self::Standard(ref origin) => origin.init_sighash(buf),
            Self::Sponsored(ref origin, _) => {
                let len = origin.init_sighash(buf)?;
                let sentinel_len = TransactionAuth::write_sponsor_sentinel(&mut buf[len..])?;
                Ok(len + sentinel_len)
            }
        }
    }

    pub fn write_sponsor_sentinel(buf: &mut [u8]) -> Result<usize, ParserError> {
        if buf.len() < SPONSOR_SENTINEL_LEN {
            return Err(ParserError::NoData);
        }
        buf.iter_mut()
            .take(SPONSOR_SENTINEL_LEN)
            .for_each(|v| *v = 0);

        Ok(SPONSOR_SENTINEL_LEN)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::prelude::v1::*;

    // Expected lengths for singlesig spending conditions
    // Origin init_sighash: 16-byte nonce+fee + 66-byte signature = 82 bytes
    const ORIGIN_SINGLESIG_INIT_LEN: usize = 82;
    // Sponsor sentinel: 21-byte (hash_mode + pubkey_hash) + 16-byte nonce+fee + 66-byte signature = 103 bytes
    const EXPECTED_SPONSOR_SENTINEL_LEN: usize = 103;

    #[test]
    fn test_standard_singlesig_initial_sighash_auth() {
        // Standard singlesig transaction auth (P2PKH)
        let auth_bytes: Vec<u8> = vec![
            0x04, // auth type: standard
            0x00, // hash mode: P2PKH
            // signer pubkey hash (20 bytes)
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // nonce (8 bytes)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            // fee (8 bytes)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb4,
            // key encoding + signature (66 bytes)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];

        let (_, auth) = TransactionAuth::from_bytes(&auth_bytes).unwrap();
        assert!(auth.is_standard_auth());

        let mut buf = [0xFFu8; 256];
        let len = auth.initial_sighash_auth(&mut buf).unwrap();

        assert_eq!(len, ORIGIN_SINGLESIG_INIT_LEN);
        assert!(buf[..len].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_sponsor_sentinel_constant() {
        // Verify the sponsor sentinel length constant is correct
        // hash_mode(1) + pubkey_hash(20) + nonce(8) + fee(8) + key_encoding(1) + signature(65)
        assert_eq!(SPONSOR_SENTINEL_LEN, 1 + 20 + 8 + 8 + 1 + 65);
        assert_eq!(SPONSOR_SENTINEL_LEN, 103);
    }

    /// Test Scenario 1: Origin signs first (sponsor hasn't signed yet)
    /// 
    /// When the origin (spender) signs a sponsored transaction BEFORE the sponsor,
    /// the transaction contains a "sponsor sentinel" - all zeros for the sponsor's
    /// spending condition. The origin's presig hash must include this sentinel.
    /// 
    /// This test verifies that initial_sighash_auth produces the correct output
    /// for computing the origin's presig hash.
    #[test]
    fn test_origin_signs_sponsored_tx_before_sponsor() {
        // Full sponsored transaction from sponsored_contract_call_testnet.json
        // This represents a tx where the origin has signed but sponsor sentinel is used
        let full_tx_hex = "808000000005002d89de56fd4db19741957831926e9ba96cf04158000000000000000000000000000000000001c88dc2ad9b081db525b68a04a4e9a021f05d6c8500b43ff01360f255826f3676636bcd0494a55bfd529028fe8c1b1e93ad23b75c31b29cee369d8bf5f643d478003b471808467d33eec688b7a7a75f06aad921ba6e0000000000000000000000000000000000001fc1ecc42a7b62598a6969cc0af77d81992839e203946867e603d4d8d2a3653a7efc00d16423b035f82d5550f26d3d59205b0cf578a93618c3eb7f50dc12f73c030200000000021a143e543243dfcd8c02a12ad7ea371bd07bc91df90b68656c6c6f2d776f726c64077365742d6261720000000200000000000000000000000000000000060000000000000000000000000000000002";
        let _full_tx = hex::decode(full_tx_hex).unwrap();

        // Parse just the auth portion (starts at byte 4 after version+chain_id)
        // version (1) + chain_id (4) = 5 bytes, but we need to parse transaction
        // For this test, let's just parse the auth directly
        
        // Auth bytes extracted from the transaction (after version byte and chain_id)
        let auth_bytes: Vec<u8> = vec![
            0x05, // sponsored auth type
            // === ORIGIN SPENDING CONDITION ===
            0x00, // hash mode: P2PKH
            // origin signer pubkey hash (20 bytes)
            0x2d, 0x89, 0xde, 0x56, 0xfd, 0x4d, 0xb1, 0x97, 0x41, 0x95,
            0x78, 0x31, 0x92, 0x6e, 0x9b, 0xa9, 0x6c, 0xf0, 0x41, 0x58,
            // origin nonce (8 bytes) = 0
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // origin fee (8 bytes) = 0
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // origin key encoding (1 byte)
            0x00,
            // origin signature (65 bytes)
            0x01, 0xc8, 0x8d, 0xc2, 0xad, 0x9b, 0x08, 0x1d,
            0xb5, 0x25, 0xb6, 0x8a, 0x04, 0xa4, 0xe9, 0xa0,
            0x21, 0xf0, 0x5d, 0x6c, 0x85, 0x00, 0xb4, 0x3f,
            0xf0, 0x13, 0x60, 0xf2, 0x55, 0x82, 0x6f, 0x36,
            0x76, 0x63, 0x6b, 0xcd, 0x04, 0x94, 0xa5, 0x5b,
            0xfd, 0x52, 0x90, 0x28, 0xfe, 0x8c, 0x1b, 0x1e,
            0x93, 0xad, 0x23, 0xb7, 0x5c, 0x31, 0xb2, 0x9c,
            0xee, 0x36, 0x9d, 0x8b, 0xf5, 0xf6, 0x43, 0xd4,
            0x78,
            // === SPONSOR SPENDING CONDITION ===
            0x00, // hash mode: P2PKH
            // sponsor signer pubkey hash (20 bytes)
            0x3b, 0x47, 0x18, 0x08, 0x46, 0x7d, 0x33, 0xee, 0xc6, 0x88,
            0xb7, 0xa7, 0xa7, 0x5f, 0x06, 0xaa, 0xd9, 0x21, 0xba, 0x6e,
            // sponsor nonce (8 bytes) = 0
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // sponsor fee (8 bytes) = 0
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // sponsor key encoding (1 byte)
            0x00,
            // sponsor signature (65 bytes)
            0x00, 0x1f, 0xc1, 0xec, 0xc4, 0x2a, 0x7b, 0x62,
            0x59, 0x8a, 0x69, 0x69, 0xcc, 0x0a, 0xf7, 0x7d,
            0x81, 0x99, 0x28, 0x39, 0xe2, 0x03, 0x94, 0x68,
            0x67, 0xe6, 0x03, 0xd4, 0xd8, 0xd2, 0xa3, 0x65,
            0x3a, 0x7e, 0xfc, 0x00, 0xd1, 0x64, 0x23, 0xb0,
            0x35, 0xf8, 0x2d, 0x55, 0x50, 0xf2, 0x6d, 0x3d,
            0x59, 0x20, 0x5b, 0x0c, 0xf5, 0x78, 0xa9, 0x36,
            0x18, 0xc3, 0xeb, 0x7f, 0x50, 0xdc, 0x12, 0xf7,
            0x3c,
        ];

        let (_, auth) = TransactionAuth::from_bytes(&auth_bytes).unwrap();
        
        // Verify it's a sponsored transaction
        assert!(!auth.is_standard_auth());
        assert!(auth.sponsor().is_some());

        // Get the initial sighash auth data
        let mut buf = [0xFFu8; 256];
        let len = auth.initial_sighash_auth(&mut buf).unwrap();

        // For sponsored singlesig transactions:
        // - Origin cleared data: 82 bytes (nonce + fee + signature, all zeros)
        // - Sponsor sentinel: 103 bytes (full spending condition, all zeros)
        // Total: 185 bytes
        let expected_len = ORIGIN_SINGLESIG_INIT_LEN + EXPECTED_SPONSOR_SENTINEL_LEN;
        assert_eq!(len, expected_len,
            "Origin signing sponsored tx: expected {} bytes, got {}", expected_len, len);

        // All bytes should be zeros (cleared origin fields + sponsor sentinel)
        assert!(buf[..len].iter().all(|&b| b == 0),
            "All initial_sighash_auth bytes should be zero for origin signing");
        
        // Verify the sponsor sentinel portion is exactly 103 bytes of zeros
        let sponsor_sentinel_start = ORIGIN_SINGLESIG_INIT_LEN;
        let sponsor_sentinel = &buf[sponsor_sentinel_start..len];
        assert_eq!(sponsor_sentinel.len(), EXPECTED_SPONSOR_SENTINEL_LEN);
        assert!(sponsor_sentinel.iter().all(|&b| b == 0),
            "Sponsor sentinel must be all zeros when origin signs first");

        // The presig hash for origin would be computed as:
        // sha512_256(tx_without_auth || origin_hash_mode || origin_signer || 
        //            [82 zeros] || [103 zeros for sponsor sentinel] ||
        //            auth_type(0x05) || origin_fee || origin_nonce)
        //
        // This test verifies initial_sighash_auth returns the correct 185-byte
        // cleared auth structure that Stacks.js uses in signBegin()
    }

    /// Test Scenario 2: Sponsor signs after origin has already signed
    /// 
    /// When the sponsor signs AFTER the origin, the sponsor's presig hash is computed
    /// from the origin's post-sign hash (which includes origin's signature).
    /// 
    /// The presig hash for sponsor = sha512_256(origin_postsig_hash || auth_type || sponsor_fee || sponsor_nonce)
    /// 
    /// This test verifies that we can correctly extract sponsor information
    /// and that the auth structure is parsed correctly for both parties.
    #[test]
    fn test_sponsor_signs_after_origin() {
        // Same transaction but now we're verifying sponsor signing
        let auth_bytes: Vec<u8> = vec![
            0x05, // sponsored auth type
            // === ORIGIN SPENDING CONDITION (already signed) ===
            0x00, // hash mode: P2PKH
            0x2d, 0x89, 0xde, 0x56, 0xfd, 0x4d, 0xb1, 0x97, 0x41, 0x95,
            0x78, 0x31, 0x92, 0x6e, 0x9b, 0xa9, 0x6c, 0xf0, 0x41, 0x58, // origin signer (20)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // origin nonce
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // origin fee
            0x00, // origin key encoding
            // Origin's actual signature (65 bytes) - this is NOT zeros now!
            0x01, 0xc8, 0x8d, 0xc2, 0xad, 0x9b, 0x08, 0x1d,
            0xb5, 0x25, 0xb6, 0x8a, 0x04, 0xa4, 0xe9, 0xa0,
            0x21, 0xf0, 0x5d, 0x6c, 0x85, 0x00, 0xb4, 0x3f,
            0xf0, 0x13, 0x60, 0xf2, 0x55, 0x82, 0x6f, 0x36,
            0x76, 0x63, 0x6b, 0xcd, 0x04, 0x94, 0xa5, 0x5b,
            0xfd, 0x52, 0x90, 0x28, 0xfe, 0x8c, 0x1b, 0x1e,
            0x93, 0xad, 0x23, 0xb7, 0x5c, 0x31, 0xb2, 0x9c,
            0xee, 0x36, 0x9d, 0x8b, 0xf5, 0xf6, 0x43, 0xd4,
            0x78,
            // === SPONSOR SPENDING CONDITION (will sign) ===
            0x00, // hash mode: P2PKH
            0x3b, 0x47, 0x18, 0x08, 0x46, 0x7d, 0x33, 0xee, 0xc6, 0x88,
            0xb7, 0xa7, 0xa7, 0x5f, 0x06, 0xaa, 0xd9, 0x21, 0xba, 0x6e, // sponsor signer (20)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sponsor nonce
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sponsor fee
            0x00, // sponsor key encoding
            // Sponsor's signature (65 bytes)
            0x00, 0x1f, 0xc1, 0xec, 0xc4, 0x2a, 0x7b, 0x62,
            0x59, 0x8a, 0x69, 0x69, 0xcc, 0x0a, 0xf7, 0x7d,
            0x81, 0x99, 0x28, 0x39, 0xe2, 0x03, 0x94, 0x68,
            0x67, 0xe6, 0x03, 0xd4, 0xd8, 0xd2, 0xa3, 0x65,
            0x3a, 0x7e, 0xfc, 0x00, 0xd1, 0x64, 0x23, 0xb0,
            0x35, 0xf8, 0x2d, 0x55, 0x50, 0xf2, 0x6d, 0x3d,
            0x59, 0x20, 0x5b, 0x0c, 0xf5, 0x78, 0xa9, 0x36,
            0x18, 0xc3, 0xeb, 0x7f, 0x50, 0xdc, 0x12, 0xf7,
            0x3c,
        ];

        let (_, auth) = TransactionAuth::from_bytes(&auth_bytes).unwrap();
        
        // Verify structure
        assert!(!auth.is_standard_auth());
        let sponsor = auth.sponsor().unwrap();
        let origin = auth.origin();

        // Verify we can read origin and sponsor details correctly
        assert_eq!(origin.nonce().unwrap(), 0);
        assert_eq!(origin.fee().unwrap(), 0);
        assert_eq!(sponsor.nonce().unwrap(), 0);
        assert_eq!(sponsor.fee().unwrap(), 0);

        // For sponsor signing, the presig hash computation is different:
        // presig_hash = sha512_256(origin_postsig_hash || auth_type || sponsor_fee || sponsor_nonce)
        //
        // Where origin_postsig_hash = sha512_256(origin_presig_hash || key_type || origin_signature)
        //
        // The initial_sighash_auth() is only used for the INITIAL origin signing.
        // For sponsor signing, we use the origin's post_sig_hash directly.
        //
        // This test verifies that we can correctly access all the sponsor info
        // needed to compute the sponsor's presig hash.

        // Sponsor pubkey hash should be accessible
        let sponsor_pubkey_hash = sponsor.pub_key_hash();
        assert_eq!(sponsor_pubkey_hash.len(), 20);
        assert_eq!(sponsor_pubkey_hash[0], 0x3b);
        assert_eq!(sponsor_pubkey_hash[19], 0x6e);

        // Origin pubkey hash should also be accessible
        let origin_pubkey_hash = origin.pub_key_hash();
        assert_eq!(origin_pubkey_hash.len(), 20);
        assert_eq!(origin_pubkey_hash[0], 0x2d);
        assert_eq!(origin_pubkey_hash[19], 0x58);
    }

    /// Test that verifies the complete presig hash structure for origin signing
    /// 
    /// According to Stacks.js sigHashPreSign:
    /// presig_hash = sha512_256(initial_sighash || auth_type || fee_le || nonce_le)
    /// 
    /// For sponsored transactions, initial_sighash includes the sponsor sentinel.
    #[test]
    fn test_origin_presig_hash_structure_for_sponsored_tx() {
        let auth_bytes: Vec<u8> = vec![
            0x05, // sponsored
            // Origin
            0x00, // hash mode
            0x2d, 0x89, 0xde, 0x56, 0xfd, 0x4d, 0xb1, 0x97, 0x41, 0x95,
            0x78, 0x31, 0x92, 0x6e, 0x9b, 0xa9, 0x6c, 0xf0, 0x41, 0x58,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // nonce = 5
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, // fee = 100
            0x00, // key encoding
            // signature (65 zeros for unsigned)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00,
            // Sponsor (sentinel - all zeros)
            0x00, // hash mode
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // signer = zeros
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // nonce = 0
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // fee = 0
            0x00, // key encoding
            // signature (65 zeros)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00,
        ];

        let (_, auth) = TransactionAuth::from_bytes(&auth_bytes).unwrap();

        // Get origin fee and nonce for presig hash
        let origin_fee = auth.origin_fee();
        let origin_nonce = auth.origin_nonce();
        assert_eq!(origin_fee, 100);
        assert_eq!(origin_nonce, 5);

        // Get initial_sighash_auth data
        let mut buf = [0xFFu8; 256];
        let len = auth.initial_sighash_auth(&mut buf).unwrap();
        
        // Should be 185 bytes (82 origin + 103 sponsor sentinel)
        assert_eq!(len, 185);

        // All should be zeros
        assert!(buf[..len].iter().all(|&b| b == 0));

        // The full presig hash computation would be:
        // 1. Compute initial_sighash = sha512_256(
        //      version || chain_id || 
        //      auth_type(0x05) || 
        //      origin_hash_mode || origin_signer || [82 zeros from initial_sighash_auth] ||
        //      [103 zeros - sponsor sentinel from initial_sighash_auth] ||
        //      anchor_mode || post_conditions || payload
        //    )
        // 2. presig_hash = sha512_256(initial_sighash || auth_type(0x05) || fee_le || nonce_le)
        //
        // The signature is then: sign(presig_hash, private_key)
        
        // This test verifies initial_sighash_auth returns correct structure
        // The actual hash computation happens in C code using this data
    }

    /// Verify sponsor_fee and sponsor_nonce are correctly accessible
    #[test]
    fn test_sponsor_fee_and_nonce_access() {
        let auth_bytes: Vec<u8> = vec![
            0x05, // sponsored
            // Origin
            0x00,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // origin nonce = 1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, // origin fee = 10
            0x00,
            // signature (65 bytes)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00,
            // Sponsor
            0x00,
            0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
            0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, // sponsor nonce = 15
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xe8, // sponsor fee = 1000
            0x00,
            // signature (65 bytes)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00,
        ];

        let (_, auth) = TransactionAuth::from_bytes(&auth_bytes).unwrap();

        // Verify origin values
        assert_eq!(auth.origin_nonce(), 1);
        assert_eq!(auth.origin_fee(), 10);

        // Verify sponsor values - these are needed for sponsor presig hash
        assert_eq!(auth.sponsor_nonce(), Some(15));
        assert_eq!(auth.sponsor_fee(), Some(1000));

        // For sponsor presig hash:
        // presig_hash = sha512_256(origin_postsig_hash || auth_type(0x05) || sponsor_fee_le || sponsor_nonce_le)
        //
        // sponsor_fee_le = 1000 in little endian = [0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        // sponsor_nonce_le = 15 in little endian = [0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    }
}
