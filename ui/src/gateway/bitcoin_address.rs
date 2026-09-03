//! Parse a user-typed Bitcoin address string into `scriptPubKey` bytes.
//!
//! Every type in `freenet_bitcoin_common` and `harvest_common::payment` works
//! in terms of `scriptPubKey` bytes, never address strings -- an address is
//! purely a display encoding of a script, and several encodings can denote
//! the same script (see `freenet_bitcoin_common::BitcoinAddressParameters`'s
//! doc comment). Converting the string a person actually types is a UI-only
//! concern, so it lives here rather than in a shared crate.
//!
//! # A real limitation, not a bug
//!
//! Bitcoin's test networks do not have distinct address encodings from one
//! another: signet and testnet4 share the same Base58Check version bytes AND
//! the same Bech32 human-readable prefix ("tb"), because signet was
//! deliberately designed to reuse testnet's wallet/address code untouched.
//! Regtest shares the same Base58Check versions as testnet4/signet and has
//! its own Bech32 prefix ("bcrt"). So this function can tell mainnet apart
//! from everything else, and regtest apart from testnet4/signet via the
//! Bech32 prefix, but it CANNOT detect "this is a signet address being
//! watched as if it were testnet4" or vice versa -- the wire bytes are
//! identical either way. This is an inherent property of Bitcoin's address
//! formats, not something a parser can fix.

use freenet_bitcoin_common::BitcoinNetwork;

/// Parse `address` as a `scriptPubKey` for `network`. Supports the standard
/// output types: legacy P2PKH / P2SH (Base58Check) and SegWit v0/v1+ P2WPKH /
/// P2WSH / P2TR (Bech32 / Bech32m, per BIP-173 / BIP-350).
pub fn address_to_script_pubkey(address: &str, network: BitcoinNetwork) -> Result<Vec<u8>, String> {
    let address = address.trim();
    if address.is_empty() {
        return Err("enter a Bitcoin address".to_string());
    }

    // SegWit addresses have a distinctive human-readable prefix, so try that
    // decoder first; `bech32::segwit::decode` itself validates whether the
    // checksum is bech32 (v0) or bech32m (v1+) as BIP-350 requires.
    if let Ok((hrp, witness_version, program)) = bech32::segwit::decode(address) {
        let expected_hrp = segwit_hrp(network);
        // The human-readable prefix is case-insensitive per BIP-173 (an
        // address is either all-lowercase or all-uppercase, never mixed),
        // so compare case-insensitively rather than assuming lowercase.
        if !hrp.as_str().eq_ignore_ascii_case(expected_hrp) {
            return Err(format!(
                "that looks like a SegWit address for a different network (expected the \"{expected_hrp}\" prefix)"
            ));
        }
        return Ok(segwit_script_pubkey(witness_version.to_u8(), &program));
    }

    let (version, payload) = decode_base58check(address)?;
    let (p2pkh_version, p2sh_version) = base58_versions(network);
    if payload.len() != 20 {
        return Err(format!("expected a 20-byte hash, got {}", payload.len()));
    }
    if version == p2pkh_version {
        // OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
        let mut script = vec![0x76, 0xa9, 0x14];
        script.extend_from_slice(&payload);
        script.extend_from_slice(&[0x88, 0xac]);
        Ok(script)
    } else if version == p2sh_version {
        // OP_HASH160 <20 bytes> OP_EQUAL
        let mut script = vec![0xa9, 0x14];
        script.extend_from_slice(&payload);
        script.push(0x87);
        Ok(script)
    } else {
        Err("that address doesn't look like it belongs to this network".to_string())
    }
}

fn segwit_hrp(network: BitcoinNetwork) -> &'static str {
    match network {
        BitcoinNetwork::Bitcoin => "bc",
        BitcoinNetwork::Testnet4 | BitcoinNetwork::Signet => "tb",
        BitcoinNetwork::Regtest => "bcrt",
    }
}

/// `(P2PKH version byte, P2SH version byte)`.
fn base58_versions(network: BitcoinNetwork) -> (u8, u8) {
    match network {
        BitcoinNetwork::Bitcoin => (0x00, 0x05),
        BitcoinNetwork::Testnet4 | BitcoinNetwork::Signet | BitcoinNetwork::Regtest => (0x6f, 0xc4),
    }
}

/// `OP_<n> <program>` -- witness version 0 pushes `OP_0` (0x00); versions 1-16
/// push `OP_1`..`OP_16` (0x51..0x60), per BIP-141/BIP-341.
fn segwit_script_pubkey(witness_version: u8, program: &[u8]) -> Vec<u8> {
    let opcode = if witness_version == 0 {
        0x00
    } else {
        0x50 + witness_version
    };
    let mut script = Vec::with_capacity(2 + program.len());
    script.push(opcode);
    script.push(program.len() as u8);
    script.extend_from_slice(program);
    script
}

/// Base58Check-decode `address`, returning `(version_byte, payload)`.
fn decode_base58check(address: &str) -> Result<(u8, Vec<u8>), String> {
    let bytes = bs58::decode(address)
        .with_check(None)
        .into_vec()
        .map_err(|e| format!("not a valid Bitcoin address: {e}"))?;
    let (version, payload) = bytes
        .split_first()
        .ok_or("empty address payload")?;
    Ok((*version, payload.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Well-known test vectors (BIP-173/BIP-350 test suites, and the classic
    // Bitcoin Core genesis P2PKH address) so the parser is checked against
    // real encodings rather than only round-tripping its own output.

    #[test]
    fn parses_mainnet_p2wpkh() {
        let script =
            address_to_script_pubkey("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", BitcoinNetwork::Bitcoin)
                .unwrap();
        assert_eq!(script[0], 0x00, "witness v0 opcode");
        assert_eq!(script[1], 20, "P2WPKH program length");
    }

    #[test]
    fn parses_mainnet_p2tr() {
        let script = address_to_script_pubkey(
            "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297",
            BitcoinNetwork::Bitcoin,
        )
        .unwrap();
        assert_eq!(script[0], 0x51, "witness v1 (OP_1) opcode");
        assert_eq!(script[1], 32, "P2TR program length");
    }

    #[test]
    fn rejects_segwit_address_on_wrong_network() {
        let err = address_to_script_pubkey(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            BitcoinNetwork::Signet,
        )
        .unwrap_err();
        assert!(err.contains("different network"));
    }

    #[test]
    fn parses_mainnet_p2pkh_genesis_address() {
        let script = address_to_script_pubkey(
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            BitcoinNetwork::Bitcoin,
        )
        .unwrap();
        assert_eq!(&script[..3], &[0x76, 0xa9, 0x14]);
        assert_eq!(&script[23..], &[0x88, 0xac]);
    }

    #[test]
    fn rejects_p2pkh_on_wrong_network() {
        assert!(
            address_to_script_pubkey("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", BitcoinNetwork::Signet)
                .is_err()
        );
    }

    #[test]
    fn rejects_garbage() {
        assert!(address_to_script_pubkey("not an address", BitcoinNetwork::Signet).is_err());
        assert!(address_to_script_pubkey("", BitcoinNetwork::Signet).is_err());
    }
}
