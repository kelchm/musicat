// mtpz.rs — MTPZ (Zune) cryptographic handshake
//
// Implements the Microsoft MTPZ authentication protocol required by Zune
// devices. This runs once at connection time when a device advertises the
// "microsoft.com/MTPZ" vendor extension. After a successful handshake,
// all standard MTP operations work normally.
//
// Protocol reference: https://github.com/kbhomes/libmtp-zune

use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
use aes::Aes128;
use cmac::{Cmac, Mac};
use log::info;
use mtp_rs::mtp::MtpDevice;
use mtp_rs::ptp::{pack_string, DevicePropertyCode, OperationCode};
use num_bigint_dig::BigUint;
use sha1::{Digest, Sha1};
use std::fs;
use std::path::PathBuf;

// ─── PTP vendor operation codes (WMDRMPD extension) ───────────────────────

const PTP_OC_SEND_WMDRMPD_APP_REQUEST: OperationCode = OperationCode::Unknown(0x9212);
const PTP_OC_GET_WMDRMPD_APP_RESPONSE: OperationCode = OperationCode::Unknown(0x9213);
const PTP_OC_ENABLE_TRUSTED_FILES_OPS: OperationCode = OperationCode::Unknown(0x9214);
const PTP_OC_END_TRUSTED_APP_SESSION: OperationCode = OperationCode::Unknown(0x9216);

/// MTP device property: SessionInitiatorInfo (0xD406)
const DPC_SESSION_INITIATOR_INFO: DevicePropertyCode = DevicePropertyCode::Unknown(0xD406);

// ─── Credentials ──────────────────────────────────────────────────────────

/// MTPZ credentials loaded from ~/.mtpz-data
struct MtpzCredentials {
    _public_exponent: BigUint,
    _encryption_key: Vec<u8>, // 16 bytes — used by protocol but key derivation happens in response
    modulus: BigUint,
    private_key: BigUint,
    certificates: Vec<u8>, // 629 bytes
}

impl MtpzCredentials {
    fn load() -> Result<Self, String> {
        let path = mtpz_data_path()?;
        let content = fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;

        let lines: Vec<&str> = content.lines().collect();
        if lines.len() < 5 {
            return Err(format!(
                "~/.mtpz-data has {} lines, expected 5",
                lines.len()
            ));
        }

        let _public_exponent = BigUint::parse_bytes(lines[0].trim().as_bytes(), 16)
            .ok_or("Invalid public exponent hex")?;
        let _encryption_key = hex::decode(lines[1].trim())
            .map_err(|e| format!("Invalid encryption key hex: {}", e))?;
        let modulus =
            BigUint::parse_bytes(lines[2].trim().as_bytes(), 16).ok_or("Invalid modulus hex")?;
        let private_key = BigUint::parse_bytes(lines[3].trim().as_bytes(), 16)
            .ok_or("Invalid private key hex")?;
        let certificates =
            hex::decode(lines[4].trim()).map_err(|e| format!("Invalid certificates hex: {}", e))?;

        if _encryption_key.len() != 16 {
            return Err(format!(
                "Encryption key is {} bytes, expected 16",
                _encryption_key.len()
            ));
        }

        Ok(Self {
            _public_exponent,
            _encryption_key,
            modulus,
            private_key,
            certificates,
        })
    }
}

fn mtpz_data_path() -> Result<PathBuf, String> {
    let home = dirs::home_dir().ok_or("Cannot determine home directory")?;
    Ok(home.join(".mtpz-data"))
}

// ─── SHA-1 hash extension (mtpz_hash_custom6A5DC) ─────────────────────────
//
// Extends a hash to an arbitrary output length by iteratively hashing
// with an appended big-endian counter.

fn hash_extend(input: &[u8], output_len: usize) -> Vec<u8> {
    let iterations = (output_len / 20) + 1;
    let mut result = Vec::with_capacity(iterations * 20);

    for i in 0..iterations {
        let mut hasher = Sha1::new();
        hasher.update(input);
        hasher.update(&(i as u32).to_be_bytes());
        result.extend_from_slice(&hasher.finalize());
    }

    result.truncate(output_len);
    result
}

// ─── Raw RSA operations ───────────────────────────────────────────────────

/// Raw RSA sign: output = input^d mod n
fn rsa_sign(input: &[u8], d: &BigUint, n: &BigUint) -> Vec<u8> {
    let m = BigUint::from_bytes_be(input);
    let sig = m.modpow(d, n);
    let mut bytes = sig.to_bytes_be();

    // Pad to 128 bytes with leading zeros
    while bytes.len() < 128 {
        bytes.insert(0, 0);
    }
    bytes
}

/// Raw RSA decrypt: output = input^d mod n
fn rsa_decrypt(input: &[u8], d: &BigUint, n: &BigUint) -> Vec<u8> {
    rsa_sign(input, d, n) // Same operation
}

// ─── AES-128-CBC ──────────────────────────────────────────────────────────

fn aes_cbc_decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() % 16 != 0 {
        return Err(format!(
            "AES data length {} not a multiple of 16",
            data.len()
        ));
    }
    let mut buf = data.to_vec();
    cbc::Decryptor::<Aes128>::new_from_slices(key, &[0u8; 16])
        .map_err(|e| format!("AES init: {}", e))?
        .decrypt_padded_mut::<NoPadding>(&mut buf)
        .map_err(|e| format!("AES-CBC decrypt: {}", e))?;
    Ok(buf)
}

/// Compute AES-CMAC (RFC 4493) of `message` using `key`.
fn aes_cmac(key: &[u8], message: &[u8]) -> [u8; 16] {
    let mut mac = Cmac::<Aes128>::new_from_slice(key).expect("CMAC key must be 16 bytes");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

// ─── Handshake implementation ─────────────────────────────────────────────

/// Check if a device requires the MTPZ handshake.
pub fn device_needs_mtpz(device: &MtpDevice) -> bool {
    device
        .device_info()
        .vendor_extension_desc
        .to_lowercase()
        .contains("microsoft.com/mtpz")
}

/// Perform the MTPZ handshake on a connected device.
/// Must be called after the session is open but before any file operations.
pub async fn perform_handshake(device: &MtpDevice) -> Result<(), String> {
    let creds = MtpzCredentials::load()?;
    let session = device.session();

    let di = device.device_info();
    info!("Starting MTPZ handshake...");
    info!("Vendor extension: {}", di.vendor_extension_desc);
    info!("Supported ops: {:?}", di.operations_supported);
    info!(
        "Device props supported: {:?}",
        di.device_properties_supported
    );

    // ── Phase 0: Set session initiator info and reset handshake state ──

    // SessionInitiatorInfo is checked by the Zune firmware against an allowlist
    // of known MTPZ clients. We must identify ourselves as the libmtp client
    // (the original reverse-engineered identifier) — anything else causes the
    // device to silently downgrade the session and reject write operations
    // with AccessDenied while still allowing reads.
    let initiator_str = pack_string("libmtp/musicat - MTPZClassDriver");
    match session
        .set_device_prop_value(DPC_SESSION_INITIATOR_INFO, &initiator_str)
        .await
    {
        Ok(()) => info!("Set SessionInitiatorInfo"),
        Err(e) => info!("SessionInitiatorInfo not supported (non-fatal): {}", e),
    }

    // Reset any prior handshake state (EndTrustedAppSession with no params)
    let reset_result = session.execute(PTP_OC_END_TRUSTED_APP_SESSION, &[]).await;
    info!(
        "Reset handshake state: {:?}",
        reset_result.as_ref().map(|r| r.code)
    );

    // ── Phase 1: Build and send application certificate message ────────

    // Generate a cryptographic-quality random nonce. The Zune embeds this
    // in the trust handshake; reusing a fixed value across runs may cause
    // the device to refuse subsequent write operations even though reads
    // still appear to work. (We previously hard-coded this for debugging
    // and never reverted it — that's almost certainly the cause of the
    // AccessDenied we see on SendObjectPropList.)
    use rand::RngCore;
    let mut random = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut random);

    let acm = build_certificate_message(&creds, &random)?;

    let send_resp = session
        .execute_with_send(PTP_OC_SEND_WMDRMPD_APP_REQUEST, &[], &acm)
        .await
        .map_err(|e| format!("Failed to send certificate: {}", e))?;

    info!(
        "Sent application certificate ({} bytes, certs={} bytes, resp={:?})",
        acm.len(),
        creds.certificates.len(),
        send_resp.code
    );

    // ── Phase 2: Receive and parse device response ─────────────────────

    let (resp, response_data) = session
        .execute_with_receive(PTP_OC_GET_WMDRMPD_APP_RESPONSE, &[])
        .await
        .map_err(|e| format!("Failed to get device response: {}", e))?;

    info!(
        "Received device response ({} bytes, resp code={:?})",
        response_data.len(),
        resp.code
    );

    let hash = parse_device_response(&creds, &response_data, &random)?;

    // ── Phase 3: Send confirmation ─────────────────────────────────────

    let confirmation = build_confirmation(&hash);

    let confirm_resp = session
        .execute_with_send(PTP_OC_SEND_WMDRMPD_APP_REQUEST, &[], &confirmation)
        .await
        .map_err(|e| format!("Failed to send confirmation: {}", e))?;

    let confirm_code = u16::from(confirm_resp.code);
    info!(
        "Sent handshake confirmation (response: 0x{:04x})",
        confirm_code
    );
    if confirm_code != 0x2001 {
        return Err(format!(
            "Handshake confirmation rejected with 0x{:04x}",
            confirm_code
        ));
    }

    // ── Phase 4: Enable trusted file operations ────────────────────────

    info!(
        "MTPZ post-handshake hash: {} bytes = {}",
        hash.len(),
        hex::encode(&hash)
    );

    let mac_count_bytes = if hash.len() >= 20 {
        [hash[16], hash[17], hash[18], hash[19]]
    } else {
        info!(
            "WARNING: hash is only {} bytes, macCount falling back to zeros — this is the suspected MTPZ bug",
            hash.len()
        );
        [0u8; 4]
    };

    info!("MTPZ macCount bytes = {}", hex::encode(&mac_count_bytes));

    let mch = aes_cmac(&hash[..16], &mac_count_bytes);

    info!("MTPZ derived params (mch) = {}", hex::encode(&mch));

    let params = [
        u32::from_be_bytes([mch[0], mch[1], mch[2], mch[3]]),
        u32::from_be_bytes([mch[4], mch[5], mch[6], mch[7]]),
        u32::from_be_bytes([mch[8], mch[9], mch[10], mch[11]]),
        u32::from_be_bytes([mch[12], mch[13], mch[14], mch[15]]),
    ];

    let enable_resp = session
        .execute(PTP_OC_ENABLE_TRUSTED_FILES_OPS, &params)
        .await
        .map_err(|e| format!("Failed to enable trusted ops: {}", e))?;

    let enable_code = u16::from(enable_resp.code);
    info!(
        "EnableTrustedFileOperations response: 0x{:04x} (params: [{:08x}, {:08x}, {:08x}, {:08x}])",
        enable_code, params[0], params[1], params[2], params[3]
    );
    if enable_code != 0x2001 {
        return Err(format!(
            "EnableTrustedFileOperations failed with 0x{:04x} — MTPZ handshake incomplete",
            enable_code
        ));
    }

    info!("MTPZ handshake complete — trusted file operations enabled");
    Ok(())
}

/// Build the 785-byte application certificate message.
fn build_certificate_message(
    creds: &MtpzCredentials,
    random: &[u8; 16],
) -> Result<Vec<u8>, String> {
    let cert_len = creds.certificates.len();
    let mut acm = vec![0u8; 7 + cert_len + 2 + 16 + 3 + 128];

    // Header
    acm[0] = 0x02;
    acm[1] = 0x01;
    acm[2] = 0x01;
    acm[3] = 0x00;
    acm[4] = 0x00;
    acm[5] = (cert_len >> 8) as u8;
    acm[6] = cert_len as u8;

    // Certificates
    acm[7..7 + cert_len].copy_from_slice(&creds.certificates);

    let off = 7 + cert_len;

    // Random data length + data
    acm[off] = 0x00;
    acm[off + 1] = 0x10;
    acm[off + 2..off + 18].copy_from_slice(random);

    // Signature header
    acm[off + 18] = 0x01;
    acm[off + 19] = 0x00;
    acm[off + 20] = 0x80;

    // Compute RSA signature over the message body
    let signature = compute_signature(creds, &acm[..off + 18])?;
    acm[off + 21..off + 149].copy_from_slice(&signature);

    Ok(acm)
}

/// Compute the RSA signature for the certificate message.
///
/// 1. SHA-1 hash of message content (with 8-byte prefix)
/// 2. Build 128-byte EMSA structure: hash_expansion XOR | 0x01 | hash | 0xBC
/// 3. Raw RSA sign
fn compute_signature(creds: &MtpzCredentials, acm: &[u8]) -> Result<Vec<u8>, String> {
    // Step 1: Hash the message body (from offset 2 to end)
    let mut v16 = [0u8; 28];
    // v16[0..8] = counter/padding (zeros)
    let body_hash = {
        let mut h = Sha1::new();
        h.update(&acm[2..]);
        h.finalize()
    };
    v16[8..28].copy_from_slice(&body_hash);

    // Step 2: Hash v16 to get the final 20-byte hash
    let hash = {
        let mut h = Sha1::new();
        h.update(&v16);
        h.finalize()
    };

    // Step 3: Expand hash to 107 bytes
    let expansion = hash_extend(&hash, 107);

    // DEBUG: Log intermediate values for comparison with reference implementation
    info!("body_hash = {}", hex::encode(&body_hash));
    info!("hash = {}", hex::encode(&hash));
    info!("expansion[0:16] = {}", hex::encode(&expansion[..16]));

    // Step 4: Build 128-byte signature input
    // Order matters — must match libmtp-zune exactly:
    //   1. Place hash at [107..127]
    //   2. Set marker 0x01 at [106]
    //   3. XOR bytes [0..107] with expansion (includes marker)
    //   4. Clear high bit of [0]
    //   5. Set trailer 0xBC at [127]
    let mut odata = [0u8; 128];

    // Hash at offset 107..127
    odata[107..127].copy_from_slice(&hash);

    // Marker before XOR
    odata[106] = 0x01;

    // XOR first 107 bytes with expansion
    for i in 0..107 {
        odata[i] ^= expansion[i];
    }

    // Clear high bit
    odata[0] &= 0x7F;

    // Trailer
    odata[127] = 0xBC;

    // XOR expansion with first 106 bytes (the expansion already IS the first 107 bytes,
    // but marker at 106 overrides)

    info!("odata[0:16] = {}", hex::encode(&odata[..16]));
    info!("odata[104:128] = {}", hex::encode(&odata[104..128]));

    // Step 5: RSA sign
    let sig = rsa_sign(&odata, &creds.private_key, &creds.modulus);
    info!("signature[0:16] = {}", hex::encode(&sig[..16]));
    Ok(sig)
}

/// Parse the device response, validate it, and extract the MAC hash.
///
/// Returns the hash/key material needed for confirmation and trusted ops.
fn parse_device_response(
    creds: &MtpzCredentials,
    response: &[u8],
    sent_random: &[u8; 16],
) -> Result<Vec<u8>, String> {
    // Response format:
    // [0]:  0x02 (type)
    // [1]:  0x02 (subtype)
    // [2]:  length high / marker
    // [3]:  0x80 (128 bytes follow)
    // [4..132]:  128-byte RSA-encrypted message
    // [132]: 0x03 (tag)
    // [133]: 0x40 (marker, 0x340 = 832 bytes)
    // [134..966]: 832-byte AES-encrypted payload

    if response.len() < 134 {
        return Err(format!(
            "Device response too short: {} bytes",
            response.len()
        ));
    }

    // Find the RSA-encrypted section
    let rsa_offset = if response[0] == 0x02 && response[1] == 0x02 {
        // Skip header to find the 128-byte encrypted block
        // Format varies — look for the length marker
        let mut off = 2;
        // Skip any length bytes
        while off < response.len() && response[off] != 0x80 {
            off += 1;
        }
        if off >= response.len() {
            return Err("Cannot find RSA block marker in response".into());
        }
        off + 1 // Skip the 0x80 marker
    } else {
        return Err(format!(
            "Unexpected response header: {:02X} {:02X}",
            response[0], response[1]
        ));
    };

    if rsa_offset + 128 > response.len() {
        return Err("Response too short for RSA block".into());
    }

    // ── RSA decrypt the first 128 bytes ────────────────────────────────

    let rsa_block = &response[rsa_offset..rsa_offset + 128];
    let mut msg_dec = rsa_decrypt(rsa_block, &creds.private_key, &creds.modulus);

    // Ensure we have exactly 128 bytes
    while msg_dec.len() < 128 {
        msg_dec.insert(0, 0);
    }
    msg_dec.truncate(128);

    // ── Key derivation via hash extension + XOR ────────────────────────

    // Step 1: Expand msg_dec[21..128] (107 bytes) to 20 bytes
    let v10 = hash_extend(&msg_dec[21..128], 20);
    for i in 0..20 {
        msg_dec[1 + i] ^= v10[i];
    }

    // Step 2: Expand msg_dec[1..21] (20 bytes) to 107 bytes
    let v11 = hash_extend(&msg_dec[1..21], 107);
    for i in 0..107 {
        msg_dec[21 + i] ^= v11[i];
    }

    // Extract 16-byte AES key from offset 112
    let aes_key: Vec<u8> = msg_dec[112..128].to_vec();

    // ── Find and decrypt AES payload ───────────────────────────────────

    let aes_offset = rsa_offset + 128;
    if aes_offset + 4 > response.len() {
        return Err("Response too short for AES section".into());
    }

    // Skip the tag bytes (0x03, 0x40 or similar) to find the encrypted data
    let mut data_offset = aes_offset;
    // Look for tag 0x03
    while data_offset < response.len() && response[data_offset] != 0x03 {
        data_offset += 1;
    }
    if data_offset >= response.len() {
        return Err("Cannot find AES data tag in response".into());
    }

    // Skip tag + length encoding to get to the actual encrypted data
    data_offset += 1; // skip 0x03 tag
                      // Parse length — could be multi-byte
    if data_offset < response.len() && response[data_offset] & 0x80 != 0 {
        let len_bytes = (response[data_offset] & 0x7F) as usize;
        data_offset += 1 + len_bytes;
    } else {
        data_offset += 1;
    }

    let encrypted = &response[data_offset..];
    // Round down to multiple of 16
    let enc_len = (encrypted.len() / 16) * 16;
    if enc_len == 0 {
        return Err("No AES data to decrypt".into());
    }

    let plaintext = aes_cbc_decrypt(&aes_key, &encrypted[..enc_len])?;

    // ── Validate: find and check our random nonce ──────────────────────

    // The plaintext contains certificates, then our random nonce, then device random,
    // then signature, then MAC hash. Search for our nonce to validate.
    let nonce_found = plaintext.windows(16).any(|w| w == sent_random);

    if !nonce_found {
        return Err("Random nonce validation failed — response may be tampered".into());
    }

    info!("Nonce validation passed");

    // DIAGNOSTIC: dump the entire decrypted plaintext so we can see all the
    // length-prefixed fields and verify that extract_mac_hash is picking the
    // right one for the MAC hash.
    info!(
        "MTPZ decrypted response plaintext ({} bytes):",
        plaintext.len()
    );
    for (i, chunk) in plaintext.chunks(32).enumerate() {
        let hex: Vec<String> = chunk.iter().map(|b| format!("{:02x}", b)).collect();
        info!("  [{:04x}] {}", i * 32, hex.join(" "));
    }

    // ── Extract MAC hash from end of plaintext ─────────────────────────

    // The MAC hash is near the end of the decrypted data.
    // Look backwards for the hash length marker (0x00, 0x20 = 32 bytes)
    // or (0x00, 0x10 = 16 bytes)
    let hash = extract_mac_hash(&plaintext)?;

    Ok(hash)
}

/// Extract the MAC hash from the decrypted device response payload.
///
/// Walks the plaintext as a sequence of length-prefixed fields, matching the
/// structure used by libmtp-zune's `ptp_mtpz_validatehandshakeresponse` and
/// NiceBeard's zune-explorer JavaScript port. The structure is:
///
///   1. Skip 1 byte (cert section marker)
///   2. u32 BE certs_length, then <certs_length> bytes (skip)
///   3. u16 BE rand_length, then <rand_length> bytes (the echoed nonce)
///   4. u16 BE dev_rand_length, then <dev_rand_length> bytes (skip)
///   5. Skip 1 byte
///   6. u16 BE sig_length, then <sig_length> bytes (skip)
///   7. Skip 1 byte
///   8. u16 BE machash_length, then <machash_length> bytes — THIS is the hash
fn extract_mac_hash(plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let mut off: usize = 0;

    // Helper to read N bytes safely
    let read_u16_be = |buf: &[u8], at: usize| -> Result<u16, String> {
        if at + 2 > buf.len() {
            return Err(format!("read_u16_be: out of bounds at {}", at));
        }
        Ok(u16::from_be_bytes([buf[at], buf[at + 1]]))
    };
    let read_u32_be = |buf: &[u8], at: usize| -> Result<u32, String> {
        if at + 4 > buf.len() {
            return Err(format!("read_u32_be: out of bounds at {}", at));
        }
        Ok(u32::from_be_bytes([
            buf[at],
            buf[at + 1],
            buf[at + 2],
            buf[at + 3],
        ]))
    };

    // Step 1: Skip 1 byte cert section marker
    if plaintext.is_empty() {
        return Err("plaintext empty".into());
    }
    off += 1;

    // Step 2: Skip the certificate section
    let certs_length = read_u32_be(plaintext, off)? as usize;
    off += 4;
    info!(
        "extract_mac_hash: certs_length = {} (0x{:x}), now at offset 0x{:x}",
        certs_length, certs_length, off
    );
    off = off
        .checked_add(certs_length)
        .ok_or_else(|| "certs_length overflow".to_string())?;

    // Step 3: Random section (echoed nonce)
    let rand_length = read_u16_be(plaintext, off)? as usize;
    off += 2;
    info!(
        "extract_mac_hash: rand_length = {} at offset 0x{:x}",
        rand_length, off
    );
    off += rand_length;

    // Step 4: Device random
    let dev_rand_length = read_u16_be(plaintext, off)? as usize;
    off += 2;
    info!(
        "extract_mac_hash: dev_rand_length = {} at offset 0x{:x}",
        dev_rand_length, off
    );
    off += dev_rand_length;

    // Step 5: Skip 1 byte
    off += 1;

    // Step 6: Signature
    let sig_length = read_u16_be(plaintext, off)? as usize;
    off += 2;
    info!(
        "extract_mac_hash: sig_length = {} at offset 0x{:x}",
        sig_length, off
    );
    off += sig_length;

    // Step 7: Skip 1 byte
    off += 1;

    // Step 8: MAC hash
    let machash_length = read_u16_be(plaintext, off)? as usize;
    off += 2;
    info!(
        "extract_mac_hash: machash_length = {} at offset 0x{:x}",
        machash_length, off
    );

    if off + machash_length > plaintext.len() {
        return Err(format!(
            "machash extends past plaintext: off={} len={} plaintext_len={}",
            off,
            machash_length,
            plaintext.len()
        ));
    }

    Ok(plaintext[off..off + machash_length].to_vec())
}

/// Build the 20-byte confirmation message.
fn build_confirmation(hash: &[u8]) -> Vec<u8> {
    let mut message = vec![0u8; 20];
    message[0] = 0x02;
    message[1] = 0x03;
    message[2] = 0x00;
    message[3] = 0x10;

    // CMAC of seed (15 zeros + 0x01) using hash as key
    let mut seed = [0u8; 16];
    seed[15] = 0x01;

    let mac = aes_cmac(&hash[..16], &seed);
    message[4..20].copy_from_slice(&mac);

    message
}
