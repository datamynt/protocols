# Beviset Protocol — Digital Ownership Certificates on Bitcoin SV

**Version:** 0.7.0
**Date:** 2026-03-19
**License (specification):** MIT
**License (implementations):** Open BSV License

---

## 1. Summary

Beviset Protocol is an open standard for registering and verifying provenance certificates for physical goods, anchored to the Bitcoin SV blockchain.

The protocol establishes **notoriety** (cryptographic proof of what was registered, by whom, and when) — not legal title (rettsvern). For physical goods under Norwegian law, legal ownership protection requires physical delivery (tradisjon). Beviset provides a complementary digital provenance record.

**Core principle:** The proof is a satoshi. The inscription commits the registration hash. The UTXO chain records transfer history.

---

## 2. Architecture

```
┌──────────────────────────────────────────────────────┐
│  Service layer (e.g. beviset.no)                     │
│  Identity verification · Registration · Dashboard    │
└───────────────────────┬──────────────────────────────┘
                        │
┌───────────────────────▼──────────────────────────────┐
│  Anchoring service                                   │
│  1SatOrdinal inscriptions · UTXO management          │
└───────────────────────┬──────────────────────────────┘
                        │
┌───────────────────────▼──────────────────────────────┐
│  Key derivation (WAB algorithm — published, open)    │
│  Identity + salt → deterministic Bitcoin key         │
└───────────────────────┬──────────────────────────────┘
                        │
┌───────────────────────▼──────────────────────────────┐
│  Bitcoin SV blockchain                               │
│  1SatOrdinals · UTXO chain = ownership history       │
└──────────────────────────────────────────────────────┘
```

Each layer can be replaced independently. The protocol survives any single service shutting down.

---

## 3. Proof Hash

### 3.1 Input fields

| Field | Type | Description |
|-------|------|-------------|
| `protocol_version` | string | Always `"beviset-v1"` |
| `owner_identity_hash` | string | HMAC-peppered hash of owner identity (see 3.2) |
| `item_identifier` | string | Primary identifier (serial number, frame number, IMEI, etc.) |
| `item_category` | string | Category code (e.g. `"ebike"`, `"watch"`, `"electronics"`) |
| `registered_at` | integer | Unix timestamp (seconds) at registration |

### 3.2 Identity hashing

Identity inputs (BankID PID, email+phone, etc.) must be hashed with a protocol pepper before inclusion in the proof hash. This defends against rainbow tables — Norwegian personal IDs have only ~5 million valid combinations.

```python
import hashlib
import hmac

# Published protocol constant — security comes from HMAC computation cost,
# not from the pepper being secret.
PID_PEPPER = "beviset-protocol-pid-pepper-v1-datamynt"

def compute_identity_hash(identity_input: str) -> str:
    """HMAC-SHA256 with protocol pepper. Deterministic and irreversible."""
    return hmac.new(
        PID_PEPPER.encode("utf-8"),
        identity_input.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
```

For BankID: `identity_input = pid` (11-digit Norwegian personal ID).
For email+phone: `identity_input = f"email:{email.lower()}|phone:{phone}"`.

Services MAY add their own secret pepper on top for defense in depth.

### 3.3 Proof hash computation

```python
PROTOCOL_VERSION = "beviset-v1"

def compute_proof_hash(
    owner_identity_hash: str,   # Output of compute_identity_hash()
    item_identifier: str,       # Serial number, frame number, etc.
    item_category: str,         # Category code
    registered_at: int,         # Unix timestamp
) -> str:
    """Compute the proof hash that gets inscribed on-chain."""
    preimage = "\n".join([
        PROTOCOL_VERSION,
        owner_identity_hash,
        item_identifier.strip().upper(),    # Canonical: UPPERCASE, trimmed
        item_category.strip().lower(),      # Canonical: lowercase, trimmed
        str(registered_at),
    ])
    return hashlib.sha256(preimage.encode("utf-8")).hexdigest()
```

### 3.4 Properties

- **Deterministic:** Same inputs always produce the same hash.
- **Irreversible:** The hash cannot reveal the original inputs.
- **Privacy-preserving:** Identity is double-hashed (HMAC-pepper + SHA-256). No personal data on-chain.
- **Rainbow-resistant:** HMAC pepper eliminates precomputed lookup tables.
- **Canonical:** Item identifiers normalized (uppercase, trimmed) for consistent hashing.

### 3.5 Example

```
Input:
  identity:         "12345678901" (BankID PID)
  item_identifier:  "WBK342C38N0271" (bike frame number)
  item_category:    "ebike"
  registered_at:    1710288000

Step 1 — Identity hash:
  HMAC-SHA256("beviset-protocol-pid-pepper-v1-datamynt", "12345678901")
  → "e7b3f1..." (64 hex chars)

Step 2 — Preimage:
  "beviset-v1\ne7b3f1...\nWBK342C38N0271\nebike\n1710288000"

Step 3 — Proof hash:
  SHA-256(preimage) → "a3f8c2d1..." (64 hex chars)
```

---

## 4. Key Derivation

Key derivation maps an identity to a deterministic Bitcoin address. A server-held 256-bit random salt (the user's "presentation key") ensures that knowing someone's identity alone is NOT sufficient to derive their private key.

### 4.1 Algorithm: Salted HKDF-SHA256

```python
import hashlib
import hmac

# Domain separator — different per application and identity type.
# See section 4.3 for the full list of domain separators.

def derive_bitcoin_key(
    identity_input: str,
    domain: str,
    salt: str,             # 256-bit random hex (user's presentation key)
    key_id: str = None,
) -> bytes:
    """
    Deterministic Bitcoin key from identity + salt.

    Uses HKDF-SHA256 (RFC 5869):
      IKM     = identity_input || salt
      Extract: PRK = HMAC-SHA256(domain, IKM)
      Expand:  OKM = HMAC-SHA256(PRK, info)

    The salt is a 256-bit random value generated per user on first key
    derivation and stored server-side. It prevents brute-force: even for
    BankID PIDs (~5M valid values), an attacker cannot derive keys without
    the salt.

    Info string:
      Without key_id: "bitcoin-key-derivation" || 0x01          (base key)
      With key_id:    "bitcoin-key-derivation:" || key_id || 0x01 (child key)

    Returns 32 bytes — a valid secp256k1 private key.
    """
    # HKDF-Extract with salted IKM
    ikm = identity_input + salt
    prk = hmac.new(
        domain.encode("utf-8"),
        ikm.encode("utf-8"),
        hashlib.sha256,
    ).digest()

    # HKDF-Expand (single block = 32 bytes = 256 bits)
    if key_id:
        info = f"bitcoin-key-derivation:{key_id}".encode("utf-8") + b"\x01"
    else:
        info = b"bitcoin-key-derivation\x01"

    okm = hmac.new(
        prk,
        info,
        hashlib.sha256,
    ).digest()

    return okm  # 32 bytes = valid secp256k1 private key
```

### 4.1.1 Child key derivation (keyID)

When `key_id` is provided, it is appended to the HKDF info string after a `:` separator. This produces a unique Bitcoin address for each distinct `key_id`, preventing on-chain linkability between registrations by the same identity.

**Recommended keyID:** Use the proof hash (section 3.3) as the `key_id`. Since the proof hash is already inscribed on-chain, a verifier can:

1. Read the inscription → extract the proof hash
2. Recompute the expected address: `derive_bitcoin_key(identity, domain, salt, key_id=proof_hash)`
3. Confirm the inscription lives at that address

No server or database lookup is needed — the keyID is self-contained in the inscription.

**Backwards compatibility:** Omitting `key_id` produces the same key as before. Existing inscriptions at base addresses remain valid.

### 4.2 Address derivation

```
private_key = derive_bitcoin_key(identity_input, domain, salt)
public_key  = secp256k1_multiply(G, private_key)  # compressed, 33 bytes
address     = P2PKH(public_key)                    # standard Bitcoin address
```

### 4.3 Domain separators

Each application uses a unique domain separator so the same identity produces different keys per service:

| Application | Identity type | Domain separator |
|-------------|--------------|------------------|
| Beviset (BankID) | PID | `"wab-keygen-beviset-v1"` |
| Beviset (email+phone) | canonical string | `"beviset-v1-keygen-emailphone"` |
| Beviset (email) | canonical email | `"beviset-v1-keygen-email"` |
| Helt Enig (BankID) | PID | `"wab-keygen-heltenig-v1"` |
| Helt Enig (email+phone) | canonical string | `"heltenig-v1-keygen-emailphone"` |
| Mer Data (email) | canonical email | `"merdata-v1-keygen-email"` |

### 4.4 Why this matters

The key derivation algorithm is **published and deterministic**, but requires a per-user salt that is stored server-side. This gives two important properties:

1. **Privacy:** Knowing someone's identity alone is NOT sufficient to derive their Bitcoin address or private key. The 256-bit salt makes brute-force computationally infeasible.
2. **Verifiability:** The key derivation service provides a public `/api/verify-address` endpoint that confirms whether an address belongs to a given identity — without exposing the salt or private keys.

**Survivability:** The salt is backed up per user. For contract platforms (e.g., Helt Enig), the salt can be embedded in signed PDF documents, making the PDF itself a self-contained backup. For ownership registrations (e.g., Beviset), the salt is held by the key derivation service and can be exported by the user.

### 4.5 Security properties

| Concern | Mitigation |
|---------|-----------|
| Brute-force PID → key | 256-bit salt makes this computationally infeasible (~2^256 guesses) |
| Key derivation server compromised | Algorithm is published — anyone can run it with their salt backup |
| Salt leaked | Salt alone is useless without identity; identity alone is useless without salt |
| Identity changes | Rare; triggers key rotation + re-signing |
| Keys derived on-demand | Never stored — derived when needed, then discarded |
| Same identity, different services | Domain separators ensure independent key spaces |
| No seed phrases | By design — users never see cryptographic keys |

---

## 5. Blockchain Model: 1SatOrdinals

### 5.1 The proof IS a satoshi

Each ownership certificate is a 1SatOrdinal inscription on a specific satoshi. The satoshi is sent to the owner's derived Bitcoin address. The owner holds the proof.

```
REGISTRATION:
  Anchoring service creates 1SatOrdinal inscription with proof hash
  → Satoshi sent to owner's derived address
  → Owner holds the proof in their wallet

TRANSFER:
  Owner signs a transaction sending the satoshi to new owner
  → No new hash, no new registration
  → The UTXO chain IS the ownership history

VERIFICATION:
  Follow the UTXO chain from inscription → current holder = current owner
```

### 5.2 Inscription format

```json
{
  "protocol": "beviset-v1",
  "hash": "<proof_hash>",
  "category": "ebike",
  "registered_at": 1710288000,
  "issuer": "beviset.no"
}
```

The inscription contains ONLY the hash and metadata. No personal data. No item details. The hash is the cryptographic commitment — the rest is private.

### 5.3 Ownership transfer as UTXO chain

```
TX1 (Registration):
  Input:  anchoring service funding UTXO
  Output: 1sat inscription → Thomas' address (derived from BankID)

TX2 (Transfer Thomas → Kari):
  Input:  TX1 output (signed with Thomas' derived key)
  Output: 1sat → Kari's address (derived from Kari's BankID)

TX3 (Transfer Kari → Erik):
  Input:  TX2 output (signed with Kari's derived key)
  Output: 1sat → Erik's address (derived from Erik's BankID)

Verification:
  Follow UTXO chain: TX1 → TX2 → TX3
  Current holder of the satoshi = current owner
  Full provenance chain visible on blockchain
```

### 5.4 Why 1SatOrdinals over OP_RETURN

| | OP_RETURN | 1SatOrdinals |
|---|---|---|
| Transfer | New OP_RETURN per transfer | Send the satoshi |
| History | Unlinked entries | UTXO chain = provable sequence |
| Ownership | Anyone can write OP_RETURN | Only holder can send the satoshi |
| Cost | New TX per transfer | Only TX fee for transfer |
| Verification | Requires database to correlate | Follow UTXO chain directly |

---

## 6. Transaction Verification (BEEF / SPV)

### 6.1 BEEF format (BRC-62)

Implementations SHOULD store all anchoring transactions in **BEEF** (Background Evaluation Extended Format, BRC-62). BEEF bundles the raw transaction data with Merkle proofs (BUMPs, BRC-74) into a single self-verifying package.

```
BEEF structure:
  Version: 0100BEEF (little-endian)
  BUMPs:   [count] [merkle_path_1] [merkle_path_2] ...
  TXs:     [count] [raw_tx_1 + bump_index] [raw_tx_2 + bump_index] ...
```

**Why BEEF matters for ownership proofs:**
- A BEEF-wrapped inscription is **independently verifiable** — no trusted third party needed
- The Merkle path proves the TX is included in a specific block at a specific height
- Combined with block headers (available from any BSV node), this provides full SPV verification
- BEEF can be embedded in PDF certificates, stored in databases, or shared peer-to-peer

### 6.2 SPV verification

Simplified Payment Verification (SPV) confirms that a transaction is included in a block without downloading the entire blockchain. For ownership proofs, SPV provides:

1. **Merkle path** — proves TX inclusion in a specific block
2. **Block height** — establishes when the proof was created
3. **Confirmation depth** — `current_height - tx_height` = proof strength

```
SPV verification flow:
  1. Extract TX and Merkle path from BEEF
  2. Compute Merkle root from TX hash + path
  3. Verify Merkle root matches the block header at the claimed height
  4. Check confirmation depth (deeper = stronger)

Confirmation depth guidelines:
  depth >= 1      Transaction is mined (basic confidence)
  depth >= 6      Standard Bitcoin confirmation threshold
  depth >= 100    Strong proof — reorganization extremely unlikely
  depth >= 1000   Historical proof — practically immutable
```

Implementations SHOULD use a chain tracker (e.g., WhatsOnChain, Chaintracks) to verify Merkle roots against block headers. For highest assurance, implementations MAY verify against their own BSV node.

### 6.3 ARC callbacks for Merkle path delivery

The ARC transaction processor (BRC-22) provides asynchronous callbacks when a transaction is mined, delivering the Merkle path needed for BEEF completion.

```
Broadcasting flow:
  1. Service broadcasts TX to ARC with callback URL + token
  2. ARC returns initial status (QUEUED → SEEN_ON_NETWORK)
  3. When TX is mined, ARC POST callback with {txid, merklePath, txStatus}
  4. Service merges Merkle path into stored BEEF → proof is now SPV-verifiable

ARC callback payload:
  {
    "txid": "<transaction_id>",
    "txStatus": "MINED",
    "merklePath": "<BRC-74 hex-encoded Merkle path>"
  }
```

Implementations SHOULD:
- Register a callback URL when broadcasting via ARC
- Store the initial BEEF without BUMPs immediately after broadcast
- Merge the Merkle path into BEEF when the callback arrives
- Mark the proof as SPV-verified only after successful Merkle path verification

### 6.4 Broadcaster failover

Implementations SHOULD use sequential failover across multiple broadcasters to maximize reliability:

```
Recommended broadcast order:
  1. ARC (TAAL)           — primary, with callbacks
  2. ARC (GorillaPool)    — secondary ARC
  3. WhatsOnChain         — fallback (no callbacks)
  4. Direct node broadcast — last resort
```

If the primary broadcaster fails, the next is tried automatically. Only the first successful broadcast registers callbacks — subsequent attempts are fire-and-forget.

---

## 7. Identity Verification

### 7.1 Online verification (primary)

The key derivation service provides a public endpoint for address verification:

```
POST /api/verify-address
{
  "identity_type": "bankid" | "emailphone" | "email",
  "pid": "12345678901",          // for bankid
  "email": "user@example.com",   // for emailphone/email
  "phone": "+4712345678",        // for emailphone
  "purpose": "beviset-v1",
  "address": "1Abc...",
  "keyID": "<proof_hash>"        // optional
}

Response: { "verified": true }
```

This endpoint re-derives the address server-side (using the stored salt) and compares — without exposing the salt or private key.

### 7.2 Full verification flow

1. **Obtain the inscription TXID** (from PDF certificate, database, or user claim)
2. **Follow the UTXO chain** to the current holder's address
3. **Call `/api/verify-address`** with the claimed identity and the holder's address
4. **Verify the proof hash** — recompute from claimed data using section 3, check it matches the inscription

```
Claimed owner provides: identity + item serial + category + registration time
                               ↓
Verifier computes:    identity_hash = HMAC-SHA256(pepper, identity)
                      proof_hash = SHA-256(preimage)
                               ↓
Verifier calls:       POST /api/verify-address { identity, address, keyID=proof_hash }
                               ↓
Verifier checks:      proof_hash matches inscription on-chain?  ✓
                      verify-address returns verified: true?     ✓
                               ↓
                      Ownership verified.
```

### 7.3 Offline verification (with salt backup)

For scenarios where the key derivation service is unavailable, the user's salt (presentation key) can be used directly with the published algorithm (section 4.1). Salt backups are available via:

- **Contract PDFs** (Helt Enig): salt embedded in the signed document
- **User export**: users can download their salt from the service dashboard
- **Recovery phrase**: salt can be derived from a BIP39 seed phrase (future)

**Dependencies for offline verification:**
- This specification (published, MIT license)
- Access to BSV blockchain (any node or block explorer)
- The user's salt (presentation key)
- The owner's identity claim (PID or email+phone)
- SHA-256 + HMAC-SHA256 + HKDF-SHA256 + secp256k1 (standard cryptography)

---

## 8. Security

### 8.1 Threat model

| Threat | Mitigation |
|--------|-----------|
| False registration | Identity verification required (BankID or email+phone OTP) |
| PID rainbow tables | HMAC pepper eliminates precomputed tables (section 3.2) |
| Hash collision | SHA-256: ~2^128 operations required — computationally infeasible |
| Blockchain manipulation | BSV: proof-of-work consensus, economically infeasible to alter |
| Unauthorized transfer | Requires owner's derived key (identity + 256-bit salt) |
| Database breach | Identity stored only as peppered HMAC hash; salt alone is useless without identity |
| Service compromised | Existing proofs are NOT invalidated — they live on-chain |
| Key derivation server down | Algorithm is published — anyone with the salt can run it (section 7.3) |

### 8.2 Entropy and salt-based security

Key derivation uses a per-user 256-bit random salt (presentation key) concatenated with the identity input before HKDF extraction. This eliminates the brute-force vulnerability that existed in protocol versions prior to v0.6.0.

**Security analysis:**

| Attack | Without salt (v0.5.0) | With salt (v0.6.0) |
|--------|----------------------|-------------------|
| Brute-force PID → key | ~5M attempts (~seconds) | ~2^256 attempts (infeasible) |
| Rainbow table on PIDs | Mitigated by HMAC pepper only | Salt adds 256 bits; infeasible |
| Address → identity linkage | Possible by trying all PIDs | Requires salt (server-held) |
| Unauthorized UTXO transfer | Possible if PID known | Requires identity + salt |

**The salt resolves the "verifier paradox"** of earlier versions: verification no longer requires the ability to derive the private key. The public `/api/verify-address` endpoint confirms address ownership without exposing the salt.

**Remaining limitations:**
- Server-side key derivation means the user does not have sole control of signing keys. This protocol produces Simple Electronic Signatures (SES) under eIDAS, not Advanced (AES) or Qualified (QES).
- The salt is a single point of failure — if lost and no backup exists, the derived keys cannot be recreated. Services SHOULD provide salt export/backup mechanisms.
- For custody of high-value digital assets or eIDAS AES/QES requirements, use independently generated keypairs (hardware wallets, WebAuthn/Passkeys, or EUDI Wallet — see section 8.3).

### 8.3 Privacy (GDPR)

**Important regulatory note:** Under EDPB and CNIL guidance, HMAC-hashed identity data constitutes **pseudonymization, not anonymization**. Pseudonymized data remains personal data under GDPR. This has specific implications for this protocol:

- **On-chain data is immutable.** Identity hashes written to BSV cannot be deleted, which conflicts with GDPR Article 17 (right to erasure).
- **Mitigation:** The on-chain proof_hash does not contain identity data directly. The identity_hash appears only in the inscription metadata. Future versions should move identity_hash off-chain entirely, storing only the proof_hash on-chain.
- **Crypto-shredding:** If the HMAC pepper is rotated or destroyed, existing on-chain hashes become computationally irreversible (effective erasure). However, this is only effective if the pepper has never been compromised and input entropy is sufficient.

Current privacy properties:
- Personal IDs (PID) are NEVER stored in cleartext — only peppered HMAC hashes
- On-chain inscriptions contain proof_hash + category — no raw personal data
- Owner can request deletion of all server-side data (GDPR art. 17)
- On-chain hashes are retained as pseudonymized data

**Planned improvements (eIDAS 2.0 / EUDI Wallet integration):**
- User-generated keypairs on-device (eliminates identity-derived keys)
- No identity data on-chain whatsoever
- Verification via wallet-issued attestations instead of deterministic derivation

---

## 9. Protocol Constants

All constants are public. This is by design — the security model does not depend on any constant being secret.

| Constant | Value | Used for |
|----------|-------|----------|
| Protocol version | `"beviset-v1"` | Proof hash preimage |
| PID pepper | `"beviset-protocol-pid-pepper-v1-datamynt"` | Identity hashing (BankID) |
| Identity pepper (email+phone) | `"beviset-protocol-identity-pepper-v1-datamynt"` | Identity hashing (email+phone) |
| Key domain (BankID) | `"wab-keygen-beviset-v1"` | HKDF-Extract |
| Key domain (email+phone) | `"beviset-v1-keygen-emailphone"` | HKDF-Extract |
| Key domain (email) | `"beviset-v1-keygen-email"` | HKDF-Extract |
| HKDF info (base) | `"bitcoin-key-derivation" \|\| 0x01` | HKDF-Expand (no keyID) |
| HKDF info (child) | `"bitcoin-key-derivation:" \|\| key_id \|\| 0x01` | HKDF-Expand (with keyID) |
| Salt size | 256 bits (64 hex chars) | Per-user presentation key |
| Inscription content-type | `application/json` | 1SatOrdinal metadata |

---

## 10. EUDI Migration Path

### 10.1 Identity upgrade via UTXO transfer

Because each ownership certificate is a 1SatOrdinal UTXO, a user can **upgrade their identity method** without losing the proof. The inscription (proof hash, timestamp, category) is permanently on-chain. Only the holder address changes.

```
Migration flow:
  1. User verifies with new identity method (e.g., EUDI Wallet)
  2. Service derives new Bitcoin address from EUDI identity
  3. User signs a transfer TX: old address → new EUDI address
  4. The UTXO chain now shows: registration → identity upgrade
  5. The inscription is unchanged — the proof is intact
```

This is a standard Bitcoin transaction — no protocol changes are needed. The UTXO model natively supports identity migration.

### 10.2 EUDI Wallet integration (planned, 2027+)

When EUDI Wallet (eIDAS 2.0) becomes available, it provides:

- **Free identity verification** — state infrastructure, no per-transaction BankID cost
- **Qualified Electronic Signature (QES)** — highest legal signature level under eIDAS
- **On-device key generation** — the user has sole control of their signing key
- **Selective disclosure** — share only the attributes needed (e.g., full name without PID)

EUDI-based key derivation will use the same HKDF-SHA256 algorithm (section 4.1) with a new domain separator (e.g., `"beviset-v1-keygen-eudi"`). Alternatively, the EUDI Wallet may provide its own signing keys directly, eliminating server-side key derivation entirely.

### 10.3 Backwards compatibility

- Existing proofs remain valid — inscriptions are immutable
- The `/api/verify-address` endpoint will support EUDI identity alongside BankID/email+phone
- UTXO chain verification naturally includes migration transactions
- Old identity methods continue to work — EUDI is additive, not a replacement

---

## 11. References

- SHA-256: FIPS PUB 180-4
- HMAC: RFC 2104
- HKDF: RFC 5869
- secp256k1: SEC 2, section 2.7.1
- BRC-22: ARC Transaction Lifecycle (broadcasting + callbacks)
- BRC-62: BEEF — Background Evaluation Extended Format
- BRC-74: BSV Unified Merkle Path (BUMP)
- 1SatOrdinals: https://docs.1satordinals.com
- BSV SDK (Python): https://github.com/bsv-blockchain/py-sdk
- BankID OIDC: https://confluence.bankidnorge.no
- eIDAS: Regulation (EU) No 910/2014
- eIDAS 2.0: Regulation (EU) 2024/1183 (EUDI Wallet)

---

*Verification requires only math, not trust.*
