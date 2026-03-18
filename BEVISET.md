# Beviset Protocol — Digital Ownership Certificates on Bitcoin SV

**Version:** 0.5.0
**Date:** 2026-03-18
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
│  Identity → deterministic Bitcoin key → address      │
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

This is the critical piece that makes verification trustless. The same identity input deterministically produces the same Bitcoin address — no secrets, no server dependency.

### 4.1 Algorithm: HKDF-SHA256

```python
import hashlib
import hmac

# Domain separator — different per application to keep key spaces independent.
# Beviset uses: "beviset-v1-keygen"
# Other services define their own domain separators.

def derive_bitcoin_key(identity_input: str, domain: str, key_id: str = None) -> bytes:
    """
    Deterministic Bitcoin key from identity.

    Uses HKDF-SHA256 (RFC 5869):
      Extract: PRK = HMAC-SHA256(domain, identity_input)
      Expand:  OKM = HMAC-SHA256(PRK, info)

    Info string:
      Without key_id: "bitcoin-key-derivation" || 0x01          (base key)
      With key_id:    "bitcoin-key-derivation:" || key_id || 0x01 (child key)

    The key_id parameter enables unique addresses per registration/transaction
    while maintaining backwards compatibility (omitting key_id = same key as before).

    Returns 32 bytes — a valid secp256k1 private key.
    """
    # HKDF-Extract
    prk = hmac.new(
        domain.encode("utf-8"),
        identity_input.encode("utf-8"),
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
2. Recompute the expected address: `derive_bitcoin_key(identity, domain, proof_hash)`
3. Confirm the inscription lives at that address

No server or database lookup is needed — the keyID is self-contained in the inscription.

**Backwards compatibility:** Omitting `key_id` produces the same key as before. Existing inscriptions at base addresses remain valid.

### 4.2 Address derivation

```
private_key = derive_bitcoin_key(identity_input, domain)
public_key  = secp256k1_multiply(G, private_key)  # compressed, 33 bytes
address     = P2PKH(public_key)                    # standard Bitcoin address
```

### 4.3 Domain separators

Each application uses a unique domain separator so the same identity produces different keys per service:

| Application | Identity type | Domain separator |
|-------------|--------------|------------------|
| Beviset (BankID) | PID | `"beviset-v1-keygen"` |
| Beviset (email+phone) | canonical string | `"beviset-v1-keygen-emailphone"` |
| Helt Enig (BankID) | PID | `"heltenig-v1-keygen"` |
| Helt Enig (email+phone) | canonical string | `"heltenig-v1-keygen-emailphone"` |

### 4.4 Why this matters

The key derivation algorithm is **published and deterministic**. This means:

1. Given someone's identity (BankID PID or email+phone), anyone can derive their Bitcoin address.
2. You can look up that address on the blockchain to find their inscriptions.
3. You can verify the inscription hash matches the claimed data.
4. **No server, no database, no trust required.** Only: identity + blockchain + SHA-256 + this document.

This is what makes the system survive its creator. If every server shuts down tomorrow, the proofs still live on-chain and can be verified by anyone with this specification.

### 4.5 Security properties

| Concern | Mitigation |
|---------|-----------|
| Key derivation server compromised | Algorithm is published — anyone can run it |
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

## 6. Verification Without Any Server

Anyone with internet access can verify an ownership proof:

1. **Obtain the inscription TXID** (from PDF certificate, database dump, or user claim)
2. **Follow the UTXO chain** to the current holder's address
3. **Derive the expected address** from the claimed owner's identity using the published key derivation algorithm (section 4)
4. **Check that the addresses match** — holder's address = derived address
5. **Verify the proof hash** — recompute from claimed data using section 3, check it matches the inscription

```
Claimed owner provides: identity + item serial + category + registration time
                               ↓
Verifier computes:    identity_hash = HMAC-SHA256(pepper, identity)
                      proof_hash = SHA-256(preimage)
                      address = P2PKH(derive_bitcoin_key(identity, domain, proof_hash))
                               ↓
Verifier checks:      proof_hash matches inscription on-chain?  ✓
                      address matches current UTXO holder?      ✓
                               ↓
                      Ownership verified. No server needed.
```

**Dependencies for independent verification:**
- This specification (published, MIT license)
- Access to BSV blockchain (any node or block explorer)
- SHA-256 + HMAC-SHA256 + HKDF-SHA256 (standard cryptography)
- secp256k1 (standard elliptic curve)
- The owner's identity claim (PID or email+phone)

---

## 7. Security

### 7.1 Threat model

| Threat | Mitigation |
|--------|-----------|
| False registration | Identity verification required (BankID or email+phone OTP) |
| PID rainbow tables | HMAC pepper eliminates precomputed tables (section 3.2) |
| Hash collision | SHA-256: ~2^128 operations required — computationally infeasible |
| Blockchain manipulation | BSV: proof-of-work consensus, economically infeasible to alter |
| Unauthorized transfer | Requires owner's derived key (derived from BankID or email+phone) |
| Database breach | Identity stored only as peppered HMAC hash, never in plaintext |
| Service compromised | Existing proofs are NOT invalidated — they live on-chain |
| Key derivation server down | Algorithm is published — anyone can run it |

### 7.2 Entropy, key derivation, and deliberate tradeoffs

**Important:** The key derivation algorithm produces a *private key* from identity inputs. For PID-based derivation (~33 bits of entropy, ~5 million valid values), an attacker can brute-force all valid PIDs in seconds to:

1. **Derive the private key** for any inscription (given the on-chain proof_hash as keyID)
2. **Transfer the 1SatOrdinal** to a different address (unauthorized ownership transfer)
3. **Identify the owner's PID** by matching derived addresses against on-chain data

**This is a known and accepted tradeoff for this protocol's use case.** The rationale:

- The 1SatOrdinal has no monetary value (~0.00001 USD). Economic incentive for theft is zero.
- The original registration and full transfer history remain permanently visible on-chain. Unauthorized transfers are forensically detectable.
- The protocol's core value is *proof of existence and provenance*, not custodial asset security.
- Verification without any server requires that addresses are derivable from identity — this inherently means the private key is also derivable.

**For email+phone derivation**, entropy is significantly higher (email address + phone number combination), making brute-force impractical without prior knowledge of both inputs.

**The keyID mechanism** (section 4.1.1) mitigates *linkability*: even after deriving one address, an attacker cannot discover other registrations by the same identity without knowing their proof hashes.

**This protocol is NOT suitable for:**
- Custody of high-value digital assets
- Scenarios requiring "sole control" over signing keys (eIDAS Advanced/Qualified signatures)
- Applications where unauthorized UTXO transfer has material consequences

For such use cases, use independently generated keypairs with proper key management (hardware wallets, WebAuthn/Passkeys) and an identity attestation model instead of deterministic derivation.

### 7.3 Privacy (GDPR)

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

## 8. Protocol Constants

All constants are public. This is by design — the security model does not depend on any constant being secret.

| Constant | Value | Used for |
|----------|-------|----------|
| Protocol version | `"beviset-v1"` | Proof hash preimage |
| PID pepper | `"beviset-protocol-pid-pepper-v1-datamynt"` | Identity hashing (BankID) |
| Identity pepper (email+phone) | `"beviset-protocol-identity-pepper-v1-datamynt"` | Identity hashing (email+phone) |
| Key domain (BankID) | `"beviset-v1-keygen"` | HKDF-Extract |
| Key domain (email+phone) | `"beviset-v1-keygen-emailphone"` | HKDF-Extract |
| HKDF info (base) | `"bitcoin-key-derivation" \|\| 0x01` | HKDF-Expand (no keyID) |
| HKDF info (child) | `"bitcoin-key-derivation:" \|\| key_id \|\| 0x01` | HKDF-Expand (with keyID) |
| Inscription content-type | `application/json` | 1SatOrdinal metadata |

---

## 9. References

- SHA-256: FIPS PUB 180-4
- HMAC: RFC 2104
- HKDF: RFC 5869
- secp256k1: SEC 2, section 2.7.1
- 1SatOrdinals: https://docs.1satordinals.com
- BSV SDK (Python): https://github.com/bsv-blockchain/py-sdk
- BankID OIDC: https://confluence.bankidnorge.no

---

*Verification requires only math, not trust.*
