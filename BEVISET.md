# Beviset Protocol — Digital Ownership Certificates on Bitcoin SV

**Version:** 0.3.0
**Date:** 2026-03-15
**License (specification):** MIT
**License (implementations):** Open BSV License

---

## 1. Summary

Beviset Protocol is an open standard for registering, verifying, and transferring digital ownership certificates anchored to the Bitcoin SV blockchain.

The core property: **anyone can verify ownership independently**, without relying on any server or service provider. All algorithms and constants are published. The blockchain is public. Verification requires only math.

**Core principle:** The proof is a satoshi. The owner holds the satoshi. The UTXO chain IS the ownership history.

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

def derive_bitcoin_key(identity_input: str, domain: str) -> bytes:
    """
    Deterministic Bitcoin key from identity.

    Uses HKDF-SHA256 (RFC 5869):
      Extract: PRK = HMAC-SHA256(domain, identity_input)
      Expand:  OKM = HMAC-SHA256(PRK, "bitcoin-key-derivation" || 0x01)

    Returns 32 bytes — a valid secp256k1 private key.
    """
    # HKDF-Extract
    prk = hmac.new(
        domain.encode("utf-8"),
        identity_input.encode("utf-8"),
        hashlib.sha256,
    ).digest()

    # HKDF-Expand (single block = 32 bytes = 256 bits)
    okm = hmac.new(
        prk,
        b"bitcoin-key-derivation\x01",
        hashlib.sha256,
    ).digest()

    return okm  # 32 bytes = valid secp256k1 private key
```

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
                      address = P2PKH(derive_bitcoin_key(identity, domain))
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

### 7.2 Privacy (GDPR)

- Personal IDs (PID) are NEVER stored — only peppered HMAC hashes
- On-chain inscriptions contain only hash + category — no personal data
- Public verification reveals existence and blockchain status, not item details
- Owner can request deletion of server-side data (GDPR art. 17)
- On-chain hash is retained (not personal data — irreversible)

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
| HKDF info | `"bitcoin-key-derivation" \|\| 0x01` | HKDF-Expand |
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
