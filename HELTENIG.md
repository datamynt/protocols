# Helt Enig Protocol — Digital Contract Signing on Bitcoin SV

**Version:** 0.5.0
**Date:** 2026-03-19
**License (specification):** MIT
**License (implementations):** Open BSV License

---

## 1. Summary

Helt Enig Protocol is an open standard for multi-party contract signing anchored to the Bitcoin SV blockchain. Each signer receives a 1SatOrdinal inscription at their Bitcoin address. The contract text is never stored on-chain — only a cryptographic hash.

Three identity methods are supported: BankID (government ID), email+phone (OTP verification), and BSV wallet (self-sovereign, BRC-100). The BSV identity path requires no intermediary — users sign with their own keys.

**Core principle:** The contract hash proves *what* was agreed. The UTXO proves *who* agreed. The blockchain proves *when*.

---

## 2. Architecture

```
┌──────────────────────────────────────────────────────┐
│  Service layer (e.g. heltenig.no)                    │
│  Identity verification · Templates · Multi-party flow │
└───────────────────────┬──────────────────────────────┘
                        │
┌───────────────────────▼──────────────────────────────┐
│  Anchoring service                                   │
│  1SatOrdinal inscriptions · UTXO management          │
└───────────────────────┬──────────────────────────────┘
                        │
┌───────────────────────▼──────────────────────────────┐
│  Key derivation (published HKDF-SHA256 algorithm)    │
│  Identity + salt → Bitcoin key (BankID/email+phone)  │
│  OR: user's own BSV wallet key (BRC-100)             │
└───────────────────────┬──────────────────────────────┘
                        │
┌───────────────────────▼──────────────────────────────┐
│  Bitcoin SV blockchain                               │
│  1SatOrdinals · One inscription per signer           │
└──────────────────────────────────────────────────────┘
```

Each layer can be replaced independently. The protocol survives any single service shutting down.

---

## 3. Identity Hashing

Identity inputs must be hashed with a protocol pepper before use. This defends against rainbow tables — Norwegian personal IDs have only ~5 million valid combinations.

### 3.1 BankID (PID)

```python
import hashlib
import hmac

PID_PEPPER = "beviset-protocol-pid-pepper-v1-datamynt"

def compute_identity_hash_bankid(pid: str) -> str:
    """HMAC-SHA256 with protocol pepper. Shared with Beviset Protocol."""
    return hmac.new(
        PID_PEPPER.encode("utf-8"),
        pid.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
```

Note: The BankID pepper is shared with Beviset Protocol for cross-service interoperability.

### 3.2 Email + Phone

```python
IDENTITY_PEPPER = "heltenig-protocol-identity-pepper-v1-datamynt"

def compute_identity_hash_emailphone(email: str, phone: str) -> str:
    """HMAC-SHA256 with protocol pepper. Canonical form: lowercase email, trimmed."""
    canonical = f"email:{email.strip().lower()}|phone:{phone.strip()}"
    return hmac.new(
        IDENTITY_PEPPER.encode("utf-8"),
        canonical.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
```

### 3.3 BSV Wallet (BRC-100)

```python
BSV_IDENTITY_PEPPER = "heltenig-protocol-bsv-identity-pepper-v1-datamynt"

def compute_identity_hash_bsv(identity_key: str) -> str:
    """HMAC-SHA256 with protocol pepper. Input is the user's BSV public key."""
    return hmac.new(
        BSV_IDENTITY_PEPPER.encode("utf-8"),
        identity_key.strip().encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
```

For BSV identity, the `identity_key` is the user's compressed public key (33 bytes, 66 hex chars). The user proves ownership via BRC-3 digital signature (challenge-response). No server-side key derivation is needed — the user's wallet address IS their signing address.

---

## 4. Contract Hash

### 4.1 Input fields

| Field | Type | Description |
|-------|------|-------------|
| `protocol_marker` | string | Always `"HELTENIG-v1"` |
| `content_hash` | string | SHA-256 of the full contract text (UTF-8) |
| `sorted_signers` | string | Identity hashes joined with `\|`, sorted lexicographically |
| `template_id` | string | Contract type (e.g. `"bil_kjop"`, `"husleie"`) |
| `signed_at` | integer | Unix timestamp (seconds) |

### 4.2 Computation

```python
def compute_contract_hash(
    contract_text: str,
    identity_hashes: list[str],   # One per signer (2 or more)
    template_id: str,
    signed_at: int,
) -> str:
    """Compute the contract hash that gets inscribed on-chain."""
    content_hash = hashlib.sha256(contract_text.encode("utf-8")).hexdigest()

    sorted_signers = "|".join(sorted(identity_hashes))

    preimage = "\n".join([
        "HELTENIG-v1",
        content_hash,
        sorted_signers,
        template_id,
        str(signed_at),
    ])

    return hashlib.sha256(preimage.encode("utf-8")).hexdigest()
```

### 4.3 Properties

- **Deterministic:** Same inputs always produce the same hash.
- **Order-independent:** Signers are sorted lexicographically — signing order doesn't change the hash.
- **N-party:** Supports any number of signers (2 or more). All identity hashes are included in the preimage.
- **Privacy-preserving:** Contract text is hashed, never stored on-chain.
- **Tamper-evident:** Any change to the contract text, signers, or timestamp produces a different hash.

---

## 5. Key Derivation

Same salted HKDF-SHA256 algorithm as Beviset Protocol (see Beviset Protocol section 4), with different domain separators. A per-user 256-bit random salt prevents brute-force derivation.

**BSV identity (BRC-100) does NOT use server-side key derivation.** Users sign with their own wallet keys directly. This section applies only to BankID and email+phone identity methods.

### 5.1 Algorithm (salted HKDF-SHA256)

```python
def derive_bitcoin_key(
    identity_input: str,
    domain: str,
    salt: str,             # 256-bit random hex (user's presentation key)
    key_id: str = None,
) -> bytes:
    """
    HKDF-SHA256 (RFC 5869) with per-user salt:
      IKM     = identity_input || salt
      Extract: PRK = HMAC-SHA256(domain, IKM)
      Expand:  OKM = HMAC-SHA256(PRK, info)

    The salt prevents brute-force even for BankID PIDs (~5M valid values).

    Info string:
      Without key_id: "bitcoin-key-derivation" || 0x01          (base key)
      With key_id:    "bitcoin-key-derivation:" || key_id || 0x01 (child key)

    Returns 32 bytes — a valid secp256k1 private key.
    """
    ikm = identity_input + salt
    prk = hmac.new(
        domain.encode("utf-8"),
        ikm.encode("utf-8"),
        hashlib.sha256,
    ).digest()

    if key_id:
        info = f"bitcoin-key-derivation:{key_id}".encode("utf-8") + b"\x01"
    else:
        info = b"bitcoin-key-derivation\x01"

    okm = hmac.new(
        prk,
        info,
        hashlib.sha256,
    ).digest()

    return okm
```

For child key derivation details, see Beviset Protocol section 4.1.1. The same keyID mechanism applies — use the contract hash as `key_id` so each contract signing produces unique addresses for all signers.

### 5.2 Domain separators

| Identity type | Domain separator |
|--------------|------------------|
| BankID (PID) | `"wab-keygen-heltenig-v1"` |
| Email + Phone | `"heltenig-v1-keygen-emailphone"` |
| BSV Wallet | N/A — user's own key |

Different domain separators ensure separate key spaces. The same person using BankID and email+phone gets different Bitcoin addresses — by design. BSV wallet users use their own address directly.

### 5.3 Address derivation

For BankID and email+phone (server-derived):
```
private_key = derive_bitcoin_key(identity_input, domain, salt)
public_key  = secp256k1_multiply(G, private_key)  # compressed, 33 bytes
address     = P2PKH(public_key)                    # standard Bitcoin address
```

For BSV wallet (self-sovereign):
```
address = user's own wallet address (P2PKH)
public_key = user's identity key (provided during BRC-103 handshake)
```

---

## 6. Signing Flow

```
Party A                    Service                  Party B (+ more)
  │                          │                          │
  ├─ Select template ───────►│                          │
  ├─ Fill Party A fields ───►│                          │
  ├─ Pay (fiat or BSV) ─────►│                          │
  │                          ├─ Send invite(s) ────────►│
  │                          │                          ├─ Open invite
  │                          │◄──── Fill Party B fields─┤
  │                          │                          │
  ├─ Verify identity ───────►│◄──── Verify identity ────┤
  │   (BankID/email/BSV)     │      (BankID/email/BSV)  │
  ├─ Sign ──────────────────►│◄──── Sign ───────────────┤
  │                          │                          │
  │                          ├─ Merge all fields        │
  │                          ├─ Generate contract text  │
  │                          ├─ Compute contract hash   │
  │                          ├─ Inscribe for each signer│
  │                          │                          │
  │◄── PDF + TXID ──────────┤──── PDF + TXID ─────────►│
```

Key points:
- The final contract text is generated only after **all** parties have filled their fields.
- The contract hash is computed from the **complete** merged text — not from partial data.
- Each signer receives their own 1SatOrdinal inscription at their address.
- The contract hash in all inscriptions is identical — they signed the same document.
- Each party can use a different identity method (BankID, email+phone, or BSV wallet).
- BSV wallet signers use their own key — no server-side derivation.

---

## 7. Inscription Format

Each signer receives a 1SatOrdinal with this JSON payload:

```json
{
    "protocol": "HELTENIG-v1",
    "type": "contract",
    "hash": "<contract_hash>",
    "template": "<template_id>",
    "role": "part_a",
    "signer_hash": "<identity_hash>",
    "identity_type": "emailphone",
    "signers_count": 2,
    "signed_at": 1710288000,
    "issuer": "heltenig.no"
}
```

| Field | Description |
|-------|-------------|
| `protocol` | Always `"HELTENIG-v1"` |
| `type` | Always `"contract"` |
| `hash` | The contract hash (section 4) |
| `template` | Contract template identifier |
| `role` | `"part_a"` or `"part_b"` |
| `signer_hash` | This signer's identity hash (section 3) |
| `identity_type` | `"emailphone"`, `"bankid"`, or `"bsv"` |
| `signers_count` | Number of signers (2 or more) |
| `signed_at` | Unix timestamp |
| `issuer` | Service that facilitated the signing |

The inscription is sent to the signer's HKDF-derived Bitcoin address. They hold it as a UTXO — no service can revoke it.

---

## 8. Transaction Verification (BEEF / SPV)

### 8.1 BEEF format (BRC-62)

Implementations SHOULD store all contract inscription transactions in **BEEF** (Background Evaluation Extended Format, BRC-62). BEEF bundles raw transaction data with Merkle proofs (BUMPs, BRC-74) into a single self-verifying package.

**Why BEEF matters for contract proofs:**
- Each signer's inscription in BEEF format is **independently verifiable** — no trusted third party needed
- The Merkle path proves the TX is included in a specific block at a specific height
- BEEF can be embedded in signed PDF contracts alongside the salt, making the PDF a complete verification bundle
- Both parties receive BEEF-wrapped inscriptions — either can prove the contract existed

### 8.2 SPV verification and confirmation depth

Simplified Payment Verification (SPV) confirms that a transaction is included in a block without downloading the entire blockchain.

```
SPV verification per signer:
  1. Extract TX and Merkle path from BEEF
  2. Compute Merkle root from TX hash + path
  3. Verify Merkle root matches the block header at the claimed height
  4. Check confirmation depth (deeper = stronger)

Confirmation depth guidelines:
  depth >= 1      Transaction is mined (basic confidence)
  depth >= 6      Standard Bitcoin confirmation threshold
  depth >= 100    Strong proof — reorganization extremely unlikely
```

For contract signing, all signers' inscriptions should be in the same block or adjacent blocks. Implementations SHOULD batch all signer inscriptions into a single transaction where possible.

### 8.3 ARC callbacks and broadcaster failover

Same ARC callback pattern as Beviset Protocol section 6.3. When inscriptions are broadcast via ARC, the Merkle path callback upgrades the stored BEEF from "broadcast" to "SPV-verified".

Implementations SHOULD use sequential broadcaster failover (ARC TAAL → ARC GorillaPool → WhatsOnChain → direct broadcast) for maximum reliability.

---

## 9. Identity Verification

### 9.1 Online verification (primary)

The key derivation service provides a public endpoint for address verification:

```
POST /api/verify-address
{
  "identity_type": "bankid" | "emailphone",
  "pid": "12345678901",
  "email": "user@example.com",
  "phone": "+4712345678",
  "purpose": "heltenig-v1",
  "address": "1Abc...",
  "keyID": "<contract_hash>"
}

Response: { "verified": true }
```

For BSV wallet signers, verification is simpler: the inscription TXID shows which address holds it, and the BSV public key in the signer's identity hash can be verified against the address directly.

### 9.2 Full verification flow

```
Given: contract text, signer identities, template_id, timestamp

Step 1 — Identity hashes:
  For email+phone:   HMAC-SHA256(emailphone_pepper, canonical)
  For BankID:        HMAC-SHA256(pid_pepper, pid)
  For BSV wallet:    HMAC-SHA256(bsv_pepper, identity_key)

Step 2 — Contract hash:
  content_hash = SHA-256(contract_text)
  sorted_signers = sort(all identity_hashes) joined with "|"
  preimage = "HELTENIG-v1\n" + content_hash + "\n" + sorted_signers
             + "\n" + template_id + "\n" + timestamp
  contract_hash = SHA-256(preimage)

Step 3 — Verify addresses:
  For BankID/email: POST /api/verify-address with identity + address + keyID
  For BSV wallet:   verify P2PKH(identity_key) matches inscription address

Step 4 — Check blockchain:
  Look up inscriptions at each signer's address
  Verify inscription hash matches computed contract_hash  ✓
  Verify inscriptions exist at verified addresses          ✓

Result: Contract verified.
```

### 9.3 Offline verification (with salt backup)

For BankID/email+phone signers, offline verification requires the user's salt (presentation key). The salt can be embedded in the signed PDF or exported by the user.

For BSV wallet signers, offline verification needs only the user's public key — no salt or server required.

**Dependencies for independent verification:**
- This specification (published, MIT license)
- The contract text (from PDF or backup)
- Signer identities (email+phone, PID, or BSV public key)
- User salt / presentation key (for BankID/email+phone signers)
- Access to BSV blockchain (any node or block explorer)
- SHA-256 + HMAC-SHA256 + HKDF-SHA256 + secp256k1 (standard cryptography)

---

## 10. Ricardian Contract Templates

The protocol supports structured templates where fields are tagged by party:

```json
{
    "id": "bil_kjop",
    "name": "Vehicle Purchase Agreement",
    "sections": [
        { "id": "seller", "party": "a", "fields": [...] },
        { "id": "buyer", "party": "b", "fields": [...] },
        { "id": "vehicle", "party": "shared", "fields": [...] }
    ]
}
```

Party tags (`"a"`, `"b"`, `"shared"`) control which party fills which fields. The service merges all data and generates the final contract text from the template. This text is what gets hashed.

Templates are a service-layer concern. The protocol itself only requires: contract text + signers + timestamp.

---

## 11. Security

### 11.1 Threat model

| Threat | Mitigation |
|--------|-----------|
| Forged signature | Identity verification required (BankID, email+phone OTP, or BSV wallet signature) |
| Contract text altered | SHA-256 hash of text is part of contract hash |
| Signer identity spoofed | HMAC-peppered identity hash + key derivation |
| Service goes down | Proofs live on-chain; this spec enables independent verification |
| Rainbow tables on PID | HMAC pepper eliminates precomputed tables |
| Service revokes contract | Impossible — inscriptions are UTXOs held by signers |
| One party denies signing | Blockchain proves inscription at their derived/wallet address |

### 11.2 Entropy and salt-based security

Same salted HKDF algorithm as Beviset Protocol section 8.2. Per-user 256-bit random salt eliminates the brute-force vulnerability of earlier versions. The keyID mechanism (section 5.1) prevents cross-contract linkability.

**BSV wallet identity has no entropy concern** — the user controls their own private key with full 256-bit entropy. No server-side derivation involved.

### 11.3 Privacy (GDPR)

**Important regulatory note:** HMAC-hashed identity data constitutes pseudonymization, not anonymization under EDPB/CNIL guidance. Pseudonymized data remains personal data under GDPR. See Beviset Protocol section 8.3 for full analysis.

Current privacy properties:
- Personal IDs are never stored on-chain in cleartext — only peppered HMAC hashes
- Contract text is never on-chain — only SHA-256 hash
- Inscriptions reveal existence and signing time, not content
- Signers can request deletion of all server-side data (GDPR art. 17)
- On-chain hashes are retained as pseudonymized data

**Planned:** Migration to EUDI Wallet-based signing (eIDAS 2.0) will eliminate identity-derived keys and remove all identity data from chain.

### 11.4 Legal basis

**Email+phone and BankID (server-derived keys):** These constitute Simple Electronic Signatures (SES) under eIDAS (EU 910/2014). They do NOT meet the "sole control" requirement for Advanced Electronic Signatures, as the signing key is derived server-side rather than held exclusively by the signatory.

**BSV wallet (self-sovereign keys):** The user holds their own private key, satisfying the sole control requirement. With a BRC-52 identity certificate from a trusted certifier, this can constitute an Advanced Electronic Signature (AES) under eIDAS.

All signature types are legally admissible as evidence of agreement in Norway (avtaleloven § 1) and the EU. The blockchain provides:
- Timestamped proof that an agreement was recorded
- Tamper-evident hash of the contract text
- Identity binding via verified identity (BankID PID, email+phone OTP, or BSV key ownership)

For Qualified Electronic Signatures (QES), use BankID's native signing service or an EUDI Wallet (future).

---

## 12. Protocol Constants

All constants are public. Security does not depend on any constant being secret.

| Constant | Value | Used for |
|----------|-------|----------|
| Protocol marker | `"HELTENIG-v1"` | Contract hash preimage |
| PID pepper (BankID) | `"beviset-protocol-pid-pepper-v1-datamynt"` | Identity hashing (shared with Beviset) |
| Identity pepper (email+phone) | `"heltenig-protocol-identity-pepper-v1-datamynt"` | Identity hashing |
| Identity pepper (BSV) | `"heltenig-protocol-bsv-identity-pepper-v1-datamynt"` | Identity hashing (BSV pubkey) |
| Key domain (BankID) | `"wab-keygen-heltenig-v1"` | HKDF-Extract |
| Key domain (email+phone) | `"heltenig-v1-keygen-emailphone"` | HKDF-Extract |
| Salt size | 256 bits (64 hex chars) | Per-user presentation key |
| HKDF info (base) | `"bitcoin-key-derivation" \|\| 0x01` | HKDF-Expand (no keyID) |
| HKDF info (child) | `"bitcoin-key-derivation:" \|\| key_id \|\| 0x01` | HKDF-Expand (with keyID) |
| Inscription content-type | `application/json; charset=utf-8` | 1SatOrdinal metadata |

---

## 13. EUDI Migration Path

### 13.1 Identity upgrade via UTXO transfer

Each signer's contract proof is a 1SatOrdinal UTXO. When a signer upgrades their identity method (e.g., from email+phone to EUDI Wallet), the satoshi can be transferred to the new identity's address. The inscription (contract hash, timestamp, parties) is permanent — only the holder changes.

```
Migration flow (per signer):
  1. Signer verifies with EUDI Wallet
  2. Service derives new Bitcoin address from EUDI identity
  3. Signer's 1sat inscription is transferred: old address → EUDI address
  4. UTXO chain shows: original signing → identity upgrade
  5. Contract hash in inscription is unchanged
```

Each signer migrates independently — no coordination between parties is needed.

### 13.2 EUDI Wallet integration (planned, 2027+)

EUDI Wallet provides free QES (Qualified Electronic Signatures) for all EU/EEA citizens. For contract signing, this is transformative:

- **QES by default** — the highest legal signature level, at zero marginal cost
- **On-device keys** — true sole control, satisfying eIDAS Art. 26 (AES) and Art. 3.12 (QES)
- **Cross-border** — contracts signed with EUDI are legally valid across the entire EEA
- **No intermediary** — similar to BSV wallet identity, the user controls their own keys

Combined with blockchain anchoring, EUDI + 1SatOrdinal provides the strongest possible digital contract: QES-level identity + immutable timestamp + tamper-evident hash.

### 13.3 Pricing impact

| Identity method | Current cost | With EUDI |
|----------------|-------------|-----------|
| Email + SMS | ~2.20 kr | N/A |
| BankID | ~4.60 kr | 0 kr (replaced by EUDI) |
| BSV Wallet | ~0.01 kr | ~0.01 kr (unchanged) |
| EUDI Wallet | N/A | ~0.01 kr (free identity + BSV TX fee) |

EUDI eliminates the per-transaction identity cost. The remaining cost is the blockchain anchoring fee (~0.01 kr per inscription).

---

## 14. Relationship to Beviset Protocol

Helt Enig and Beviset share the same cryptographic foundation:

| | Beviset | Helt Enig |
|---|---------|-----------|
| Purpose | Ownership certificates | Contract signatures |
| Signers | 1 (owner) | 2+ (parties) |
| On-chain data | Proof hash | Contract hash |
| Transfer | Send the satoshi | Not transferable |
| Key derivation | Salted HKDF-SHA256 | Salted HKDF-SHA256 (or user's own BSV key) |
| Identity methods | BankID, email+phone, email | BankID, email+phone, BSV wallet (BRC-100) |
| BankID pepper | Shared | Shared |
| Domain separators | `beviset-v1-*` | `heltenig-v1-*` |

Both protocols use independent domain separators, so the same identity produces different Bitcoin addresses per service.

---

## 15. References

- SHA-256: FIPS PUB 180-4
- HMAC: RFC 2104
- HKDF: RFC 5869
- secp256k1: SEC 2, section 2.7.1
- BRC-22: ARC Transaction Lifecycle (broadcasting + callbacks)
- BRC-62: BEEF — Background Evaluation Extended Format
- BRC-74: BSV Unified Merkle Path (BUMP)
- 1SatOrdinals: https://docs.1satordinals.com
- Beviset Protocol: [BEVISET.md](./BEVISET.md)
- BRC-100: BSV Unified Wallet Interface
- BRC-3: BSV Digital Signatures
- BRC-52: BSV Identity Certificates
- BRC-103: Peer-to-Peer Mutual Authentication
- eIDAS: Regulation (EU) No 910/2014
- eIDAS 2.0: Regulation (EU) 2024/1183 (EUDI Wallet)

---

*The blockchain proves the agreement existed. Your keys prove you agreed. This specification proves it can be verified.*
