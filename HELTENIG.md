# Helt Enig Protocol — Digital Contract Signing on Bitcoin SV

**Version:** 0.3.0
**Date:** 2026-03-18
**License (specification):** MIT
**License (implementations):** Open BSV License

---

## 1. Summary

Helt Enig Protocol is an open standard for two-party contract signing anchored to the Bitcoin SV blockchain. Each signer receives a 1SatOrdinal inscription at their deterministically derived Bitcoin address. The contract text is never stored on-chain — only a cryptographic hash.

**Core principle:** The contract hash proves *what* was agreed. The UTXO proves *who* agreed. The blockchain proves *when*.

---

## 2. Architecture

```
┌──────────────────────────────────────────────────────┐
│  Service layer (e.g. heltenig.no)                    │
│  Identity verification · Templates · Two-party flow  │
└───────────────────────┬──────────────────────────────┘
                        │
┌───────────────────────▼──────────────────────────────┐
│  Anchoring service                                   │
│  1SatOrdinal inscriptions · UTXO management          │
└───────────────────────┬──────────────────────────────┘
                        │
┌───────────────────────▼──────────────────────────────┐
│  Key derivation (published HKDF-SHA256 algorithm)    │
│  Identity → deterministic Bitcoin key → address      │
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
    identity_hash_a: str,
    identity_hash_b: str,
    template_id: str,
    signed_at: int,
) -> str:
    """Compute the contract hash that gets inscribed on-chain."""
    content_hash = hashlib.sha256(contract_text.encode("utf-8")).hexdigest()

    sorted_signers = "|".join(sorted([identity_hash_a, identity_hash_b]))

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
- **Order-independent:** Signers are sorted — Party A signing first or second doesn't change the hash.
- **Privacy-preserving:** Contract text is hashed, never stored on-chain.
- **Tamper-evident:** Any change to the contract text, signers, or timestamp produces a different hash.

---

## 5. Key Derivation

Same HKDF-SHA256 algorithm as Beviset Protocol (see Beviset Protocol section 4), with different domain separators.

### 5.1 Algorithm

```python
def derive_bitcoin_key(identity_input: str, domain: str, key_id: str = None) -> bytes:
    """
    HKDF-SHA256 (RFC 5869):
      Extract: PRK = HMAC-SHA256(domain, identity_input)
      Expand:  OKM = HMAC-SHA256(PRK, info)

    Info string:
      Without key_id: "bitcoin-key-derivation" || 0x01          (base key)
      With key_id:    "bitcoin-key-derivation:" || key_id || 0x01 (child key)

    Returns 32 bytes — a valid secp256k1 private key.
    """
    prk = hmac.new(
        domain.encode("utf-8"),
        identity_input.encode("utf-8"),
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

For child key derivation details, see Beviset Protocol section 4.1.1. The same keyID mechanism applies — use the contract hash as `key_id` so each contract signing produces unique addresses for both signers.

### 5.2 Domain separators

| Identity type | Domain separator |
|--------------|------------------|
| BankID (PID) | `"heltenig-v1-keygen"` |
| Email + Phone | `"heltenig-v1-keygen-emailphone"` |

Different domain separators ensure separate key spaces. The same person using BankID and email+phone gets different Bitcoin addresses — by design.

### 5.3 Address derivation

```
private_key = derive_bitcoin_key(identity_input, domain)
public_key  = secp256k1_multiply(G, private_key)  # compressed, 33 bytes
address     = P2PKH(public_key)                    # standard Bitcoin address
```

---

## 6. Two-Party Signing Flow

```
Party A                    Service                    Party B
  │                          │                          │
  ├─ Select template ───────►│                          │
  ├─ Fill Party A fields ───►│                          │
  ├─ Verify identity ───────►│                          │
  ├─ Sign ──────────────────►│                          │
  │                          ├─ Send invite ───────────►│
  │                          │                          ├─ Open invite
  │                          │◄──── Fill Party B fields─┤
  │                          │◄──── Verify identity ────┤
  │                          │◄──── Sign ───────────────┤
  │                          │                          │
  │                          ├─ Merge all fields        │
  │                          ├─ Generate contract text  │
  │                          ├─ Compute contract hash   │
  │                          ├─ Inscribe for Party A    │
  │                          ├─ Inscribe for Party B    │
  │                          │                          │
  │◄── PDF + TXID ──────────┤──── PDF + TXID ─────────►│
```

Key points:
- The final contract text is generated only after **both** parties have filled their fields.
- The contract hash is computed from the **complete** merged text — not from partial data.
- Each signer receives their own 1SatOrdinal inscription at their derived address.
- The contract hash in both inscriptions is identical — they signed the same document.

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
| `identity_type` | `"emailphone"` or `"bankid"` |
| `signers_count` | Number of signers (currently always 2) |
| `signed_at` | Unix timestamp |
| `issuer` | Service that facilitated the signing |

The inscription is sent to the signer's HKDF-derived Bitcoin address. They hold it as a UTXO — no service can revoke it.

---

## 8. Verification Without Any Server

Anyone with the contract text and signer identities can verify:

```
Given: contract text, email+phone for both signers, template_id, timestamp

Step 1 — Identity hashes:
  canonical_a = "email:alice@example.com|phone:+4791234567"
  identity_hash_a = HMAC-SHA256(pepper, canonical_a)

  canonical_b = "email:bob@example.com|phone:+4798765432"
  identity_hash_b = HMAC-SHA256(pepper, canonical_b)

Step 2 — Contract hash:
  content_hash = SHA-256(contract_text)
  sorted_signers = sort([identity_hash_a, identity_hash_b]) joined with "|"
  preimage = "HELTENIG-v1\n" + content_hash + "\n" + sorted_signers
             + "\n" + template_id + "\n" + timestamp
  contract_hash = SHA-256(preimage)

Step 3 — Derive addresses (using contract_hash as keyID):
  address_a = P2PKH(derive_bitcoin_key(canonical_a, "heltenig-v1-keygen-emailphone", contract_hash))
  address_b = P2PKH(derive_bitcoin_key(canonical_b, "heltenig-v1-keygen-emailphone", contract_hash))

Step 4 — Check blockchain:
  Look up inscriptions at address_a and address_b
  Verify inscription hash matches computed contract_hash  ✓
  Verify inscriptions exist at derived addresses           ✓

Result: Contract verified. No server needed.
```

**Dependencies for independent verification:**
- This specification (published, MIT license)
- The contract text (from PDF or backup)
- Signer identities (email+phone or PID)
- Access to BSV blockchain (any node or block explorer)
- SHA-256 + HMAC-SHA256 + HKDF-SHA256 (standard cryptography)
- secp256k1 (standard elliptic curve)

---

## 9. Ricardian Contract Templates

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

## 10. Security

### 10.1 Threat model

| Threat | Mitigation |
|--------|-----------|
| Forged signature | Identity verification required (BankID or email+phone OTP) |
| Contract text altered | SHA-256 hash of text is part of contract hash |
| Signer identity spoofed | HMAC-peppered identity hash + key derivation |
| Service goes down | Proofs live on-chain; this spec enables independent verification |
| Rainbow tables on PID | HMAC pepper eliminates precomputed tables |
| Service revokes contract | Impossible — inscriptions are UTXOs held by signers |
| One party denies signing | Blockchain proves inscription at their derived address |

### 10.2 Entropy and deliberate tradeoffs

Same considerations as Beviset Protocol section 7.2. PID has limited entropy (~33 bits); address derivability from identity is by design. The keyID mechanism (section 5.1) prevents cross-contract linkability.

### 10.3 Privacy (GDPR)

**Important regulatory note:** HMAC-hashed identity data constitutes pseudonymization, not anonymization under EDPB/CNIL guidance. Pseudonymized data remains personal data under GDPR. See Beviset Protocol section 7.3 for full analysis.

Current privacy properties:
- Personal IDs are never stored on-chain in cleartext — only peppered HMAC hashes
- Contract text is never on-chain — only SHA-256 hash
- Inscriptions reveal existence and signing time, not content
- Signers can request deletion of all server-side data (GDPR art. 17)
- On-chain hashes are retained as pseudonymized data

**Planned:** Migration to EUDI Wallet-based signing (eIDAS 2.0) will eliminate identity-derived keys and remove all identity data from chain.

### 10.4 Legal basis

Electronic signatures via email + phone verification constitute Simple Electronic Signatures under eIDAS (EU 910/2014). They do NOT meet the "sole control" requirement for Advanced Electronic Signatures, as the signing key is deterministically derived from identity inputs rather than held exclusively by the signatory.

The signatures are nonetheless legally admissible as evidence of agreement in Norway (avtaleloven § 1) and the EU. The blockchain provides:
- Timestamped proof that an agreement was recorded
- Tamper-evident hash of the contract text
- Identity binding via verified email + phone

For use cases requiring Advanced or Qualified Electronic Signatures (e.g., real estate, regulated financial contracts), use BankID's native signing service instead.

---

## 11. Protocol Constants

All constants are public. Security does not depend on any constant being secret.

| Constant | Value | Used for |
|----------|-------|----------|
| Protocol marker | `"HELTENIG-v1"` | Contract hash preimage |
| PID pepper (BankID) | `"beviset-protocol-pid-pepper-v1-datamynt"` | Identity hashing (shared with Beviset) |
| Identity pepper (email+phone) | `"heltenig-protocol-identity-pepper-v1-datamynt"` | Identity hashing |
| Key domain (BankID) | `"heltenig-v1-keygen"` | HKDF-Extract |
| Key domain (email+phone) | `"heltenig-v1-keygen-emailphone"` | HKDF-Extract |
| HKDF info (base) | `"bitcoin-key-derivation" \|\| 0x01` | HKDF-Expand (no keyID) |
| HKDF info (child) | `"bitcoin-key-derivation:" \|\| key_id \|\| 0x01` | HKDF-Expand (with keyID) |
| Inscription content-type | `application/json; charset=utf-8` | 1SatOrdinal metadata |

---

## 12. Relationship to Beviset Protocol

Helt Enig and Beviset share the same cryptographic foundation:

| | Beviset | Helt Enig |
|---|---------|-----------|
| Purpose | Ownership certificates | Contract signatures |
| Signers | 1 (owner) | 2 (parties) |
| On-chain data | Proof hash | Contract hash |
| Transfer | Send the satoshi | Not transferable |
| Key derivation | Same HKDF-SHA256 | Same HKDF-SHA256 |
| BankID pepper | Shared | Shared |
| Domain separators | `beviset-v1-*` | `heltenig-v1-*` |

Both protocols use independent domain separators, so the same identity produces different Bitcoin addresses per service.

---

## 13. References

- SHA-256: FIPS PUB 180-4
- HMAC: RFC 2104
- HKDF: RFC 5869
- secp256k1: SEC 2, section 2.7.1
- 1SatOrdinals: https://docs.1satordinals.com
- Beviset Protocol: [BEVISET.md](./BEVISET.md)
- eIDAS: Regulation (EU) No 910/2014

---

*The blockchain proves the agreement existed. This specification proves it can be verified.*
