# Datamynt Protocols

Open specifications for blockchain-anchored verification on Bitcoin SV.

These protocols share a common cryptographic foundation: **salted HKDF-SHA256 key derivation from identity to Bitcoin address**. The algorithm is published and deterministic, so anyone holding the inputs can independently re-derive an address and verify proofs and contracts against the blockchain — no proprietary server logic, no trust in a database. Only math.

> **Important:** key derivation mixes a per-user 256-bit random salt (the user's *presentation key*) with the identity input. Identity alone is **not** enough to derive the key — see [BEVISET §4](./BEVISET.md#4-key-derivation). Without the salt, derived keys would be reproducible by anyone who knows the (low-entropy) identity inputs; the salt is what makes derivation forgery-resistant. The snippet below is illustrative; the normative algorithm (including the salt) lives in the spec.

## Protocols

### [BEVISET.md](./BEVISET.md) — Digital Ownership Certificates

Register, verify, and transfer ownership proofs anchored as 1SatOrdinal inscriptions.

- HMAC-peppered identity hashing (rainbow table resistant)
- 1SatOrdinals: the proof IS a satoshi, transferable via UTXO chain
- Independent verification without any server

> *The proof is a satoshi. The owner holds the satoshi. The UTXO chain IS the ownership history.*

### [HELTENIG.md](./HELTENIG.md) — Digital Contract Signing

Two-party contract signing with blockchain anchoring. One inscription per signer.

- Ricardian contract templates with party-tagged fields
- Contract text hashed, never stored on-chain
- Each signer holds their own inscription as a UTXO

> *The contract hash proves what was agreed. The UTXO proves who agreed. The blockchain proves when.*

## Shared foundation

Both protocols use the same key derivation algorithm (HKDF-SHA256, RFC 5869) with independent domain separators per service. The same identity produces different Bitcoin addresses for Beviset and Helt Enig — by design.

```
Identity (BankID PID or email+phone) + per-user 256-bit salt
    │
    ├─ domain: "wab-keygen-beviset-v1"           → Beviset address (BankID)
    ├─ domain: "beviset-v1-keygen-emailphone"    → Beviset address (email+phone)
    ├─ domain: "wab-keygen-heltenig-v1"          → Helt Enig address (BankID)
    └─ domain: "heltenig-v1-keygen-emailphone"   → Helt Enig address (email+phone)
```

The full list of domain separators is in [BEVISET §4.3](./BEVISET.md#43-domain-separators). The algorithm is published; anyone holding the identity claim **and** the user's salt can re-derive the address and verify it against the blockchain. Services also expose a public `/api/verify-address` endpoint that confirms an address belongs to an identity without revealing the salt.

## Quick reference

```python
import hashlib, hmac

# Identity hashing (shared pepper for BankID)
PID_PEPPER = "beviset-protocol-pid-pepper-v1-datamynt"
identity_hash = hmac.new(PID_PEPPER.encode(), pid.encode(), hashlib.sha256).hexdigest()

# Key derivation (salted HKDF-SHA256). `salt` is a per-user 256-bit random
# hex string (the presentation key). Without it, derivation is forgeable —
# see BEVISET §4.5. The IKM is identity_input || salt.
def derive_key(identity_input: str, domain: str, salt: str) -> bytes:
    ikm = identity_input + salt
    prk = hmac.new(domain.encode(), ikm.encode(), hashlib.sha256).digest()
    return hmac.new(prk, b"bitcoin-key-derivation\x01", hashlib.sha256).digest()
```

## License

- **Specifications** (BEVISET.md, HELTENIG.md): [MIT License](./LICENSE-MIT)
- **Code** (implementations): [Open BSV License](./LICENSE-BSV)

## Links

[datamynt.no](https://datamynt.no) · [beviset.no](https://beviset.no) · [heltenig.no](https://heltenig.no)

*Verification requires only math, not trust.*
