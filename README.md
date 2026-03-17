# Datamynt Protocols

Open specifications for blockchain-anchored verification on Bitcoin SV.

These protocols share a common cryptographic foundation: **HKDF-SHA256 key derivation from identity to Bitcoin address**. This means anyone can independently verify proofs and contracts — no server, no database, no trust required. Only math.

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
Identity (BankID PID or email+phone)
    │
    ├─ domain: "beviset-v1-keygen"    → Beviset address
    ├─ domain: "heltenig-v1-keygen"   → Helt Enig address
    └─ domain: "yourapp-v1-keygen"    → Your service's address
```

The algorithm is published. Anyone can derive the address from an identity claim and verify it against the blockchain.

## Quick reference

```python
import hashlib, hmac

# Identity hashing (shared pepper for BankID)
PID_PEPPER = "beviset-protocol-pid-pepper-v1-datamynt"
identity_hash = hmac.new(PID_PEPPER.encode(), pid.encode(), hashlib.sha256).hexdigest()

# Key derivation (HKDF-SHA256)
def derive_key(identity_input: str, domain: str) -> bytes:
    prk = hmac.new(domain.encode(), identity_input.encode(), hashlib.sha256).digest()
    return hmac.new(prk, b"bitcoin-key-derivation\x01", hashlib.sha256).digest()
```

## License

- **Specifications** (BEVISET.md, HELTENIG.md): [MIT License](./LICENSE-MIT)
- **Code** (implementations): [Open BSV License](./LICENSE-BSV)

## Links

[datamynt.no](https://datamynt.no) · [beviset.no](https://beviset.no) · [heltenig.no](https://heltenig.no)

*Verification requires only math, not trust.*
