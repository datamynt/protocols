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

### [HELTENIG-V2.md](./HELTENIG-V2.md) — Sealed Agreements *(draft)*

Multi-party agreement signing where the signing service issues a **seal** over the document, each
party's signing act, a certificate per party (BRC-52) and its audit log, and anchors the seal's hash
as a BRC-220 NotaryHash. Parties get the signed PDF and a proof bundle that verifies without the
service.

- Parties are keys, not e-mail addresses: no key or identifier is ever derived from personal data
- Three signature suites, and the verifier must say which one was used: the party's own BRC-100
  wallet key, a passkey (WebAuthn), or an attestation by the service
- Identity strength is a certificate type (e-mail control, BankID, ...), not a change to the seal
- Nothing personal on chain; keys are derived per agreement so public data does not link a person
  across agreements

> *The seal proves what was signed and how. The certificate proves who. The block header proves when.*

**[HELTENIG.md](./HELTENIG.md) v0.5 is withdrawn.** It derived the signing key from e-mail + phone
number under published constants, so anyone knowing those two facts could forge a signature. The
file is kept for the record and must not be implemented.

### [BUDRUNDE.md](./BUDRUNDE.md) — Verifiable Sealed-Bid Auctions *(draft)*

Commit–reveal sealed bids: no party sees any bid before the deadline, and anyone can
verify afterward that the bid set was not altered.

- SHA256 commitments hide bids until reveal, bind them against change
- Commitment set anchored before deadline → auctioneer cannot peek, shill, or drop bids
- Identity-verified bidders (shared foundation) as the defense against Sybil/shill

> *The commitment proves what was bid. The anchor proves the set could not be altered. The identity proves each bid is a distinct person.*

## Shared foundation (Beviset and the withdrawn Helt Enig v1)

Beviset and Helt Enig v1 use the same key derivation algorithm (HKDF-SHA256, RFC 5869) with independent domain separators per service. The same identity produces different Bitcoin addresses for Beviset and Helt Enig — by design.

Helt Enig v2 does **not** use this foundation. It derives keys per agreement with BRC-42/43 from keys the parties or the service hold, and puts identity attributes in BRC-52 certificates instead of in key derivation (see HELTENIG-V2.md §9.1 for why).

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

- **Specifications** (BEVISET.md, HELTENIG-V2.md, HELTENIG.md, BUDRUNDE.md): [MIT License](./LICENSE-MIT)
- **Code** (implementations): [Open BSV License](./LICENSE-BSV)

## Links

[datamynt.no](https://datamynt.no) · [beviset.no](https://beviset.no) · [heltenig.no](https://heltenig.no)

*Verification requires only math, not trust.*
