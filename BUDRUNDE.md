# Budrunde Protocol — Verifiable Sealed-Bid Auctions on Bitcoin SV

**Version:** 0.1.0-draft
**Date:** 2026-07-22
**Status:** DRAFT — concept anchored, cryptographic construction sketched, not final. Not for implementation.
**License (specification):** MIT
**License (implementations):** Open BSV License

---

## 1. Summary

Budrunde is an open standard for **verifiable sealed-bid auctions**: bidders commit
cryptographically to a bid amount, no party — not the seller, not the auctioneer,
not the platform — can see any bid before the deadline, and after close anyone can
independently verify that no bid was added, dropped, or altered.

It is the third protocol in this family, alongside [BEVISET.md](./BEVISET.md)
(ownership certificates) and [HELTENIG.md](./HELTENIG.md) (contract signing), and
reuses the same foundation: **HKDF-SHA256 identity → Bitcoin address** derivation,
with commitments anchored as inscriptions on Bitcoin SV.

**Why the cryptography is load-bearing here.** A sealed-bid auction *without* proof
is worse than an open one: whoever holds the hidden bids has maximum temptation and
zero detection risk (see the highest bid, insert one just below; invent a bid). This
is the "trust me" auction people run in comment threads today, and everyone knows it
is rotten. The commitment scheme removes exactly this trust requirement.

**Historical anchor.** Rothkopf, Teisberg & Kahn (1990), *"Why Are Vickrey Auctions
Rare?"* — the answer was that you must trust the auctioneer not to lie about the
second-highest bid. A 35-year-old, well-documented product blocker with a
mathematical answer that did not exist at the time.

> *The commitment proves what was bid. The anchor proves the bid set could not be
> altered after the deadline. The identity proves each bid is a distinct person.*

---

## 2. Roles

| Role | Description |
|---|---|
| **Seller** | Publishes the lot and a sealed reserve price; sets one parameter: duration. |
| **Bidder** | Commits a sealed bid before the deadline; reveals after. Identity-verified. |
| **Auctioneer / platform** | Collects commitments, anchors the set, runs the reveal window. Holds no power to peek or shill. |
| **Verifier** | Anyone. Recomputes the hashes and checks the anchored commitment set. |

---

## 3. Cryptographic construction

The core is a **commit–reveal** scheme with an on-chain immutability anchor.

### 3.1 Commit phase (before deadline)

Each bidder derives their Budrunde address from their identity claim using the shared
foundation (domain separator `budrunde-v1-keygen`), then publishes a commitment:

```
nonce        = 32 random bytes (kept secret by bidder)
commitment C = SHA256( amount_minor_units ‖ nonce ‖ bidder_address ‖ auction_id )
```

- **Hiding:** without `nonce`, `C` reveals nothing about `amount`.
- **Binding:** the bidder cannot later open the same `C` to a different `amount`.
- Binding `bidder_address` and `auction_id` into the preimage prevents a commitment
  from one bidder or auction being replayed as another's.

The seller commits a **sealed reserve price** the same way, at publish time. It is
opened together with the bids — so the seller cannot move the goalposts after seeing
what came in.

### 3.2 Anchor (at/before deadline)

The ordered set of commitments (a Merkle root over all `C`, plus the seller reserve
commitment and the deadline) is inscribed on Bitcoin SV before the reveal window
opens. This is the immutability guarantee: after the anchor, the auctioneer **cannot**
add a late bid, drop a real one, or swap a commitment — any such change breaks the
anchored root, and the timestamp proves it existed before any reveal.

### 3.3 Reveal phase (after deadline)

Each bidder publishes `(amount, nonce)`. Any verifier checks:

```
SHA256( amount ‖ nonce ‖ bidder_address ‖ auction_id ) == C_bidder
AND  C_bidder ∈ anchored Merkle set
```

The winner is the highest valid revealed bid `≥` the revealed reserve. Everything —
the winning bid, the reserve, the count, the losers — is publicly recomputable.

---

## 4. What cryptography does **not** solve (open problems)

These are stated plainly because they determine whether the product is real, not just
the math:

1. **Sybil / shill bids.** The scheme proves bids were not altered — *not* that three
   of them are the same person. The only real defense is identity-verified bidders
   (BankID PID via the shared identity-hashing foundation). This is why identity is
   load-bearing, not optional.
2. **Withholding / non-reveal.** A bidder who commits but never reveals. Mitigation:
   non-reveal = forfeit; optionally a small deposit that is burned on non-reveal.
3. **Winner enforcement.** The chain proves the auction was honest; it cannot force
   the winner to pay or show up. Needs a deposit or reputation layer — "the chain as
   bailiff" is out of scope for v1.
4. **First-price vs. second-price (Vickrey).** Design choice, deliberately unfixed.
   Vickrey has cleaner incentives (bid your true value) but is notoriously
   counter-intuitive to explain ("you won, but pay the second price?"). A consumer
   product likely wants first-price sealed-bid even if it is theoretically weaker.

---

## 5. Shared foundation

Budrunde uses the same HKDF-SHA256 (RFC 5869) key derivation as Beviset and Helt
Enig, with its own domain separator so the same identity yields a distinct address
per service:

```
Identity (BankID PID or email+phone)
    ├─ domain: "beviset-v1-keygen"    → Beviset address
    ├─ domain: "heltenig-v1-keygen"   → Helt Enig address
    └─ domain: "budrunde-v1-keygen"   → Budrunde address
```

The ownership handoff after a sale reuses **Beviset** directly: the winner receives
the ownership certificate as part of the settlement. Budrunde is the missing middle
of the lifecycle — *register → sell → transfer*.

---

## 6. Product direction (non-normative)

Detailed product reasoning — the cold-start insight (a register has no moment, an
auction has a deadline), the wedge (a link pasted into existing group auctions rather
than a marketplace), and the segment (high-value goods that warrant ceremony) — lives
in the `beviset-no` repository as `BUDRUNDE.md`. This specification covers only the
cryptographic construction.
