# Helt Enig Protocol v2 — Sealed Agreements on Bitcoin SV

**Version:** 2.0.0-draft.2
**Date:** 2026-09-17
**Status:** Draft for review. Not yet implemented. draft.1 was reviewed adversarially on 2026-09-17; Appendix C lists what changed.
**Supersedes:** [HELTENIG.md](./HELTENIG.md) v0.5 (withdrawn, see §1.3)
**License (specification):** MIT
**License (implementations):** Open BSV License

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as described in RFC 2119.
Sections marked *informative* contain no requirements.

---

## 1. Introduction

### 1.1 What this protocol does

A multi-party agreement is signed through a signing service (the **issuer**). When every party has signed,
the issuer produces a **seal**: one record that binds

- the exact document the parties saw,
- each party's signing act, with that party's own signature where the party holds a key,
- a certificate for each party saying how the party's identity was established,
- a commitment to the issuer's audit log,

and anchors the seal's hash on Bitcoin SV as a BRC-220 NotaryHash. The parties receive the signed PDF and a
**proof bundle**. With those two files and Bitcoin SV block headers, anyone can check the agreement without
contacting the issuer, and after the issuer has ceased to exist.

### 1.2 What a bundle proves and what it does not

A verified bundle proves that a holder of the issuer key `I` sealed exactly this document with exactly these
statements and certificates, and that the seal existed no later than the block that contains the anchor.
Where a party signed with a key only the party holds (§3.1, §3.2), it also proves that key signed the
party's statement. It does not prove who `I` belongs to: that comes from the issuer's domain (§2.2, V5) or
from a key the verifier already trusts. It does not make a signature "qualified" or "legally binding"; §10
says what each assurance level can honestly claim.

### 1.3 Why v1 was withdrawn

v1 derived both an identity hash and a signing key from e-mail + phone number under published constants.
Anyone who knew a person's e-mail and phone number could re-derive the key and forge that person's
signature. v2 MUST NOT derive any key, hash or identifier that stands in for a person from personal data
(§9.1). v1 anchors remain on chain, but v1 signatures SHOULD be treated as issuer statements only.

### 1.4 Design principles

1. **Parties are keys, not e-mail addresses.** Identity attributes live in certificates (BRC-52), never in
   key derivation.
2. **Identity strength is a certificate, not a format.** An e-mail check, a BankID check or a future EUDI
   wallet check changes the certificate type, not the seal.
3. **Say who signed.** A signature made with a party's own key and a statement the issuer makes on a
   party's behalf are different things, and every verifier output MUST keep them apart.
4. **Block time is the only established time.** Every timestamp in a bundle is chosen by the issuer; the
   anchor's block is the one time a verifier can establish.
5. **Nothing personal on chain.** The chain carries hashes only. Keys are derived per agreement, so public
   data does not link a person across agreements.
6. **Verifiable derivation.** Every issuer key in a bundle is a child of `I` that any verifier can compute.
   A bundle cannot be assembled around a key the issuer never derived.
7. **Reuse the standards.** Keys follow BRC-42/43, certificates BRC-52, the anchor BRC-220, the trust
   anchor BRC-68, transaction proofs BRC-10/11 (with BRC-74 optional).

### 1.5 Non-goals

- **Qualified electronic signatures (eIDAS art. 3(12)).** See §10.
- **Trust in PDF viewers.** v2 does not make Adobe Acrobat or other viewers show a signature panel. A
  conventional PAdES seal MAY be layered underneath (§7.3).
- **On-chain agreement state.** Amendment and termination tokens are deferred to a later version (§11).
- **Hiding that an agreement exists.** An observer can see that some issuer anchored a NotaryHash at a given
  time. The observer cannot see what, or between whom.

---

## 2. Roles, keys and notation

### 2.1 Roles

| Role | Description |
|---|---|
| **Issuer** | The signing service. Holds an identity key `I`, acts as BRC-52 certifier, builds seals, pays for anchors. |
| **Party** | A person who signs. Indexed `0..n-1` in the agreement. |
| **Sender** | The party (or non-party) who created and sent the agreement. Authenticated to the issuer. |
| **Verifier** | Anyone checking an agreement. Needs the signed PDF, the proof bundle and block headers. |

### 2.2 Issuer trust anchor

The issuer MUST publish its identity key per BRC-68 at `https://<issuer-domain>/manifest.json`:
`metanet.trust.publicKey` = `I` (with `name`, `note`, `icon` as BRC-68 defines). BRC-68 defines nothing
more; the following `heltenig` object is specific to this protocol:

```json
{
  "heltenig": {
    "version": "2",
    "issuerKey": "<I, 33-byte compressed, hex>",
    "keyHistory": [
      { "key": "<hex>", "validFrom": "<RFC 3339>", "validTo": null, "proof": null },
      { "key": "<hex>", "validFrom": "<RFC 3339>", "validTo": null, "proof": "<DER hex>" }
    ]
  }
}
```

`keyHistory` is ordered oldest first. Entry 0 has `proof: null`. Every later entry's `proof` MUST be an
ECDSA signature by the **previous entry's key** over `SHA-256(JCS({"key": <key>, "validFrom": <validFrom>}))`.
Whoever controls the domain can edit the file, so a verifier trusts an entry only after checking the chain of
proofs (V5); a new domain holder cannot insert a key the previous key holder did not endorse.

`I` is also copied into every seal (§4.6), so a bundle stays self-consistent when the domain is gone. A
verifier that cannot reach the manifest MUST report the issuer key as **pinned by the bundle only**.

### 2.3 Key derivation

All secp256k1 keys are BRC-42 child keys with BRC-43 invoice numbers `2-<protocol name>-<keyID>`.
Protocol names follow BRC-43: lowercase letters, digits and single spaces, 5–280 characters, not ending in
" protocol". `agreementId` is a random UUIDv4 in lowercase string form chosen by the issuer.

| Key | Holder | protocolID | keyID | counterparty |
|---|---|---|---|---|
| `K_seal` — signs the seal | Issuer | `[2, "heltenig agreement seal"]` | `agreementId` | `anyone` |
| `K_att(i)` — speaks for party `i` when the party holds no key; certificate subject for that party | Issuer | `[2, "heltenig party attestation"]` | `agreementId + " " + i` | `anyone` |
| `K_party(i)` — a wallet party's signing key | Party wallet | `[2, "heltenig agreement signature"]` | `agreementId` | `I` |

The `anyone` counterparty is the BRC-43 public counterparty (private key `1`). A verifier therefore computes
`K_seal` and every `K_att(i)` from `I` and the invoice number alone, and MUST do so (V4, V7): a bundle whose
seal key or attestation keys are not the derived children of `I` is invalid. Issuer keys derived with
counterparty `self` MUST NOT be used, because no verifier can derive them.

`K_party(i)` is derived by the party's wallet with counterparty `I` and `forSelf: true` (BRC-56/BRC-100
`getPublicKey`). The issuer computes the same public key from `I`'s private key and the party's identity key
(BRC-42 is symmetric) and MUST reject a presented key that does not match.

Because every key is derived with `agreementId`, public keys of the same person or issuer do not repeat
across agreements.

### 2.4 Notation and encodings

- `H(x)` is SHA-256. `JCS(o)` is the RFC 8785 serialization of object `o` as UTF-8 bytes (§8).
- `statementHash`, `sealHash` and every `sha256` member: 64 lowercase hex characters.
- Timestamps: RFC 3339, UTC, `Z` suffix, millisecond precision, e.g. `2026-09-17T12:04:05.123Z`.
- Integers (`partyIndex`, `partyCount`, `count`, block heights): JSON numbers without fraction or exponent.

| Encoding | Used for |
|---|---|
| hex, lowercase | hashes; secp256k1 public keys (33 bytes, compressed); P-256 public keys (65 bytes, uncompressed SEC1); DER signatures (low-S); `txid`; `rawTx`; scripts |
| base64, padded | BRC-52 `type`, `serialNumber`, encrypted field values, 32-byte field revelation keys |
| base64url, unpadded | WebAuthn `authenticatorData`, `clientDataJSON`, and `challenge` inside `clientDataJSON` |

---

## 3. Signature suites

A party's signing act is a **signing statement** (§4.3) and a signature over `statementHash = H(JCS(statement))`.
Three suites are defined. An issuer MUST support `issuer-attestation`, SHOULD support `webauthn-es256`, and
MAY omit `brc100-secp256k1` (§11).

### 3.1 `brc100-secp256k1` — party signs with a BRC-100 wallet

The party's wallet exposes `K_party(i)` with
`getPublicKey({ protocolID: [2, "heltenig agreement signature"], keyID: agreementId, counterparty: I, forSelf: true })`
and signs the digest with
`createSignature({ hashToDirectlySign: statementHash, protocolID, keyID, counterparty: I })`.

Signature object:

```json
{ "suite": "brc100-secp256k1", "publicKey": "<K_party(i), hex>", "signature": "<DER hex>" }
```

The issuer MUST obtain the party's identity key during signing, derive the expected `K_party(i)` and reject
any other key. Linkage from the party's identity key to `K_party(i)` is not carried in the bundle: BRC-97
defines no checkable proof type, so a verifier could only report it as claimed. Who the party is comes from
the certificate.

**Sole control:** yes. The issuer never holds `K_party(i)`.

### 3.2 `webauthn-es256` — party signs with a passkey

The party signs in a browser with a platform or roaming authenticator (W3C Web Authentication Level 3). The
assertion MUST be produced with `challenge` = the 32 bytes of `statementHash`, `userVerification: "required"`,
at the origin fixed in the seal (`seal.issuer.webauthn.origin`, §4.6). The passkey MUST have been registered
during this signing flow or an earlier one with the same issuer, and its public key MUST appear in the
party's certificate (`webauthnPublicKey`), which is issued before the statement (§5).

Signature object:

```json
{ "suite": "webauthn-es256", "publicKey": "<P-256 key, SEC1 uncompressed, hex>", "signature": "<DER hex>",
  "authenticatorData": "<base64url>", "clientDataJSON": "<base64url>" }
```

The signed data is `authenticatorData || H(clientDataJSON)`, hashed with SHA-256 by ES256. The issuer
converts the credential's COSE key to SEC1 once, at registration; verifiers compare hex strings.

**Sole control:** yes, subject to the authenticator. Synced passkeys (iCloud Keychain, Google Password
Manager) are controlled by the party's cloud account; verifiers SHOULD report the `BE`/`BS` flags.

### 3.3 `issuer-attestation` — the issuer states that the party signed

For a party with neither a wallet nor a passkey. The issuer signs `statementHash` with `K_att(i)`.

```json
{ "suite": "issuer-attestation", "publicKey": "<K_att(i), hex>", "signature": "<DER hex>" }
```

This is **not** the party's signature. It is the issuer's statement that the party completed the signing
steps described in the party's certificate. `publicKey` MUST be the derived `K_att(i)` (§2.3), and verifier
output MUST say that the issuer, not the party, signed (§6.2).

**Sole control:** no.

---

## 4. Objects

All objects are JSON. Hashing rules are in §8.

### 4.1 Agreement identifiers

- `agreementId` — UUIDv4 string, unique per agreement, generated by the issuer with a CSPRNG.
- `originalSha256` — `H(bytes)` of the document exactly as every party was shown it, after the issuer's
  sanitisation (§7.2). For a text agreement rendered to PDF, the hash is of the rendered PDF bytes.

### 4.2 Consent text

The consent sentence each party confirmed, stored verbatim with a version label. The sentence MUST contain
`originalSha256` in full, e.g.

`"Jeg har lest dokumentet og signerer det elektronisk som bindende for meg. Dokumentets fingeravtrykk (SHA-256) er <originalSha256>."`

### 4.3 Signing statement

```json
{
  "protocol": "heltenig",
  "version": "2",
  "type": "signing-statement",
  "agreementId": "<uuid>",
  "originalSha256": "<hex>",
  "partyIndex": 1,
  "partyCount": 2,
  "certificateSerial": "<BRC-52 serialNumber, base64>",
  "consent": { "version": "2026-09-17.v1", "text": "<verbatim consent sentence>" },
  "signedAt": "<RFC 3339, claimed by the issuer>",
  "suite": "webauthn-es256"
}
```

`statementHash = H(JCS(statement))`. The statement binds agreement, document, party slot, roster size,
certificate, consent and suite, so a signature cannot be moved to another agreement, slot, roster or
certificate.

### 4.4 Party certificates

Each party has exactly one **primary certificate**, a BRC-52 certificate issued by the issuer with field
values encrypted per BRC-52. The certifier signature is made, as BRC-52 specifies, with the certifier's
child key for protocol `[2, "certificate signature"]`, keyID `<type> <serialNumber>`, counterparty `anyone`,
so any verifier derives the signing key from `I`.

**What these certificates are.** For a wallet party the `subject` is `K_party(i)`, a per-agreement child
key; for every other party the `subject` is `K_att(i)`, which the issuer holds. In both cases the certificate
is an artefact of the bundle: no BRC-100 wallet can acquire, store or present it, because BRC-52 storage
requires the subject to be the wallet's identity key. For a non-wallet party the certificate is therefore the
issuer's signed, selectively disclosable record of the identity check it performed, and nothing more.
Implementations and verifiers MUST describe it that way.

**Common rules**

- `certifier` = `I` (or a `keyHistory` key valid at the anchor block time).
- `subject` = `K_party(i)` for suite `brc100-secp256k1`, otherwise `K_att(i)`.
- `serialNumber` = 32 CSPRNG bytes, base64.
- `revocationOutpoint` = the all-zero outpoint
  `0000000000000000000000000000000000000000000000000000000000000000.0`. **Revocation policy (published as
  BRC-52 requires):** primary certificates attest to past facts about one agreement and are never revoked.
  Certifier compromise is handled by `keyHistory` and the anchor block time (§9.2).
- Every primary certificate has the fields `agreementId`, `partyIndex` and `issuedAt`.
- The certificate's `sha256` (§4.6) is `H` of the BRC-52 `CertificateBinary` **including** the signature field.

**Type `email-control`** — type id = base64 of `H("heltenig v2 certificate email-control")`

| Field | Meaning |
|---|---|
| `email` | The address the party proved control of. |
| `name` | The name as entered by the sender. **Not verified.** |
| `nameSource` | Always `"sender"` for this type. |
| `linkSentAt`, `linkOpenedAt`, `codeVerifiedAt` | Times of the e-mail link and one-time code steps, as recorded by the issuer. |
| `method` | `"email-link+one-time-code"` |
| `webauthnPublicKey` | The passkey public key (SEC1 hex). Present when the party registered a passkey before the certificate was issued. |

**Type `authenticated-sender`** — type id = base64 of `H("heltenig v2 certificate authenticated-sender")`

| Field | Meaning |
|---|---|
| `email` | The sender's login e-mail. |
| `name` | The sender's display name from the login provider or as entered. |
| `loginMethod` | e.g. `"google"`, `"microsoft"`, `"email-link"`. |

Future certificate types (a BankID identity certificate from an identity broker, a BRC-169 organisation
delegation certificate) plug in as additional certificates for the same subject key. They MUST be listed in
the seal (§4.6) to be considered.

### 4.5 Disclosures

A proof bundle is handed to the parties and whoever they share it with. By default the bundle discloses
exactly the fields printed on the certificate page of the signed PDF (names, e-mail addresses, times). The
issuer places the raw 32-byte BRC-52 field revelation keys for those fields in the bundle, base64:

```json
{ "certificateSerial": "<base64>", "fields": { "email": "<base64 key>", "name": "<base64 key>" } }
```

Disclosure in a shared bundle is irrevocable. A party MAY ask the issuer for a bundle variant with fewer
disclosures; the certificate signature still verifies because BRC-52 signs the encrypted form. Variants come
from the issuer, not from the party, because for non-wallet parties the issuer holds the master keyring.

### 4.6 Seal record

```json
{
  "protocol": "heltenig",
  "version": "2",
  "type": "seal",
  "agreementId": "<uuid>",
  "issuer": {
    "identityKey": "<I, hex>",
    "sealKey": "<K_seal, hex>",
    "manifest": "https://heltenig.no/manifest.json",
    "webauthn": { "origin": "https://heltenig.no", "rpId": "heltenig.no" }
  },
  "originalSha256": "<hex>",
  "signedDocument": { "sha256": "<hex>", "mediaType": "application/pdf" },
  "parties": [
    {
      "index": 0,
      "statementHash": "<hex>",
      "signature": { "...": "signature object from §3" },
      "certificates": [ { "serialNumber": "<base64>", "sha256": "<hex>" } ]
    }
  ],
  "auditLog": { "profile": "HE-EVENTS-1", "head": "<hex>", "count": 17 },
  "sealedAt": "<RFC 3339, claimed by the issuer>",
  "previous": null
}
```

- `signedDocument` is the PDF delivered to the parties: the original pages plus the issuer's certificate
  page(s). It does not contain the anchor (the anchor is created after the document).
- `issuer.webauthn` is present when any party used `webauthn-es256`; it fixes the origin and RP ID a
  verifier checks against, independently of the manifest.
- `parties[].certificates[0]` is the primary certificate. Additional entries are optional stronger
  certificates for the same subject.
- `auditLog.head` commits to the issuer's full audit trail without publishing it (Appendix A).
- `previous` MUST be `null` in version 2. It is reserved for amendment chains in a later version.

`sealHash = H(JCS(seal))`. `sealSignature` is an ECDSA signature by `K_seal` over the raw 32-byte
`sealHash`, without further hashing (this is what BRC-220 requires of `signature`, §4.7), DER, low-S, hex.

### 4.7 On-chain anchor

The anchor is a BRC-220 NotaryHash certificate in **hybrid** mode, one seal per transaction. Field values
under this protocol:

| NotaryHash field | Value |
|---|---|
| `protocol`, `version` | as BRC-220 defines them |
| `mode` | hybrid (`1`) |
| `algorithm` | `"ECDSA-secp256k1"` |
| `hashAlgorithm` | `"SHA-256"` |
| `payloadHash` | `sealHash` |
| `publicKey` | `K_seal` |
| `signature` | `sealSignature` |
| `encoding` | `"hex"` — BRC-220 requires the field but does not enumerate its values; this protocol fixes it, and the test vector (Appendix B) is normative |
| `proofHash` | `SHA-256` of the BRC-220 canonical proof bytes: `lp("NotaryHash/1.0") ‖ u8(1) ‖ lp(algorithm) ‖ lp(hashAlgorithm) ‖ lp(payloadHash) ‖ lp(publicKey) ‖ lp(signature) ‖ u64be(createdAt)` with `lp(x) = u32be(len(x)) ‖ x` over the raw bytes of each field |
| `createdAt` | `sealedAt` as Unix seconds. Advisory only (BRC-220): the proof-of-existence time is the block time |
| `anchor` | `{ "txid": "<hex>", "vout": <n> }`, set when the transaction is broadcast |
| `spv` | added once mined, see below |

The on-chain output is `OP_FALSE OP_RETURN` with the pushes BRC-220 defines for hybrid mode:
`"NOTARYHASH" ‖ u8(1) ‖ u8(1) ‖ algorithm ‖ hashAlgorithm ‖ payloadHash ‖ proofHash ‖ SHA-256(publicKey) ‖ SHA-256(signature)`.
The chain therefore carries the marker, the seal hash, the proof hash and hashes of an agreement-specific key
and signature, nothing else about the agreement. Anyone holding a valid `(payloadHash, signature, publicKey)`
triple may re-anchor it (BRC-220); a second anchor does not change what the first proves.

**SPV envelope.** Once mined, `spv` carries `rawTx`, `blockHash`, `blockHeight`, `merkleProof` and `format`.
Under this protocol `format` MUST be `"TSC"` (BRC-10/11 with heights, the BRC-220 default), so that a generic
BRC-220 verifier accepts the certificate. An issuer MAY add a member `bump` holding the same proof as a
BRC-74 BUMP in hex; verifiers MAY use either. The envelope is not part of the canonical proof bytes, so adding
it does not change `proofHash`.

Batch mode (`kind = 2`) is deferred to a later version (§11). Fees follow the issuer's normal fee policy;
this specification does not change fee rates.

### 4.8 Proof bundle

File extension `.heltenig.json`, media type `application/vnd.heltenig.proof+json`.

```json
{
  "protocol": "heltenig",
  "version": "2",
  "type": "proof-bundle",
  "seal": { "...": "§4.6" },
  "sealSignature": "<DER hex>",
  "statements": [ { "...": "§4.3, one per party, same order as seal.parties" } ],
  "certificates": [ { "...": "BRC-52 certificates, JSON form" } ],
  "disclosures": [ { "...": "§4.5" } ],
  "anchor": { "...": "BRC-220 NotaryHash certificate (§4.7), or null before broadcast" },
  "auditLog": null
}
```

A bundle is in one of three anchor states, and verifiers report which (§6.2):

| State | Bundle content |
|---|---|
| **anchored** | `anchor.spv` present and verified (V8) |
| **broadcast, not mined** | `anchor.anchor.txid` present, no `spv` |
| **not anchored** | `anchor` is `null` |

The issuer's duties to move a bundle to **anchored** and to get the updated bundle to the parties are in
§7.4. `auditLog` MAY contain the full event list (Appendix A) when the parties want an independently
recomputable trail; it contains IP addresses and user agents and is omitted by default.

---

## 5. Signing flow (informative)

1. The sender authenticates and creates the agreement. The issuer sanitises the document (§7.2), computes
   `originalSha256` and generates `agreementId`.
2. The issuer invites each party with a personal link.
3. For each party:
   1. The party opens the link and proves control of the e-mail address with a one-time code.
   2. The party chooses how to sign. For a passkey, the party registers it now (WebAuthn `create`) and the
      issuer records the SEC1 public key; for a wallet, the issuer obtains the party's identity key and
      `K_party(i)`.
   3. The issuer issues the party's primary certificate (§4.4), including `webauthnPublicKey` when a
      passkey was registered.
   4. The issuer builds the signing statement with the certificate serial, the consent text and the suite.
   5. The party signs: WebAuthn assertion (§3.2), wallet signature (§3.1), or by confirming consent, in
      which case the issuer attests (§3.3).
4. When all parties have signed, the issuer renders the signed PDF, computes `signedDocument.sha256`,
   builds and signs the seal, and broadcasts the NotaryHash transaction.
5. The issuer delivers the signed PDF and the proof bundle to every party, then keeps the bundle current as
   the anchor is mined (§7.4).

---

## 6. Verification

### 6.1 Algorithm

Inputs: the signed PDF bytes `D`, a proof bundle `B`, and a source of Bitcoin SV block headers. Any MUST
failure makes the result **invalid**, and the verifier MUST name the failing step.

- **V1 Document.** `H(D)` MUST equal `B.seal.signedDocument.sha256`.
- **V2 Structure.** `B.seal.protocol == "heltenig"`, `version == "2"`, `type == "seal"`, `previous == null`;
  `B.statements` and `B.seal.parties` MUST have the same length `n`, indexes `0..n-1` without gaps, and every
  statement's `partyCount` MUST equal `n`.
- **V3 Statements.** For each party `i`: `statements[i].agreementId`, `originalSha256` MUST equal the seal's;
  `partyIndex` MUST equal `i`; `H(JCS(statements[i]))` MUST equal `seal.parties[i].statementHash`;
  `statements[i].suite` MUST equal `seal.parties[i].signature.suite`; the consent text MUST contain
  `originalSha256`.
- **V4 Party signatures.** For each party, by suite:
  - `issuer-attestation`: `signature.publicKey` MUST equal the BRC-42 child of `seal.issuer.identityKey` for
    invoice number `2-heltenig party attestation-<agreementId> <i>`, counterparty `anyone`; the signature
    MUST verify over `statementHash`.
  - `brc100-secp256k1`: the signature MUST verify over `statementHash` under `signature.publicKey`, and that
    key MUST equal the primary certificate's `subject` (V6).
  - `webauthn-es256`: decode `clientDataJSON`; `type` MUST be `"webauthn.get"`; the base64url `challenge`
    MUST decode to `statementHash`; `origin` MUST equal `seal.issuer.webauthn.origin`; `crossOrigin` MUST be
    absent or `false`. In `authenticatorData`, `rpIdHash` MUST equal `H(seal.issuer.webauthn.rpId)` and the
    UP and UV flags MUST be set. The ES256 signature MUST verify over `authenticatorData || H(clientDataJSON)`
    under `signature.publicKey`. Report the `BE`/`BS` flags.
- **V5 Issuer key.** `I = B.seal.issuer.identityKey`. If the manifest is reachable: every `keyHistory`
  entry after the first MUST carry a valid `proof` by its predecessor; `I` MUST appear in the list; and when
  V8 yields a block time, `I` MUST be valid (`validFrom` ≤ block time < `validTo` or `validTo` null) at that
  time. Report **issuer key confirmed by domain**, or **pinned by the bundle only** when the manifest is
  unreachable, and **validity unchecked** when there is no mined anchor.
- **V6 Certificates.** For each party's listed certificates:
  1. `H(CertificateBinary including signature)` MUST equal the listed `sha256`; the serial MUST match.
  2. The certifier signature MUST verify under the certifier's child key for `[2, "certificate signature"]`,
     keyID `<type> <serialNumber>`, counterparty `anyone`. For primary certificates the certifier MUST be `I`
     (or a `keyHistory` key valid at the anchor block time).
  3. The primary certificate's `subject` MUST equal `signature.publicKey` for suite `brc100-secp256k1`, and
     the derived `K_att(i)` otherwise. `statements[i].certificateSerial` MUST equal the primary serial.
  4. Decrypt disclosed fields with the bundle's revelation keys. `agreementId` and `partyIndex`, when
     disclosed, MUST match.
  5. For `webauthn-es256`, the disclosed `webauthnPublicKey` MUST equal `signature.publicKey`. If that field
     is not disclosed, report the passkey binding as **undisclosed**.
  6. Primary certificates are never revoked (§4.4); report that policy. For other certificates with a
     non-zero `revocationOutpoint`, check that the outpoint is unspent where the verifier has a spend source;
     otherwise report revocation status as **unchecked**.
- **V7 Seal signature.** `sealHash = H(JCS(B.seal))`. `B.seal.issuer.sealKey` MUST equal the BRC-42 child of
  `I` for invoice number `2-heltenig agreement seal-<agreementId>`, counterparty `anyone`. `sealSignature`
  MUST verify under `sealKey` over the raw 32-byte `sealHash`.
- **V8 Anchor.** When `B.anchor` is present: `payloadHash` MUST equal `sealHash`, `publicKey` MUST equal
  `sealKey`, `signature` MUST equal `sealSignature`; the BRC-220 signature and `proofHash` checks MUST pass.
  With an `spv` envelope: `reverse(SHA-256(SHA-256(rawTx)))` MUST equal `anchor.txid`; the `OP_FALSE OP_RETURN`
  output in `rawTx` MUST decode to the hybrid pushes of §4.7 for this certificate; folding `merkleProof`
  from the txid MUST yield the Merkle root of the block header at `blockHeight` obtained from the header
  source, whose hash MUST equal `blockHash`. Report the block height and the block's time as the established
  time. Without `spv`, report **broadcast, not mined**; without `anchor`, **not anchored**.
- **V9 Audit log (optional).** When `B.auditLog` is present, recompute the chain (Appendix A); the final hash
  MUST equal `seal.auditLog.head` and the count MUST match.

### 6.2 What a verifier reports

A conforming verifier reports, per party, **how** that party signed, never just "signed":

- `brc100-secp256k1`: "signed with a key only they hold"
- `webauthn-es256`: "signed with a passkey on their device" (+ synced / not synced when known)
- `issuer-attestation`: "the issuer states that this party completed the signing steps"

plus the certificate types that establish identity (e.g. "controls the e-mail address a***@example.com",
"identity confirmed with BankID"), the anchor state (§4.8) with block height and block time, and the issuer
key status from V5.

Times: the verifier MUST present `signedAt`, `sealedAt`, `issuedAt`, `createdAt` and every certificate time
as **claimed by the issuer**, and the anchor block time as the only established time. Several seals MAY
exist for one `agreementId`; the verifier reports this bundle's anchor and MUST NOT call it the only seal.

A verifier MUST NOT describe a result as "legally binding" or "qualified".

---

## 7. Issuer obligations

### 7.1 Suites

A party MUST always be able to sign by `issuer-attestation`. Stronger suites are offered, never required,
unless the sender requires a minimum assurance level (§10); the issuer MUST record that requirement in the
audit log.

### 7.2 Originals

Before computing `originalSha256`, the issuer MUST reject, or flatten to plain page content, an uploaded
PDF that contains JavaScript, interactive form fields, embedded files, optional content groups or
incremental updates. Parties view the issuer's rendering of the document, and the certificate page MUST say
so.

### 7.3 The signed PDF is delivered unmodified

The delivered PDF is exactly the byte sequence hashed in `signedDocument.sha256`, and the proof bundle is a
separate file. Implementations MUST NOT append the bundle, or any later revision (including PAdES LTV/DSS
updates), to the PDF as an incremental update: a verifier that hashes a prefix of a file can be shown
different page content by a later revision. An issuer MAY apply a PAdES seal from a certificate authority
**before** computing `signedDocument.sha256`; it then becomes part of the hashed bytes.

### 7.4 Anchoring and redelivery

The issuer MUST broadcast the NotaryHash transaction when the seal is made and MUST retry until it is mined.
Delivery of the signed PDF and bundle MUST NOT wait for mining, and SHOULD NOT wait for broadcast beyond a
short timeout. A bundle carries `anchor` with `txid` as soon as broadcast succeeds. When the anchor is mined,
the issuer MUST make the updated bundle available and MUST deliver it, or notify every party where to fetch
it. A bundle without an anchor is a delivery failure the issuer MUST track, not a final state.

### 7.5 Lookup

An issuer SHOULD let anyone fetch the current bundle by `signedDocument.sha256`, rate-limited. There MUST be
no lookup by `originalSha256`: it would tell anyone holding a template whether it was signed. The default
bundle discloses exactly what the certificate page prints, so a holder of the PDF learns nothing new from it.

### 7.6 Certificate page

The certificate page inside the signed PDF SHOULD show `agreementId`, `originalSha256`, each party's name,
e-mail, suite in plain language, that parties viewed the issuer's rendering, and the verification address.
It cannot show `sealHash` or the anchor, because both are computed after the PDF.

---

## 8. Canonicalization and versioning

- Every hashed object is serialized with RFC 8785 (JCS). Verifiers hash `JCS(o)` of the **complete received
  object**, including members they do not recognise, and MUST NOT normalise, reorder, re-encode or drop
  anything first. Objects with duplicate member names are invalid.
- Issuers MUST emit strings in Unicode NFC. Verifiers MAY warn about non-NFC strings and MUST NOT normalise
  them: RFC 8785 does not normalise, and a normalised object would hash to something the issuer never signed.
- Only integers appear as JSON numbers (§2.4); implementations MUST NOT emit fractions or exponents.
- `version` is `"2"` for every object in this document. Later versions MAY add members to hashed objects;
  version-2 verifiers hash them and do not interpret them. Any change to the meaning of an existing member,
  to a suite or to a verification rule requires a new version.

---

## 9. Security considerations

### 9.1 No keys from personal data

An implementation MUST NOT derive keys, key IDs, identifiers or hashes that represent a person from e-mail
addresses, phone numbers, national identity numbers or names, with or without a salt. Personal attributes
appear only as encrypted certificate fields.

### 9.2 Issuer compromise

A stolen `I` allows forged attestations, certificates and seals. Mitigations: `I` in hardware-backed or
managed key storage, with `K_seal`/`K_att` derived per agreement; `keyHistory` with predecessor proofs; and
block time. Because V5 checks validity at the anchor **block** time, a thief cannot launder a seal by writing
an earlier `sealedAt`: a seal anchored in a block mined after `validTo` is invalid no matter what it claims.
Seals anchored before the compromise are unaffected. Parties who sign with suites 3.1 or 3.2 are protected
against forged signatures regardless of issuer compromise; their certificates, however, are still the
issuer's statements.

### 9.3 Substitution, replay and re-assembly

The statement binds `agreementId`, `originalSha256`, party index, party count, certificate serial and suite.
The seal binds statement hashes and certificate hashes. Because `K_seal` and `K_att(i)` are derived from `I`
with the public counterparty and verifiers recompute them, a bundle assembled by someone without `I`'s
private key fails V4 or V7 even if it reuses genuine certificates from another bundle. A dishonest issuer can
still emit several seals for one `agreementId`; §6.2 requires verifiers to say so.

### 9.4 Canonicalization

See §8. The audit-log profile in Appendix A predates v2 and is not JCS; it is self-contained and its rules
are stated completely there.

### 9.5 Header source

SPV verification is only as good as the block header source. Verifiers SHOULD use more than one source or
validate proof of work over a header chain, and SHOULD make the source explicit in their output.

### 9.6 Privacy

- On chain: the NotaryHash marker, `sealHash`, `proofHash` and hashes of an agreement-specific key and
  signature. No names, e-mail addresses or document hashes. An observer learns that some issuer anchored a
  NotaryHash at a block time, not which issuer.
- Key derivation per agreement prevents linking a party or the issuer's seal keys across agreements.
- Funding: anchors paid from one issuer wallet can be clustered by transaction-graph analysis, revealing the
  issuer's anchoring volume and timing.
- Lookup is by `signedDocument.sha256` only (§7.5) and rate-limited.
- Disclosure in a shared bundle is irrevocable; the optional audit log contains IP addresses and user agents.

### 9.7 Passkeys

A passkey created during signing is bound to an authenticator, not a person, and synced passkeys are
controlled by a cloud account. The certificate binds the passkey to the e-mail check at signing time; it does
not strengthen identity beyond that check. The origin and RP ID are fixed in the seal, so a later manifest
cannot retroactively widen them.

### 9.8 What "confirmed by domain" means

The manifest is controlled by whoever holds the domain. Predecessor proofs stop a new domain holder from
inserting a key the previous holder did not endorse, but the first key in the list is trusted on the domain's
word alone. A verifier that has `I` from another channel SHOULD compare it.

---

## 10. Assurance levels (informative)

| Level | Party signature | Identity certificate | Plain-language claim |
|---|---|---|---|
| **A0** | `issuer-attestation` | `email-control` | The issuer states that someone controlling this e-mail address completed the signing steps. |
| **A1** | `webauthn-es256` or `brc100-secp256k1` | `email-control` | Someone controlling this e-mail address signed with a key only they control. |
| **A2** | as A1 | an identity certificate from a recognised identity provider (e.g. BankID) | A person identified by that provider signed with a key only they control. |

Under eIDAS (Regulation (EU) No 910/2014), A0 is a simple electronic signature. A1 is designed to meet three
of the four requirements of an advanced electronic signature in art. 26: uniquely linked to the signatory
(a), created with data under the signatory's sole control (c), and linked to the data so that changes are
detectable (d). Requirement (b), capable of identifying the signatory, rests at A1 on e-mail control and a
name entered by the sender, which is weak; A2 meets (b) through the identity provider. Whether a court
accepts any of this is outside this specification. No level is a qualified signature. The anchor is a
non-qualified electronic time stamp (art. 41(1)); the presumption of art. 41(2) does not apply.

A sender MAY require a minimum level per party (§7.1).

---

## 11. Deferred to a later version

| Feature | Why not in 2.0 |
|---|---|
| Agreement state token (BRC-48 PushDrop), `previous` chains, overlay topic and lookup service | Issuer-held locking key makes it unenforceable; nothing to build against yet |
| Batch-mode anchoring (BRC-220 `kind = 2`) | Volume too low; leaf datum not fixed in BRC-220 |
| `brc100-secp256k1` as a required suite | No wallet users yet; the suite stays defined so bundles are forward-compatible |
| Key linkage from the party's identity key (BRC-69/97) | No checkable proof type exists |
| `authenticated-sender` fields `accountRef`, `organisationNumber`, `organisationVerifiedAt` | Cross-agreement linkage; no register check exists |
| BRC-52 verifier keyrings instead of raw revelation keys | Only meaningful for wallet parties |
| Full audit log in the bundle by default | IP addresses and user agents |

---

## Appendix A. Audit log profile HE-EVENTS-1

The issuer's audit log is a list of events in insertion order. Each event has `envelope_id` (UUID string),
`party_id` (UUID string, or `null` for envelope-level events), `type` (string), `at` (UTC, ISO 8601 with
microseconds and `+00:00` offset, as produced by Python `datetime.isoformat(timespec="microseconds")`),
`ip` (string truncated to 64 characters, `null` when empty), `ua` (string truncated to 300 characters,
`null` when empty) and `details` (object, stored and read back as PostgreSQL `jsonb`, so key order and
whitespace are not preserved and must not matter).

```
canonical_i = json.dumps({"envelope_id": ..., "party_id": ..., "type": ..., "at": ...,
                          "ip": ..., "ua": ..., "details": ...},
                         sort_keys=True, separators=(",", ":"), ensure_ascii=False)
hash_0      = SHA-256(utf8("" + "\n" + canonical_0))
hash_i      = SHA-256(utf8(hash_{i-1} + "\n" + canonical_i))
```

`sort_keys` orders member names by Unicode code point (Python string order), which differs from JCS's UTF-16
code-unit order for non-BMP characters; keys in this profile are ASCII, so the two agree. `seal.auditLog.head`
is the hash of the last event **up to and including the `completed` event** that the issuer appends when the
last party has signed; `count` is the number of events up to that point. Events appended afterwards (delivery,
reminders) are not covered. This profile predates v2 and keeps its serialization; a later profile MAY switch
to JCS.

## Appendix B. Test vectors (to be generated before 2.0.0)

Generated with `@bsv/sdk` where the operation exists there, cross-checked in Python (`bsv-brc`), and
published with the reference implementation:

1. A fixed `I` with derived `K_seal`, `K_att(0)`, `K_att(1)` (counterparty `anyone`) and one `K_party(0)`
   for a fixed party identity key (both sides of the derivation).
2. A signing statement whose consent text contains `å` and `é`, given once in NFC and once in NFD, with the
   single expected `statementHash` for the NFC form and the verifier's expected warning for the NFD form.
3. A seal and its raw-digest, low-S `sealSignature`.
4. One `email-control` certificate: plaintext fields, field keys, ciphertexts, `CertificateBinary` with and
   without the signature, and the `sha256` over the form with signature.
5. A NotaryHash certificate: canonical proof bytes, `proofHash`, the OP_RETURN script, and a mined
   certificate with a `spv` envelope in `TSC` format (and the optional `bump` member) against a real block
   header.
6. A WebAuthn assertion with fixed `authenticatorData` and `clientDataJSON` and the expected V4 result.
7. An HE-EVENTS-1 chain of three events with a truncated `ua`, a `null` `ip` and a `completed` event.

## Appendix C. Changes from 2.0.0-draft.1 (informative)

From the adversarial review of 2026-09-17 (`REVIEW-2.0.0-draft.1.md`):

- **C1** `K_seal` and `K_att(i)` are derived with counterparty `anyone` and verifiers recompute them (V4,
  V7); `self`-derived issuer keys are forbidden. draft.1 let anyone assemble a verifying seal around genuine
  certificates.
- **C2** §8 replaces the contradictory "ignore unknown members / MUST NOT appear" rules: verifiers hash the
  complete received object and never normalise; issuers emit NFC.
- **H1** Block time is the only established time; V5 checks key validity at block time; all issuer times are
  reported as claimed.
- **H2** `K_subj(i)` deleted; `K_att(i)` is the subject for non-wallet parties; the certificates are stated to
  be bundle artefacts that no wallet can hold.
- **H3** WebAuthn origin and RP ID pinned in the seal; full `clientDataJSON` checks; passkey registered before
  the certificate is issued; Level 3.
- **H4** §4.7 rewritten from the BRC-220 text: canonical proof bytes, `proofHash`, hybrid push list, literal
  algorithm names, raw-digest signature, `encoding`, `spv.format` pinned to `TSC`, batch deferred.
- **H5** §7.4: broadcast retry until mined, updated bundle delivered or notified; three anchor states.
- **M1** `forSelf: true`; issuer verifies `K_party(i)` by derivation; `linkage` removed.
- **M2** Certificate `sha256` includes the signature; serial is 32 CSPRNG bytes.
- **M3** §7.2 originals sanitised; parties consent to the issuer's rendering; no incremental updates after
  the hash.
- **M4** `partyCount` in statements; several seals per agreement acknowledged in reports.
- **M5** `keyHistory` entries carry predecessor proofs; revocation policy published.
- **M6** No lookup by `originalSha256`; default disclosure stated.
- **M7** Appendix A completed against the implementation.
- **M8** §8 state token, `K_state`, V10 and the overlay references removed; `previous` reserved as `null`.
- **L1–L4** §1.2 states what a bundle proves; normative text moved out of §5 and §10 into §7; eIDAS
  wording corrected; encodings declared per field; `size` dropped.

## References

- BRC-10 Merkle proof standardised format; BRC-11 TSC Proof Format with Heights; BRC-9 SPV
- BRC-42 BSV Key Derivation Scheme; BRC-43 Security Levels, Protocol IDs, Key IDs and Counterparties
- BRC-52 Identity Certificates
- BRC-56 / BRC-100 Wallet-to-Application Interface (`getPublicKey`, `createSignature`)
- BRC-62 BEEF; BRC-74 BUMP
- BRC-68 Publishing Trust Anchor Details at an Internet Domain
- BRC-169 Universal Handle Addressing and Resolution (delegation certificates, future)
- BRC-220 NotaryHash
- RFC 2119, RFC 3339, RFC 8785; W3C Web Authentication Level 3
- Regulation (EU) No 910/2014 (eIDAS), articles 3, 25, 26, 41
