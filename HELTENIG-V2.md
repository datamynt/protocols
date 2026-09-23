# Helt Enig Protocol v2 — Sealed Agreements on Bitcoin SV

**Version:** 2.0.0-draft.6
**Date:** 2026-09-23
**Status:** Draft for review. draft.1 was reviewed adversarially on 2026-09-17; Appendix C lists what changed
in draft.2, Appendix D what changed in draft.3, Appendix E what changed in draft.4, Appendix F what changed in
draft.5, Appendix G what changed in draft.6.
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
Where a party signed with a key only the party holds (§3.1, §3.2, §3.4), it also proves that key signed the
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
| `K_party(i)` — the party's own signing key | Party wallet (§3.1), or the party's browser from the passkey root `R` (§3.4) | `[2, "heltenig agreement signature"]` | `agreementId` | `I` |

The `anyone` counterparty is the BRC-43 public counterparty (private key `1`). A verifier therefore computes
`K_seal` and every `K_att(i)` from `I` and the invoice number alone, and MUST do so (V4, V7): a bundle whose
seal key or attestation keys are not the derived children of `I` is invalid. Issuer keys derived with
counterparty `self` MUST NOT be used, because no verifier can derive them.

`K_party(i)` is derived by the party's wallet with counterparty `I` and `forSelf: true` (BRC-56/BRC-100
`getPublicKey`). The issuer computes the same public key from `I`'s private key and the party's identity key
(BRC-42 is symmetric) and MUST reject a presented key that does not match.

**Passkey root `R` (suite §3.4).** A party without a wallet can hold the same kind of key through a passkey
that supports the WebAuthn PRF extension. `prfOutput` is the 32-byte result of `prf.eval.first` with the
input fixed to the UTF-8 bytes of `heltenig v2 party root`. The root private key is

`R_priv = HMAC-SHA256(key = prfOutput, message = UTF-8("heltenig v2 party root key"))`

read as a big-endian integer, which MUST lie in `[1, n-1]` (otherwise the passkey cannot be used with §3.4).
`R` stands where a wallet's identity key stands: `K_party(i)` is the BRC-42 child of `R` with the protocolID,
keyID and counterparty of the table above, and the issuer checks it the same way, from `R`'s public key and
`I`'s private key. `R` depends only on the passkey and the relying party, so it is the same on every device
the passkey is synced to. Nothing in the derivation comes from personal data (§9.1). `prfOutput`, `R_priv` and
`K_party(i)`'s private key exist only in the party's browser for the duration of one signing ceremony; the
issuer MUST NOT receive or store any of them.

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
Four suites are defined. An issuer MUST support `issuer-attestation`, SHOULD support `webauthn-es256`, MAY
support `webauthn-prf-secp256k1` (and MUST then also support `webauthn-es256`, §7.8), and MAY omit
`brc100-secp256k1` (§11).

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

**What is established, and what is only stated.** Passkeys are registered without attestation (synced
passkeys offer none), so neither the issuer nor a verifier can know what kind of authenticator holds the key.
What a verified assertion establishes is that the credential key registered for the address, a key the issuer
never held, signed this statement. That a person was verified by biometrics or a screen lock (`UV`), and
whether the passkey is synced (`BE`/`BS`), are the authenticator's own statements. Issuers and verifiers
MUST present them as statements ("the passkey states that …"), never as facts (§6.2, §9.7).

### 3.3 `issuer-attestation` — the issuer states that the party signed

For a party with neither a wallet nor a passkey. The issuer signs `statementHash` with `K_att(i)`.

```json
{ "suite": "issuer-attestation", "publicKey": "<K_att(i), hex>", "signature": "<DER hex>" }
```

This is **not** the party's signature. It is the issuer's statement that the party completed the signing
steps described in the party's certificate. `publicKey` MUST be the derived `K_att(i)` (§2.3), and verifier
output MUST say that the issuer, not the party, signed (§6.2).

**Sole control:** no.

### 3.4 `webauthn-prf-secp256k1` — party signs with a passkey and with a key derived from it

One WebAuthn ceremony yields two signatures over the same statement: the passkey's own ES256 assertion, as
in §3.2, and an ECDSA-secp256k1 signature by `K_party(i)`, derived in the browser from the passkey's PRF
output (§2.3). The party ends up holding a Bitcoin-capable key without a wallet, a seed phrase or an
installation.

Before the ceremony the issuer MUST hold, from the passkey's registration (§7.8), its SEC1 public key and the
public key of `R`. The issuer derives the expected `K_party(i)`, issues the primary certificate with
`subject = K_party(i)` and `webauthnPublicKey`, and builds the statement, which for this suite carries the
additional member `partyKey` = `K_party(i)` (§4.3). The assertion is requested as in §3.2 (`challenge` = the
32 bytes of `statementHash`, `userVerification: "required"`, the seal's origin) with `prf.eval.first` set as
§2.3 defines. The client derives `R_priv` and `K_party(i)`, MUST verify that the derived public key equals
`statement.partyKey` before signing, signs the raw 32-byte `statementHash` (DER, low-S), and MUST discard
`prfOutput` and both private keys when the ceremony ends. It MUST NOT store them or send them anywhere.

Signature object:

```json
{ "suite": "webauthn-prf-secp256k1", "publicKey": "<K_party(i), hex>", "signature": "<DER hex>",
  "webauthn": { "publicKey": "<P-256 key, SEC1 uncompressed, hex>", "signature": "<DER hex>",
                "authenticatorData": "<base64url>", "clientDataJSON": "<base64url>" } }
```

Because the statement names `K_party(i)` and the assertion's challenge is the statement's hash, the
authenticator's signature covers the choice of party key: nobody can pair a genuine assertion with a
secp256k1 key the party did not use, and a copy of `R_priv` alone cannot produce a signature object of this
suite.

**Sole control:** two answers, and verifiers keep them apart. The passkey signature: yes, subject to the
authenticator, exactly as §3.2. `K_party(i)`: the issuer never holds it, but it is computed in a page the
issuer serves, so it is under the party's sole control only as far as that page is honest at signing time
(§9.7). A device whose passkey has no PRF support signs with §3.2 instead and loses nothing in assurance
level (§10).

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

For suite `webauthn-prf-secp256k1` the statement carries one more member, `"partyKey": "<K_party(i), hex>"`.
It MUST be present for that suite and MUST be absent for every other.

`statementHash = H(JCS(statement))`. The statement binds agreement, document, party slot, roster size,
certificate, consent and suite (and, where present, the party key), so a signature cannot be moved to another
agreement, slot, roster or certificate.

### 4.4 Party certificates

Each party has exactly one **primary certificate**, a BRC-52 certificate issued by the issuer with field
values encrypted per BRC-52. The certifier signature is made, as BRC-52 specifies, with the certifier's
child key for protocol `[2, "certificate signature"]`, keyID `<type> <serialNumber>`, counterparty `anyone`,
so any verifier derives the signing key from `I`.

**What these certificates are.** For a party who signs with an own secp256k1 key (§3.1, §3.4) the `subject`
is `K_party(i)`, a per-agreement child key; for every other party the `subject` is `K_att(i)`, which the issuer holds. In both cases the certificate
is an artefact of the bundle: no BRC-100 wallet can acquire, store or present it, because BRC-52 storage
requires the subject to be the wallet's identity key. For a non-wallet party the certificate is therefore the
issuer's signed, selectively disclosable record of the identity check it performed, and nothing more.
Implementations and verifiers MUST describe it that way.

**Common rules**

- `certifier` = `I` (or a `keyHistory` key valid at the anchor block time).
- `subject` = `K_party(i)` for suites `brc100-secp256k1` and `webauthn-prf-secp256k1`, otherwise `K_att(i)`.
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
| `email` | The address the issuer sent the personal link to, and which the party showed access to by the `method` below (§9.8). |
| `name` | The name as entered by the sender. **Not verified.** |
| `nameSource` | Always `"sender"` for this type. |
| `linkSentAt`, `linkOpenedAt` | When the issuer sent the personal link, and when it was first opened, as recorded by the issuer. |
| `codeVerifiedAt` | When a one-time code was verified. Present if and only if `method` names a one-time code. |
| `method` | How control of the address was established and what was added to it. Defined values: `"email-link"` (the personal link was the signing credential), `"email-link+one-time-code"` (the link, plus a code mailed to the same address and typed back) and `"email-link+passkey"` (the link, plus a signature by a passkey registered for that address, §7.8). An issuer MAY define further values for additional factors (§4.4.1). |
| `webauthnPublicKey` | The passkey public key (SEC1 hex). Present when the party signs with a passkey (§3.2, §3.4). |
| `passkeyRegisteredAt` | When that passkey was registered with the issuer, as recorded by the issuer. Present with `webauthnPublicKey`. It lets a reader tell a passkey made minutes before the signature from one the party has used for months. |

**Type `authenticated-sender`** — type id = base64 of `H("heltenig v2 certificate authenticated-sender")`

| Field | Meaning |
|---|---|
| `email` | The sender's login e-mail. |
| `name` | The sender's display name from the login provider or as entered. |
| `loginMethod` | How the sender logged in: e.g. `"google"`, `"microsoft"`, `"email-link"`, or the name of the login service the issuer uses. Never a passkey: a passkey signs, it does not log in. |
| `webauthnPublicKey` | The passkey public key (SEC1 hex). Present when the sender signs with a passkey (§3.2, §3.4). |
| `passkeyRegisteredAt` | When that passkey was registered with the issuer, as recorded by the issuer. Present with `webauthnPublicKey`. |

A sender who signs with a passkey keeps this type. The authenticated login is what established control of the
address, as the personal link does for an `email-control` party, and the passkey is added to it (§7.8). The type
has no `method`: the passkey is recorded by `webauthnPublicKey` and `passkeyRegisteredAt` and checked through the
suite (V4) and V6.5, exactly as for `email-control`. An issuer MUST NOT put the passkey fields on a certificate for
a sender who did not sign with that passkey; where its records cannot show the passkey signature, it issues the
certificate without them, which claims the login only (§4.4.1).

Future certificate types (a BankID identity certificate from an identity broker, a BRC-169 organisation
delegation certificate) plug in as additional certificates for the same subject key. They MUST be listed in
the seal (§4.6) to be considered.

#### 4.4.1 `method` and what it must not claim

`method` is the certificate's statement about what the party actually did, and the field a reader leans on
when deciding what a signature is worth. Therefore:

- The issuer MUST set `method` to the factors the party actually completed, and MUST NOT name a factor that
  was not exercised for that party. Where the issuer's own records cannot tell the factors apart, it MUST
  choose the weaker value.
- `codeVerifiedAt` MUST be present when `method` names a one-time code, and MUST be absent otherwise. An
  issuer MUST NOT emit a certificate with one and not the other; a verifier MAY report the mismatch, and
  MUST NOT read a `codeVerifiedAt` as a factor that `method` does not name.
- An issuer that adds a second factor (a code, an SMS, a passkey challenge, a wallet) MUST record it in
  `method` rather than leaving `method` unchanged; a value not listed here is permitted and SHOULD read as
  `email-link+<factor>`.
- Verifiers MUST NOT reject a bundle for carrying a `method` they do not recognise; an unrecognised value is
  handled exactly like an unrecognised certificate type (§6.1 V6, §6.2). The defined values verify
  identically: `method` changes what the certificate claims, not how it is checked. A passkey named in
  `method` is checked through the suite (V4), not through `method`.

Bundles issued under an earlier `method` remain valid; the value records history and is never rewritten.

### 4.5 Disclosures

A proof bundle is handed to the parties and whoever they share it with. By default the bundle discloses
the fields printed on the certificate page of the signed PDF (names, e-mail addresses, times) and, for a
passkey party, `webauthnPublicKey` and `passkeyRegisteredAt`, which V6 needs and which add nothing the
signature object does not already show (§9.6). The
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
- `issuer.webauthn` is present when any party used `webauthn-es256` or `webauthn-prf-secp256k1`; it fixes the origin and RP ID a
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
   1. The party opens the personal link. Delivery of that link to the party's address, and its use within
      its validity window, is what establishes control of the address; an issuer MAY require a further
      factor and then records it in `method` (§4.4.1). The issuer MUST NOT treat the mere opening of a link
      as a signature: a mail scanner, a link preview or a prefetcher opens links (§9.9).
   2. The party chooses how to sign. For a passkey, the party uses one registered for the address earlier
      (§7.8) or registers it now (WebAuthn `create`), and the issuer records the SEC1 public key and, when
      the passkey supports PRF, the public key of `R`; for a wallet, the issuer obtains the party's identity
      key and `K_party(i)`.
   3. The issuer issues the party's primary certificate (§4.4), including `webauthnPublicKey` when a
      passkey was registered.
   4. The issuer builds the signing statement with the certificate serial, the consent text and the suite.
   5. The party signs: WebAuthn assertion (§3.2), assertion plus derived key (§3.4), wallet signature
      (§3.1), or by confirming consent, in which case the issuer attests (§3.3).
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
  - Every secp256k1 signature in a bundle MUST be low-S (§2.4), and a verifier MUST reject a high-S one
    rather than normalise it: two verifiers that disagree about one bundle are worse than either rule.
  - `webauthn-es256`: decode `clientDataJSON`; `type` MUST be `"webauthn.get"`; the base64url `challenge`
    MUST decode to `statementHash`; `origin` MUST equal `seal.issuer.webauthn.origin`; `crossOrigin` MUST be
    absent or the JSON boolean `false` (the number `0` is not `false`). `clientDataJSON` MUST be UTF-8 without
    a byte order mark, and every base64url value MUST be in canonical unpadded form. In `authenticatorData`, `rpIdHash` MUST equal `H(seal.issuer.webauthn.rpId)` and the
    UP and UV flags MUST be set. The ES256 signature MUST verify over `authenticatorData || H(clientDataJSON)`
    under `signature.publicKey`. Report the `BE`/`BS` flags.
  - `webauthn-prf-secp256k1`: every `webauthn-es256` check above MUST pass on `signature.webauthn` (its
    `publicKey`, `signature`, `authenticatorData`, `clientDataJSON`). `statements[i].partyKey` MUST be present
    and MUST equal `signature.publicKey`; the secp256k1 signature MUST verify over `statementHash` under
    `signature.publicKey`, and that key MUST equal the primary certificate's `subject` (V6). For every other
    suite a statement carrying `partyKey` is invalid.
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
  3. The primary certificate's `subject` MUST equal `signature.publicKey` for suites `brc100-secp256k1` and
     `webauthn-prf-secp256k1`, and the derived `K_att(i)` otherwise. `statements[i].certificateSerial` MUST equal the primary serial.
  4. Decrypt disclosed fields with the bundle's revelation keys. `agreementId` and `partyIndex`, when
     disclosed, MUST match.
  5. For `webauthn-es256`, the disclosed `webauthnPublicKey` MUST equal `signature.publicKey`; for
     `webauthn-prf-secp256k1` it MUST equal `signature.webauthn.publicKey`. If that field is not disclosed,
     report the passkey binding as **undisclosed**.
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
- `webauthn-prf-secp256k1`: "signed with a passkey on their device, and with their own key derived from
  it" (+ synced / not synced when known). A verifier MUST NOT shorten this to the wording of
  `brc100-secp256k1`: the key was computed in a page the issuer served (§9.7).

For both passkey suites the report states user verification and sync status as what the passkey states
(§3.2), and MUST NOT say where or how the signature was physically made.
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

### 7.7 The personal link as a credential

An issuer that lets the personal link stand as the signing credential MUST:

- deliver the link only to the party's own address, and give it enough entropy that it cannot be guessed
  (at least 128 bits) while storing only its hash;
- bound its validity, and record in `linkSentAt` the issue time the window is measured from. Reissuing a link
  (invitation, resend, reminder, or a party's request) MUST invalidate the previous one and start a new
  window;
- make signing an explicit act that a request to the link's URL cannot perform on its own: a state-changing
  method, an affirmative consent step, and a defence against cross-site submission (§9.9);
- let a party whose link has expired obtain a new one, sent to the same address it was first sent to, without
  revealing that address to whoever asked, and rate-limit that request.

### 7.8 Passkeys registered for an address

An issuer that lets a party sign with a passkey (§3.2, §3.4) MUST:

- register a passkey for an address only in a session that has just established control of that address
  under this protocol (a party who has completed the signing steps through a valid personal link, or an
  authenticated sender), and tell the address by e-mail that a passkey was registered, with a way to remove
  it. For an authenticated sender the session is the login, and the signing act the window is measured from
  (next item) is the sender's own signature made from that login; the registration is bound to it: the
  sender's own party, on the sender's own agreement, for the address the login is authenticated for, and
  never for another account or address;
- register only within a short time of that party's signing act (15 minutes is reasonable), never on a
  cancelled agreement, and never replace an active passkey silently: the holder removes the old one first,
  with the link from the notice. Otherwise a personal link that leaks later (a forwarded mail, a shared
  inbox) becomes a standing credential for every future sender;
- check at registration that the authenticator data carries attested credential data, that its credential
  id is the one presented, and that its public key is the one stored. This binds the three values to each
  other; it does not attest the authenticator (§3.2);
- choose the WebAuthn `user.id` with a CSPRNG (§9.1) and show the party's own address as `user.name`, so the
  party recognises the passkey in their device's list;
- store only the credential id, the SEC1 public key and, for §3.4, the public key of `R` together with a
  signature by `R` over the registration challenge (proof of possession). It MUST NOT receive `prfOutput` or
  any private key;
- keep the personal link as what establishes control of the address for **each** agreement. The passkey is
  added to the link, never used instead of it, and the certificate says `method = "email-link+passkey"`. A
  passkey registered during an earlier compromise of the mailbox is therefore useless without the mailbox.
  For an authenticated sender the login takes the place of the link: the sender signs with a passkey only
  from an authenticated session for the same address, and the certificate stays `authenticated-sender`,
  carrying `webauthnPublicKey` and `passkeyRegisteredAt` (§4.4);
- treat a passkey as registered for the address, not for the route that registered it: the one active
  passkey of an address MAY sign for that address as a recipient (with the personal link) and as an
  authenticated sender (with the login). Neither route may use it without its own control factor, and each
  certificate names only the factor that was used for that signature;
- keep passkey trouble away from link signing and from the sender's own signing: a failing passkey table,
  lookup or script MUST leave both flows exactly as they are for a party without a passkey;
- fall back without loss to the party: a device without PRF support signs with `webauthn-es256`, and a
  device without a usable passkey, or a party who dismisses the prompt, signs with `issuer-attestation`
  (§7.1). A passkey prompt MUST NOT stand between a party and the ability to sign;
- explain the prompt before it appears. Browsers word passkey dialogs as signing **in**, and a first-time
  party who is asked to "sign in" while signing an agreement has reason to stop.

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
Seals anchored before the compromise are unaffected. Parties who sign with suites 3.1, 3.2 or 3.4 are protected
against forged signatures regardless of issuer compromise (a stolen `I` does not yield an authenticator); their certificates, however, are still the
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
- Key derivation per agreement prevents linking a party or the issuer's seal keys across agreements. The
  passkey root `R` (§2.3) is the same for every agreement and is therefore known to the issuer only, who
  already knows the address it belongs to; it MUST NOT appear in a bundle, a certificate or on chain.
- The passkey's own P-256 public key cannot be derived per agreement: it is one key for every agreement that
  party signs with that passkey, and it stands in the signature object of each bundle. A default bundle
  already names the party by e-mail address, so the key tells its holder nothing new; but a bundle variant
  with fewer disclosures (§4.5) still carries it, and two such bundles can be linked by it. Issuers MUST say
  so when they offer reduced disclosure. `K_party(i)` does not have this property.
- Funding: anchors paid from one issuer wallet can be clustered by transaction-graph analysis, revealing the
  issuer's anchoring volume and timing.
- Lookup is by `signedDocument.sha256` only (§7.5) and rate-limited.
- Disclosure in a shared bundle is irrevocable; the optional audit log contains IP addresses and user agents.

### 9.7 Passkeys

A passkey created during signing is bound to an authenticator, not a person, and synced passkeys are
controlled by a cloud account. The certificate binds the passkey to the e-mail check, or to the sender's login,
at signing time; it does not strengthen identity beyond that check. The origin and RP ID are fixed in the seal,
so a later manifest cannot retroactively widen them.

For §3.4, four further points:

- **The page is in the trust path of the derived key.** `R_priv` exists in the memory of a page the issuer
  serves. An issuer that serves hostile script, or whose page is compromised, can copy it. That does not let
  anyone forge a signature object of §3.4, which also needs the authenticator, but it would matter for
  anything `K_party` keys are used for outside this protocol. A native BRC-100 wallet (§3.1) does not have
  this limit; §3.4 trades it for needing no installation.
- **Synced passkeys carry the PRF secret with them.** `R` is then the same on every device of the party's
  cloud account, and as exposed as that account. Measured on 2026-09-21 with Google Password Manager: a
  passkey created in Chrome 149 on a Linux desktop returned PRF output at creation, and Chrome 153 on
  Android, signed in to the same account, derived the identical key with no new registration. Apple
  platforms were not measured; the fallback in §7.8 is what makes that harmless.
- **Losing the passkey loses the key, and for signatures that costs nothing.** The bundle carries
  `K_party(i)`'s public key, so past signatures verify for ever; the next agreement is signed with a new
  passkey or by link. There is nothing to back up and no recovery flow to attack. This stops being true the
  moment such a key controls funds or state (§11).
- **One root per passkey, one key per agreement.** Signing with `R` directly, or with any secp256k1 key that
  repeats across agreements, would give every bundle a person shares the same identifier. Implementations
  MUST sign with the per-agreement child only. (The passkey's own P-256 key does repeat, and cannot be made
  not to; §9.6 says what follows from that.)
- **No attestation, so no facts about the authenticator.** A party can register a software key and set any
  flag. That weakens that party's own evidence and nobody else's: it still takes the personal link to sign,
  and the signature is still by a key the issuer never held. It is why §3.2 separates what is established
  from what is stated.

### 9.8 What a link-only signature shows

A signature at `method = "email-link"` shows that someone with access to the mail delivered to that address
completed the signing steps within the link's validity window. It does not show which human that was. Mail is
forwarded, mailboxes are shared, and an address belongs to an employer more often than to a person, so the
signer may be a colleague, an assistant or a successor in the same role. A mailbox compromised during the
window is a valid link. The window bounds the exposure: it is what separates "had access to the inbox then"
from "has the mail archive now".

This is still A0 (§10), a simple electronic signature — the same level as link plus one-time code, because a
code mailed to the address the link was mailed to tests the same channel a second time and adds little the
first did not establish. Issuers MAY add a second factor over a different channel, and MUST then record it in
`method` (§4.4.1); only that changes what the certificate claims.

Two things carry the weight instead of the factor count: the trail (link sent, link opened, consent
confirmed with the document hash, signed, each with time, IP and user agent, hash-chained per Appendix A) and
the seal's anchor, which fixes when the record existed. A verifier MUST present the method as the certificate
states it and MUST NOT describe a link-only signature as identity-verified.

### 9.9 Opening a link is not signing

Anything between the sender and the party opens links: scanners in the mail path, link previews in chat
clients, prefetchers in browsers and mail apps, archivers. An issuer whose link signs on GET, or on any
request without an affirmative act, will record signatures nobody made, and the audit trail will say they
were made from the scanner's address.

An issuer MUST therefore require, for the signing act itself: a state-changing request (never GET), an
explicit consent step by the party in that request, and a check that the request came from the issuer's own
page (an origin check, a token, or both). `linkOpenedAt` records an opening, never a signature, and an
implementation SHOULD expect openings it cannot attribute to the party.

### 9.10 What "confirmed by domain" means

The manifest is controlled by whoever holds the domain. Predecessor proofs stop a new domain holder from
inserting a key the previous holder did not endorse, but the first key in the list is trusted on the domain's
word alone. A verifier that has `I` from another channel SHOULD compare it.

---

## 10. Assurance levels (informative)

| Level | Party signature | Identity certificate | Plain-language claim |
|---|---|---|---|
| **A0** | `issuer-attestation` | `email-control` (any `method`) or `authenticated-sender` | The issuer states that someone with access to the mail delivered to this e-mail address, or logged in with it, completed the signing steps. |
| **A1** | `webauthn-es256`, `webauthn-prf-secp256k1` or `brc100-secp256k1` | `email-control` or `authenticated-sender` | Someone controlling this e-mail address signed with a key only they control. |
| **A2** | as A1 | an identity certificate from a recognised identity provider (e.g. BankID) | A person identified by that provider signed with a key only they control. |

The `method` on an `email-control` certificate, and the `loginMethod` on an `authenticated-sender` one, do not
change the level: a one-time code mailed to the same address tests the same channel twice, so link-only and
link-plus-code are both A0. A factor over a different channel, or a key the party alone holds, is what moves a
signature up, and A1 asks for the latter.

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
| Transactions co-signed by `K_party(i)` keys (an agreement whose anchor is valid only when every party has signed an input; escrow) | Needs a funded output per party and a position on the page-trust limit of §9.7 before such a key holds value |
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
8. A fixed `prfOutput` with the resulting `R` key pair, and `K_party(0)` for the fixed `I` and `agreementId`
   of vector 1, computed from both sides (the party's from `R_priv` and `I`; the issuer's from `I`'s private
   key and `R`'s public key), plus a complete §3.4 signature object over the statement of vector 2.

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

## Appendix D. Changes from 2.0.0-draft.2 (informative)

- **D1** `method` on `email-control` gains the value `email-link` for a signature where the personal link
  itself was the credential, alongside `email-link+one-time-code`. §4.4.1 states what `method` must not
  claim, ties `codeVerifiedAt` to it, requires a second factor to be recorded in it, and requires verifiers
  to pass an unrecognised value through rather than reject the bundle. Existing bundles keep verifying.
- **D2** §7.7: what an issuer must do if the personal link is the signing credential — delivery to the
  party's own address, entropy and hashed storage, a bounded window measured from `linkSentAt` that every
  reissue restarts, an explicit signing act, and a rate-limited way to get a fresh link without disclosing
  the address.
- **D3** §9.8 states plainly what a link-only signature shows and what it does not, names forwarding and
  shared mailboxes as the residual risk, and keeps the level at A0 either way. §10 says the same for the
  table: `method` does not move the level; a factor on another channel or a party-held key does.
- **D4** §9.9: opening a link is not signing. Scanners and prefetchers open links, so the signing act needs a
  state-changing request, affirmative consent and a same-origin check. §5 step 3.1 rewritten accordingly.

## Appendix E. Changes from 2.0.0-draft.3 (informative)

- **E1** New suite `webauthn-prf-secp256k1` (§3.4): one WebAuthn ceremony gives the passkey's ES256
  assertion and an ECDSA-secp256k1 signature by `K_party(i)`, derived in the browser from the passkey's PRF
  output. §2.3 defines the passkey root `R`, which stands where a wallet's identity key stands, so
  `K_party(i)` is the same BRC-42 child as for a wallet party and differs per agreement.
- **E2** The statement names the party key (`partyKey`, §4.3) for that suite, so the authenticator's
  signature covers it; V4 and V6 extended accordingly. §6.2 gives the suite its own wording.
- **E3** `method` gains `email-link+passkey`; `email-control` gains `passkeyRegisteredAt` (§4.4).
- **E4** §7.8: what an issuer must do when it registers passkeys for an address — registration only after
  address control, notice to the address, random `user.id`, no secret ever sent to the issuer, the link stays
  the credential for each agreement, and a fallback chain (§3.4 → §3.2 → §3.3) that never blocks a party.
- **E5** §9.7 states the limits of a key derived in the issuer's page, what synced passkeys mean for it, why
  key loss is free for signatures, and records the first device measurements. §9.6: `R` never appears in a
  bundle, a certificate or on chain. §11 defers transactions co-signed by party keys.

## Appendix F. Changes from 2.0.0-draft.4 (informative)

From the adversarial review of the first implementation (2026-09-21):

- **F1** §3.2: what a passkey signature establishes (the registered credential key signed; the issuer never
  held it) is separated from what the authenticator merely states (user verification, sync status).
  Registration is without attestation, so issuers and verifiers present the latter as statements. §6.2 and
  §9.7 follow.
- **F2** V4: `crossOrigin` must be absent or the boolean `false`; `clientDataJSON` without a byte order
  mark; canonical base64url; verifiers reject high-S secp256k1 signatures instead of normalising them. Each
  was a case where two conforming-looking verifiers disagreed about one bundle.
- **F3** §7.8: registration only shortly after the signing act, never on a cancelled agreement, never as a
  silent replacement; attested credential data checked for consistency; passkey failures never reach the
  link flow.
- **F4** §4.5 and §9.6: the default disclosure includes the two passkey fields V6 needs, and the passkey's
  P-256 key is named for what it is: one key across agreements, visible in every bundle's signature object,
  and therefore a linking value in reduced-disclosure variants.

## Appendix G. Changes from 2.0.0-draft.5 (informative)

From the first implementation of a sender who signs with a passkey (the party that created the agreement and
signs from the issuer's authenticated session):

- **G1** §4.4: `authenticated-sender` gains `webauthnPublicKey` and `passkeyRegisteredAt`, with the meaning they
  have on `email-control`. A sender who signs with a passkey keeps the type: the login established control of the
  address, and the passkey is added to it. `loginMethod` never names a passkey, and the passkey fields appear only
  on a certificate for a sender who signed with that passkey.
- **G2** §7.8: for an authenticated sender the login plays the part of the personal link, both at registration
  (bound to the sender's own party, agreement and login address, within a short time of the sender's own
  signature) and at signing (the certificate stays `authenticated-sender`). One passkey per address serves both
  routes, each with its own control factor, and passkey trouble must not reach the sender's own signing either.
- **G3** §10: `authenticated-sender` stands next to `email-control` in the A0 and A1 rows.

No verification rule changes. V4 and V6 were already defined per suite and per party, whatever the certificate
type, so draft.5 verifiers verify a sender's passkey signature as they stand, and conforming draft.5 bundles are
conforming draft.6 bundles.

## References

- BRC-10 Merkle proof standardised format; BRC-11 TSC Proof Format with Heights; BRC-9 SPV
- BRC-42 BSV Key Derivation Scheme; BRC-43 Security Levels, Protocol IDs, Key IDs and Counterparties
- BRC-52 Identity Certificates
- BRC-56 / BRC-100 Wallet-to-Application Interface (`getPublicKey`, `createSignature`)
- BRC-62 BEEF; BRC-74 BUMP
- BRC-68 Publishing Trust Anchor Details at an Internet Domain
- BRC-169 Universal Handle Addressing and Resolution (delegation certificates, future)
- BRC-220 NotaryHash
- RFC 2119, RFC 3339, RFC 8785; W3C Web Authentication Level 3, including its `prf` extension (built on the
  CTAP2 `hmac-secret` extension)
- Regulation (EU) No 910/2014 (eIDAS), articles 3, 25, 26, 41
