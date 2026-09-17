# Helt Enig Protocol v2 — Sealed Agreements on Bitcoin SV

**Version:** 2.0.0-draft.1
**Date:** 2026-09-17
**Status:** Draft for review. Not yet implemented.
**Supersedes:** [HELTENIG.md](./HELTENIG.md) v1 (withdrawn, see §1.3)
**License (specification):** MIT
**License (implementations):** Open BSV License

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as described in RFC 2119.

---

## 1. Introduction

### 1.1 What this protocol does

A multi-party agreement is signed through a signing service (the **issuer**). When every party has signed,
the issuer produces a **seal**: one record that binds

- the exact document the parties saw,
- each party's signing act, with that party's own signature where the party holds a key,
- a certificate for each party saying how the party's identity was established,
- the issuer's audit log,

and anchors the seal's hash on Bitcoin SV. The parties receive the signed PDF and a **proof bundle**. With
those two files and Bitcoin SV block headers, anyone can verify the agreement without contacting the
issuer, without trusting a certificate authority list, and after the issuer has ceased to exist.

### 1.2 Design principles

1. **Parties are keys, not e-mail addresses.** Identity attributes live in certificates (BRC-52), never in
   key derivation.
2. **Identity strength is a certificate, not a format.** An e-mail check, a BankID check or a future EUDI
   wallet check changes the certificate type, not the seal.
3. **Say who signed.** A signature made with a party's own key and a statement the issuer makes on a
   party's behalf are different things, and every verifier output MUST keep them apart.
4. **Nothing personal on chain.** The chain carries hashes only. Keys are derived per agreement, so
   public data does not link a person across agreements.
5. **Reuse the standards.** The on-chain anchor is a BRC-220 NotaryHash. Keys follow BRC-42/43,
   certificates BRC-52, transaction proofs BRC-62/74, trust anchors BRC-68.

### 1.3 Why v1 was withdrawn

v1 derived both an identity hash and a signing key from e-mail + phone number under published constants.
Anyone who knew a person's e-mail and phone number could re-derive the key and forge that person's
signature. v2 MUST NOT derive any key, hash or identifier that stands in for a person from personal data
(§9.1). v1 anchors remain on chain, but v1 signatures SHOULD be treated as issuer statements only.

### 1.4 Non-goals

- **Qualified electronic signatures (eIDAS art. 3(12)).** v2 does not make a signature qualified. §10
  describes what each assurance level can reasonably claim.
- **Trust in PDF viewers.** v2 does not make Adobe Acrobat or other viewers show a signature panel. A
  conventional PAdES seal MAY be layered on top by the issuer (§7.4).
- **Enforcement.** On-chain agreement state (§8) records what happened. It does not enforce terms.
- **Hiding that an agreement exists.** An observer can see that the issuer anchored something at a given
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

The issuer MUST publish its identity key per BRC-68 at `https://<issuer-domain>/manifest.json` under
`metanet.trust`, and SHOULD additionally list, under `heltenig`:

```json
{
  "heltenig": {
    "version": "2",
    "issuerKey": "<33-byte compressed identity key, hex>",
    "webauthnOrigins": ["https://heltenig.no"],
    "certificateTypes": { "email-control": "<type id>", "authenticated-sender": "<type id>" },
    "keyHistory": [ { "key": "<hex>", "validFrom": "<RFC 3339>", "validTo": "<RFC 3339 or null>" } ]
  }
}
```

The issuer key is also copied into every seal (§4.6), so a proof bundle stays verifiable when the domain
is gone. A verifier that cannot reach the manifest MUST report the issuer key as **pinned by the bundle
only** (§6, step V5).

### 2.3 Key derivation

All secp256k1 keys below are BRC-42 child keys with BRC-43 protocol IDs. `agreementId` is a random
UUIDv4 in lowercase string form, chosen by the issuer. Protocol names contain letters, digits and spaces
only.

| Key | Holder | protocolID | keyID | counterparty |
|---|---|---|---|---|
| `K_seal` — signs the seal | Issuer | `[2, "heltenig agreement seal"]` | `agreementId` | `self` |
| `K_att(i)` — attests for party `i` | Issuer | `[2, "heltenig party attestation"]` | `agreementId + " " + i` | `self` |
| `K_subj(i)` — certificate subject for a party without a wallet | Issuer | `[2, "heltenig party subject"]` | `agreementId + " " + i` | `self` |
| `K_party(i)` — a wallet party's signing key | Party wallet | `[2, "heltenig agreement signature"]` | `agreementId` | `I` (issuer identity key) |
| `K_state` — locks the agreement state token (§8) | Issuer | `[2, "heltenig agreement state"]` | `agreementId` | `self` |

Because every key is derived with `agreementId`, public keys of the same person or issuer do not repeat
across agreements.

### 2.4 Notation and encodings

- `H(x)` is SHA-256. Hashes are written as 64 lowercase hex characters.
- `JCS(o)` is the RFC 8785 JSON Canonicalization Scheme serialization of object `o` as UTF-8 bytes. Strings
  MUST be Unicode NFC before canonicalization.
- Timestamps are RFC 3339 in UTC with a `Z` suffix and millisecond precision, e.g. `2026-09-17T12:04:05.123Z`.
- Public keys are hex: secp256k1 compressed (33 bytes); P-256 uncompressed SEC1 (65 bytes).
- ECDSA signatures are DER-encoded, low-S, hex.

---

## 3. Signature suites

A party's signing act is a **signing statement** (§4.3) and a signature over `statementHash = H(JCS(statement))`.
Three suites are defined.

### 3.1 `brc100-secp256k1` — party signs with a BRC-100 wallet

The party's wallet signs `statementHash` as a pre-hashed digest with `K_party(i)`
(`createSignature` with `hashToDirectlySign = statementHash`, protocolID/keyID/counterparty from §2.3; the
counterparty MUST be given explicitly on both `getPublicKey` and `createSignature`).

Signature object:

```json
{ "suite": "brc100-secp256k1", "publicKey": "<K_party(i), hex>", "signature": "<DER hex>",
  "linkage": null }
```

`linkage` MAY carry a BRC-69 specific key linkage revelation from the party's identity key to `K_party(i)`,
together with BRC-52 certificates about that identity key issued by other certifiers. Because of the
limitation described in BRC-93, a verifier MUST report such a linkage as **claimed by the party** unless it
is accompanied by a proof type from BRC-97 that the verifier can check.

**Sole control:** yes. The issuer never holds `K_party(i)`.

### 3.2 `webauthn-es256` — party signs with a passkey

The party signs in a browser with a platform or roaming authenticator. The WebAuthn assertion MUST use:

- `challenge` = the 32 bytes of `statementHash`,
- `userVerification: "required"`, and the verifier MUST check the UV flag,
- an origin listed in the issuer manifest `webauthnOrigins`, with `rpIdHash` = `H(rpId)`.

The signed data is `authenticatorData || H(clientDataJSON)` per WebAuthn Level 2.

Signature object:

```json
{ "suite": "webauthn-es256", "publicKey": "<P-256 key, hex>", "signature": "<DER hex>",
  "authenticatorData": "<base64url>", "clientDataJSON": "<base64url>" }
```

The passkey public key is bound to the party by the party's certificate (§4.4, field `webauthnPublicKey`).
A passkey created during the signing flow proves sole control of a device key. It proves nothing about
the person beyond what the certificate attests.

**Sole control:** yes, subject to the authenticator. Synced passkeys (e.g. iCloud Keychain, Google
Password Manager) are controlled by the party's cloud account; verifiers SHOULD report the `BE`/`BS`
(backup eligible / backed up) flags from `authenticatorData`.

### 3.3 `issuer-attestation` — the issuer states that the party signed

For a party with neither a wallet nor a passkey. The issuer signs `statementHash` with `K_att(i)`.

```json
{ "suite": "issuer-attestation", "publicKey": "<K_att(i), hex>", "signature": "<DER hex>" }
```

This is **not** the party's signature. It is the issuer's statement that the party completed the signing
steps described in the party's certificate. Verifier output MUST say so (§6.2).

**Sole control:** no.

---

## 4. Objects

All objects are JSON. Unknown members MUST be ignored by verifiers and MUST NOT appear in the objects the
issuer hashes unless defined by a later version of this specification.

### 4.1 Agreement identifiers

- `agreementId` — UUIDv4 string, unique per agreement, generated by the issuer with a CSPRNG.
- `originalSha256` — `H(bytes)` of the document exactly as every party was shown it. For a text agreement
  rendered to PDF, the hash is of the rendered PDF bytes.

### 4.2 Consent text

The consent sentence each party confirmed, stored verbatim with a version label, e.g.

`"Jeg har lest dokumentet og signerer det elektronisk som bindende for meg. Dokumentets fingeravtrykk (SHA-256) er <originalSha256>."`

The sentence MUST contain `originalSha256` in full.

### 4.3 Signing statement

```json
{
  "protocol": "heltenig",
  "version": "2",
  "type": "signing-statement",
  "agreementId": "<uuid>",
  "originalSha256": "<hex>",
  "partyIndex": 1,
  "certificateSerial": "<BRC-52 serialNumber, base64>",
  "consent": { "version": "2026-09-17.v1", "text": "<verbatim consent sentence>" },
  "signedAt": "<RFC 3339>",
  "suite": "webauthn-es256"
}
```

`statementHash = H(JCS(statement))`. The statement binds agreement, document, party slot, certificate,
consent and suite, so a signature cannot be moved to another agreement, party slot or certificate.

### 4.4 Party certificates

Each party has exactly one **primary certificate**, a BRC-52 certificate issued by the issuer. Its field
values are encrypted per BRC-52.

**Common rules**

- `certifier` = issuer identity key `I` (or a key listed in `keyHistory` valid at `issuedAt`).
- `subject` = `K_party(i)` for suite `brc100-secp256k1`; otherwise `K_subj(i)`.
- `revocationOutpoint` = the all-zero outpoint `0000000000000000000000000000000000000000000000000000000000000000.0`.
  Primary certificates attest to past facts about one agreement and are not revocable.
- Every primary certificate has the fields `agreementId`, `partyIndex` and `issuedAt`.

**Type `email-control`** (type id = base64 of `H("heltenig v2 certificate email-control")`)

| Field | Meaning |
|---|---|
| `email` | The address the party proved control of. |
| `name` | The name as entered by the sender. **Not verified.** |
| `nameSource` | Always `"sender"` for this type. |
| `linkSentAt`, `linkOpenedAt`, `codeVerifiedAt` | Times of the e-mail link and one-time code steps. |
| `method` | `"email-link+one-time-code"` |
| `webauthnPublicKey` | Present when the party signed with suite `webauthn-es256`. |

**Type `authenticated-sender`** (type id = base64 of `H("heltenig v2 certificate authenticated-sender")`)

| Field | Meaning |
|---|---|
| `email` | The sender's login e-mail. |
| `name` | The sender's display name. |
| `loginMethod` | e.g. `"google"`, `"microsoft"`, `"email-link"`. |
| `accountRef` | `H(issuer-salt || account subject id)`, never the raw id. The salt stays with the issuer. |
| `organisationNumber` | Present only when the issuer has verified it against a public register. |
| `organisationVerifiedAt` | Time of that check. |

Future certificate types (e.g. a BankID identity certificate issued by an identity broker, or a BRC-169
organisation delegation certificate) plug in as additional certificates for the same subject key. They
MUST be listed in the seal (§4.6) to be considered.

### 4.5 Disclosures

A proof bundle is handed to the parties and whoever they share it with. By default the bundle discloses
the fields already printed on the certificate page of the signed PDF (names, e-mail addresses, times). The
issuer places the raw 32-byte BRC-52 field revelation keys for those fields in the bundle, base64-encoded:

```json
{ "certificateSerial": "<base64>", "fields": { "email": "<base64 key>", "name": "<base64 key>" } }
```

A party MAY obtain a bundle variant with fewer disclosures. Undisclosed fields stay encrypted; the
certificate signature still verifies because BRC-52 signs the encrypted form.

### 4.6 Seal record

```json
{
  "protocol": "heltenig",
  "version": "2",
  "type": "seal",
  "agreementId": "<uuid>",
  "issuer": { "identityKey": "<I, hex>", "sealKey": "<K_seal, hex>", "manifest": "https://heltenig.no/manifest.json" },
  "originalSha256": "<hex>",
  "signedDocument": { "sha256": "<hex>", "size": 183942, "mediaType": "application/pdf" },
  "parties": [
    {
      "index": 0,
      "statementHash": "<hex>",
      "signature": { "...": "signature object from §3" },
      "certificates": [ { "serialNumber": "<base64>", "sha256": "<H(certificate binary per BRC-52)>" } ]
    }
  ],
  "auditLog": { "profile": "HE-EVENTS-1", "head": "<hex>", "count": 17 },
  "sealedAt": "<RFC 3339>",
  "previous": null
}
```

- `signedDocument` is the PDF delivered to the parties: the original pages plus the issuer's certificate
  page(s). It does not contain the anchor (the anchor is created after the document).
- `parties[].certificates[0]` is the primary certificate. Additional entries are optional stronger
  certificates for the same subject.
- `auditLog.head` commits to the issuer's full audit trail without publishing it (Appendix A).
- `previous` is `null` for a first seal, and `{ "txid": "<hex>", "vout": <n> }` of the prior state token for
  an amendment or termination (§8).

`sealHash = H(JCS(seal))`. The issuer signs `sealHash` with `K_seal` → `sealSignature` (DER hex).

### 4.7 On-chain anchor

The anchor is a **BRC-220 NotaryHash** certificate in **hybrid** mode with:

| NotaryHash field | Value |
|---|---|
| `algorithm` | secp256k1 ECDSA, as named by BRC-220 |
| `hashAlgorithm` | SHA-256 |
| `payloadHash` | `sealHash` |
| `publicKey` | `K_seal` |
| `signature` | `sealSignature` |
| `createdAt` | `sealedAt` as Unix seconds |

The on-chain output therefore carries `sealHash` and hashes of `K_seal` and `sealSignature`, and nothing
else about the agreement. An issuer MAY use NotaryHash batch mode to anchor many seals in one transaction.
Fees follow the issuer's normal fee policy; this specification does not change fee rates.

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
  "anchor": { "...": "BRC-220 NotaryHash certificate, including the spv envelope once mined" },
  "auditLog": null
}
```

- `auditLog` MAY contain the full event list (Appendix A) when the parties want an independently
  recomputable trail. It contains IP addresses and user agents and is therefore omitted by default.
- A bundle created before the anchor is mined has `anchor.spv` absent. The issuer SHOULD offer the updated
  bundle for download by `signedDocument.sha256` once mined. The bundle's other contents do not change.

---

## 5. Signing flow (informative)

1. The sender authenticates and creates the agreement. The issuer computes `originalSha256` and generates
   `agreementId`.
2. The issuer invites each party with a personal link.
3. For each party:
   1. The party opens the link and proves control of the e-mail address with a one-time code.
   2. The issuer issues the party's primary certificate (§4.4).
   3. The issuer builds the signing statement with the certificate serial and the consent text.
   4. The party signs: with a wallet (§3.1), a passkey (§3.2), or by confirming consent, in which case the
      issuer attests (§3.3). A party MUST be able to sign by attestation; stronger suites are offered, never
      required, unless the sender requires a minimum assurance level (§10).
4. When all parties have signed, the issuer renders the signed PDF, computes `signedDocument.sha256`,
   builds and signs the seal, and broadcasts the NotaryHash anchor.
5. The issuer delivers the signed PDF and the proof bundle to every party. Delivery MUST NOT wait for the
   anchor to be mined, and SHOULD NOT wait for broadcast longer than a short timeout. A bundle delivered
   before broadcast carries the seal and statements; the anchor is added when available.

---

## 6. Verification

### 6.1 Algorithm

Inputs: the signed PDF bytes `D`, a proof bundle `B`, and a source of Bitcoin SV block headers.

- **V1 Document.** `H(D)` MUST equal `B.seal.signedDocument.sha256` and `len(D)` MUST equal `size`.
- **V2 Structure.** `B.seal.protocol == "heltenig"`, `version == "2"`, `type == "seal"`; one statement and one
  seal party entry per party, same order, indexes `0..n-1` without gaps.
- **V3 Statements.** For each party `i`:
  1. `statements[i].agreementId` and `originalSha256` MUST equal the seal's.
  2. `H(JCS(statements[i]))` MUST equal `seal.parties[i].statementHash`.
  3. `statements[i].suite` MUST equal `seal.parties[i].signature.suite`.
  4. The consent text MUST contain `originalSha256`.
- **V4 Party signatures.** Verify `seal.parties[i].signature` over `statementHash` by suite (§3). For
  `webauthn-es256` also check: challenge equals `statementHash`, type `webauthn.get`, origin in the issuer's
  `webauthnOrigins`, `rpIdHash`, UP and UV flags.
- **V5 Issuer key.** Determine `I` from `B.seal.issuer.identityKey`. If the manifest is reachable, `I` MUST
  be listed and valid at `sealedAt`; report **issuer key confirmed by domain**. Otherwise report **issuer key
  pinned by bundle only**.
- **V6 Certificates.** For each party's listed certificates:
  1. The certificate's BRC-52 hash MUST equal the listed `sha256`, and its serial MUST equal the listed serial.
  2. The certifier signature MUST verify. For primary certificates the certifier MUST be `I`.
  3. The primary certificate's `subject` MUST equal `K_party(i)` (wallet suite) or be the certificate subject
     used by the issuer for that party (other suites). `statements[i].certificateSerial` MUST equal the
     primary serial.
  4. Decrypt disclosed fields. `agreementId` and `partyIndex`, when disclosed, MUST match.
  5. For `webauthn-es256`, the disclosed `webauthnPublicKey` MUST equal the signature's `publicKey`. If that
     field is not disclosed, report the passkey binding as **undisclosed**.
  6. For certificates with a non-zero `revocationOutpoint`, check that the outpoint is unspent where the
     verifier has a spend source; otherwise report revocation status as **unchecked**.
- **V7 Seal signature.** `sealHash = H(JCS(B.seal))`; `sealSignature` MUST verify with `B.seal.issuer.sealKey`.
- **V8 Anchor.** Verify `B.anchor` per BRC-220: signature, `proofHash`, and anchor output. `payloadHash` MUST
  equal `sealHash`, `publicKey` MUST equal `sealKey`, `signature` MUST equal `sealSignature`. With an `spv`
  envelope, verify the Merkle proof against a block header from the header source and report the block
  height and time. Without one, report **anchor not yet confirmed**.
- **V9 Audit log (optional).** When `B.auditLog` is present, recompute the chain (Appendix A); the final hash
  MUST equal `seal.auditLog.head` and the count MUST match.
- **V10 State (optional, §8).** When the verifier has a spend source, report whether the agreement's state
  token is unspent (in force) or spent, and follow the chain of later seals.

Any MUST failure makes the result **invalid**, and the verifier MUST name the failing step.

### 6.2 What a verifier reports

A conforming verifier reports, per party, **how** that party signed, never just "signed":

- `brc100-secp256k1`: "signed with their own key"
- `webauthn-es256`: "signed with a passkey on their device" (+ synced/not synced when known)
- `issuer-attestation`: "the issuer confirms this party completed the signing steps"

plus the certificate types that establish identity (e.g. "controls the e-mail address a***@example.com",
"identity confirmed with BankID"), the anchor block height and time, and the issuer key status from V5.

A verifier MUST NOT describe a result as "legally binding" or "qualified".

---

## 7. Delivery and documents

### 7.1 The signed PDF is delivered unmodified

The delivered PDF is exactly the byte sequence hashed in `signedDocument.sha256`. The proof bundle is a
separate file. Implementations MUST NOT append the bundle to the PDF as an incremental update in v2: a
verifier that hashes only a prefix of a file can be shown different page content by a later revision
(the "incremental saving" and "shadow" attack classes known from PDF signatures).

### 7.2 Certificate page

The issuer's certificate page inside the signed PDF SHOULD show `agreementId`, `originalSha256`, each
party's name, e-mail, suite in plain language, and the verification address. It cannot show `sealHash` or
the anchor, because both are computed after the PDF.

### 7.3 Lookup

An issuer SHOULD let anyone fetch the current proof bundle by `signedDocument.sha256` (and by
`originalSha256` for status only). A lookup service MUST NOT reveal certificate fields that the bundle
does not disclose.

### 7.4 Layering a conventional seal

An issuer MAY additionally apply a PAdES seal from a certificate authority to the PDF before computing
`signedDocument.sha256`. The PAdES seal then becomes part of the hashed bytes and does not interfere with
this protocol.

---

## 8. Agreement state (optional profile)

An issuer MAY represent an agreement's lifecycle as a token (BRC-45) using a PushDrop output (BRC-48):

- **Fields:** `"heltenig"`, `"2"`, `"state"`, `sealHash` (32 bytes), status (`0x01` in force, `0x02` amended,
  `0x03` terminated).
- **Locking key:** `K_state`. **Amount:** 1 satoshi.
- **Creation:** in the same transaction as the NotaryHash anchor, or a later one referencing it.
- **Amendment or termination:** the issuer spends the token in a transaction that creates the new state
  token and anchors a new seal whose `previous` is the spent outpoint. The new seal's parties are the parties
  who signed the amendment or the termination notice.
- **Discovery:** an overlay topic `tm_heltenig_agreement` (BRC-22) admits state tokens whose seal and chain
  of `previous` references verify; a lookup service `ls_heltenig_agreement` (BRC-24) answers by `sealHash`
  and by `signedDocument.sha256` (names per BRC-87).

**Limitation:** `K_state` is held by the issuer, so the issuer could spend the token without the parties. A
verifier MUST check that every spend is accompanied by a seal whose statements justify it (V3–V8 applied
to the successor seal). A later version MAY lock the state token to a multisignature (BRC-47) including
wallet parties' keys.

---

## 9. Security considerations

### 9.1 No keys from personal data

An implementation MUST NOT derive keys, key IDs, identifiers or hashes that represent a person from e-mail
addresses, phone numbers, national identity numbers or names, with or without a published salt. Personal
attributes appear only as encrypted certificate fields.

### 9.2 Issuer compromise

A stolen issuer key allows forged attestations, forged certificates and forged seals. Mitigations:
issuer keys in hardware-backed or managed key storage; `keyHistory` in the manifest; verifiers compare the
anchor block time with key validity. A seal anchored in a block mined before the key's `validTo` is not
affected by a later compromise. Parties who sign with suites 3.1 or 3.2 are protected against forged
signatures regardless of issuer compromise, because the issuer never holds their keys.

### 9.3 Substitution and replay

The statement binds `agreementId`, `originalSha256`, party index, certificate serial and suite. The seal
binds statement hashes and certificate hashes. A signature, statement or certificate cannot be moved to
another agreement or slot without failing V3, V4 or V6.

### 9.4 Canonicalization

All hashed objects use RFC 8785 JCS with NFC-normalized strings. Implementations MUST reject objects with
duplicate member names and MUST hash the canonical form, never the received bytes.

### 9.5 Header source

SPV verification is only as good as the block header source. Verifiers SHOULD use more than one source or
validate proof of work over a header chain.

### 9.6 Privacy

- On chain: `sealHash` and hashes of an agreement-specific key and signature. No names, e-mail addresses or
  document hashes.
- Key derivation per agreement prevents linking a party or the issuer's seal keys across agreements.
- Funding: anchors paid from one issuer wallet can be clustered by transaction graph analysis, revealing the
  issuer's anchoring volume and timing. Batch mode (§4.7) reduces this.
- `originalSha256` and `signedDocument.sha256` are not on chain, but anyone holding the document can look
  up its status (§7.3). Issuers SHOULD rate-limit lookups.
- The optional audit log in a bundle contains IP addresses and user agents.

### 9.7 Passkeys

A passkey created during signing is not bound to a person, only to an authenticator, and synced passkeys are
controlled by a cloud account. The certificate binds the passkey to the e-mail check at signing time; it
does not strengthen identity beyond that check.

---

## 10. Assurance levels (informative)

| Level | Party signature | Identity certificate | Plain-language claim |
|---|---|---|---|
| **A0** | `issuer-attestation` | `email-control` | The issuer confirms that someone controlling this e-mail address completed the signing steps. |
| **A1** | `webauthn-es256` or `brc100-secp256k1` | `email-control` | Someone controlling this e-mail address signed with a key only they control. |
| **A2** | as A1 | an identity certificate from a recognised identity provider (e.g. BankID) | A person identified by that provider signed with a key only they control. |

Under eIDAS, A0 is a simple electronic signature. A1 and A2 are designed to meet the four requirements of an
advanced electronic signature (art. 26): uniquely linked to the signatory, capable of identifying the
signatory (at the level of the certificate), created with data under the signatory's sole control, and
linked to the data so that changes are detectable. Whether a specific court accepts that is outside this
specification. No level is a qualified signature, and the anchor is a non-qualified electronic time stamp
(art. 41(1)).

A sender MAY require a minimum level per party. The issuer MUST record that requirement in the audit log.

---

## 11. Versioning

`version` is `"2"` for every object in this document. Additive changes that verifiers can ignore keep
version `"2"`. Any change to hashed object layouts, suites or verification rules requires a new version.

---

## Appendix A. Audit log profile HE-EVENTS-1

The issuer's audit log is a list of events in order. Each event has:

`envelope_id`, `party_id` (issuer-internal id or `null`), `type`, `at` (UTC ISO 8601 with microseconds and
`+00:00` offset), `ip`, `ua`, `details` (object).

```
canonical_i = json.dumps({"envelope_id", "party_id", "type", "at", "ip", "ua", "details"},
                         sort_keys=True, separators=(",", ":"), ensure_ascii=False)
hash_0      = H(utf8("" + "\n" + canonical_0))
hash_i      = H(utf8(hash_{i-1} + "\n" + canonical_i))
```

`seal.auditLog.head` is the last event's hash; `count` is the number of events. This profile predates v2
and keeps its existing Python serialization, which is not RFC 8785. A later profile MAY switch to JCS.

## Appendix B. Open questions for review

1. Should `K_subj(i)` exist, or should non-wallet parties' certificates use `K_att(i)` as subject?
2. Is the all-zero `revocationOutpoint` the right convention for non-revocable BRC-52 certificates, or
   should primary certificates point at the agreement state token?
3. Should disclosures (§4.5) use per-verifier keyrings (BRC-52 verifier keyrings) instead of raw revelation
   keys in the bundle?
4. Should the NotaryHash anchor and the state token always share one transaction?
5. Test vectors: to be generated by the reference implementation before 2.0.0.

## References

- BRC-3 Digital Signature Creation and Verification
- BRC-22 Overlay Network Data Synchronization; BRC-24 Overlay Network Lookup Services; BRC-87 naming
- BRC-42 BSV Key Derivation Scheme; BRC-43 Security Levels, Protocol IDs, Key IDs and Counterparties
- BRC-45 UTXOs as Bitcoin Tokens; BRC-47 Bare Multi-Signature; BRC-48 Pay to Push Drop
- BRC-52 Identity Certificates; BRC-53 Certificate Creation and Revelation
- BRC-62 BEEF; BRC-74 BUMP
- BRC-68 Publishing Trust Anchor Details at an Internet Domain
- BRC-69 Revealing Key Linkages; BRC-93 Limitations of BRC-69; BRC-97 Proof types for specific key linkage
- BRC-100 Wallet-to-Application Interface
- BRC-169 Universal Handle Addressing and Resolution (delegation certificates)
- BRC-220 NotaryHash
- RFC 2119, RFC 3339, RFC 8785; W3C Web Authentication Level 2
- Regulation (EU) No 910/2014 (eIDAS), articles 3, 25, 26, 41
