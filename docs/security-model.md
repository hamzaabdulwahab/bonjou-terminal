# Bonjou Security Model

This document describes what Bonjou's encryption layer does today (protocol v2)
and what it does not yet do. It is meant as ground truth for users deciding
whether to send sensitive content over Bonjou.

## What is protected

Protocol v2 (introduced in this release) provides:

- **Confidentiality** of every envelope and every file/folder byte against
  passive on-network eavesdroppers, using **AES-256-GCM** with HKDF-derived
  per-purpose keys.
- **Integrity** of envelopes and stream chunks: any tampering — including
  changing the wire-format version, the nonce, the ciphertext, or the
  tag — is rejected before plaintext is exposed. Streams authenticate
  **per chunk**, so corruption is detected mid-transfer, not only at the
  end via a plaintext SHA-256.
- **Identity binding (TOFU)**: the first announcement under each username
  pins that peer's X25519 public key. Subsequent announcements claiming the
  same username with a different key are dropped and logged. Users can
  inspect, replace, or remove pinned keys with `@known`, `@trust`, and
  `@forget`.
- **Replay rejection**: the wire nonce of every accepted envelope is
  remembered per peer for a sliding window; duplicates are dropped.
  Envelopes whose timestamp is more than 10 minutes stale or more than
  1 minute in the future are also rejected.
- **Size cap** on incoming transfers: `max_incoming_bytes` (default 16 GiB)
  bounds what a peer can persuade us to read.
- **Path safety**: file and folder writes are confined to the configured
  receive root via `filepath.Rel` checks; ZIP extraction validates each
  member against the same root. `@setpath` refuses to point the receive
  root at OS-level system directories.

## What is **not** yet protected

The largest remaining gap is **lack of forward secrecy**.

- A peer's X25519 long-term private key is derived deterministically from
  the `secret` value in `~/.bonjou/config.json`. Every conversation uses a
  shared secret computed from that long-term key plus the other side's
  long-term public key.
- If `config.json` is ever read by another process (browser extension,
  malware, leaked backup), **every past transcript captured on the wire
  can be retroactively decrypted**.
- A future protocol version will introduce ephemeral DH per TCP
  connection so that compromise of `config.json` does not retroactively
  decrypt historical traffic. See "Future work" below.

Other limitations:

- **TOFU can be lost on a network change**. If you've never seen a peer
  before and an attacker spoofs an announcement under their username
  before they boot, you pin the attacker's key. Side-channel verification
  (read the fingerprint over the phone or in person) remains the only
  defence against that pre-first-contact attack.
- **`config.json` is on disk in plaintext**. The file is mode 0600 but
  anything running as your user can read it. We do not yet integrate
  with platform keychains.
- **Chat content is logged in plaintext** to `~/.bonjou/logs/chat.log`.

## Cryptographic primitives

| Purpose                            | Primitive            | Notes                                                  |
|------------------------------------|----------------------|--------------------------------------------------------|
| Identity key agreement             | X25519 ECDH          | One long-term keypair per device.                      |
| Key derivation from shared secret  | HKDF-SHA256          | Info labels: `bonjou/v2/envelope`, `bonjou/v2/mac`, `bonjou/v2/stream/<id>`. |
| Envelope authenticated encryption  | AES-256-GCM          | 12-byte random nonce per envelope; version is bound as AAD. |
| Stream authenticated encryption    | AES-256-GCM, chunked | Per-stream subkey (HKDF, info=`bonjou/v2/stream/`+streamID). Nonce = 12-byte counter, never reused thanks to per-stream subkey. |
| Field-level signature (legacy)     | HMAC-SHA256          | Inputs are length-prefixed (4-byte BE). Used only for delivery-ack metadata; redundant with GCM elsewhere. |
| Replay detection                   | per-peer nonce cache | TTL 10 min; cap 4096 nonces per peer. |

## Wire format (v2)

### Envelopes

JSON-encoded, length-prefixed on the wire (a 4-byte BE length followed by the
JSON bytes):

```json
{
  "v": 2,
  "n": "<hex 12-byte GCM nonce>",
  "c": "<base64 ciphertext || 16-byte GCM tag>"
}
```

`AAD = "bonjou.v2"`. Decryption with any other version label fails.

### Streams (file/folder payloads)

Immediately after the sealed envelope, the sender opens a chunked AEAD
stream on the same TCP connection. Each chunk on the wire is:

```
[4-byte BE uint32: len(ciphertext+tag)]
[ciphertext + 16-byte GCM tag]
```

The nonce is **not** transmitted: both sides derive nonces deterministically
from a counter starting at zero. Per-stream subkeys guarantee no nonce reuse
across streams even with the same long-term key.

The receive loop terminates when total decrypted plaintext bytes equal the
size declared in the preceding envelope. Frame length is bounded
(`streamMaxFrameBytes`) to prevent allocator-based DoS.

## Threat model

Bonjou's encryption is designed to protect against the **active LAN
adversary** in v2:

- Passive eavesdropper: defended. AES-256-GCM is current best practice.
- Active LAN attacker spoofing UDP announcements: defended on second contact
  (TOFU rejects key replacement). Vulnerable on **first contact** unless the
  user verifies the fingerprint out-of-band.
- Replay of captured traffic: defended (replay cache + timestamp window).
- Tampered file payload: defended (per-chunk AEAD).

Bonjou's encryption does **not** protect against:

- A local-machine attacker with read access to `~/.bonjou/config.json`
  (loses confidentiality and identity, and can retroactively decrypt
  recorded traffic).
- An attacker who controls the user's terminal (the TUI cannot defend
  against itself being framed by a keystroke injector).
- Traffic analysis (timing, sizes, peer presence are observable).

## Future work

Tracked in `docs/backlog.md` and the project's review document:

- **Ephemeral DH per TCP session** to gain forward secrecy. The intended
  approach is to adopt a Noise-style handshake (e.g. Noise XX or IK) so
  the per-session key is independent of the long-term identity key. This
  requires a wire-format v3 because the message exchange grows by one
  handshake round trip. It is a larger refactor than the v2 cut and is
  deferred to a follow-up release.
- **OS keychain integration** so `secret` lives outside the home directory.
- **Optional chat-content encryption at rest** so the local history is not
  in plaintext.
- **Out-of-band fingerprint exchange** (QR code or short-secret confirm)
  to harden TOFU's first-contact step.

## Operational notes

- After upgrading from a pre-v2 build, peers running older versions cannot
  talk to upgraded peers. The version mismatch fails closed at envelope
  open time. This is intentional: silent fallback to v1 would re-introduce
  the weaknesses the upgrade is designed to fix.
- The fingerprint format is the leading eight bytes of `SHA-256(pubkey)`,
  printed as colon-separated hex pairs (e.g. `a1:b2:c3:d4:e5:f6:78:90`).
  64 bits of collision resistance is more than enough for visual side-
  channel verification.
- `@fingerprint` with no argument prints the local fingerprint; pass a
  username or IP to read a peer's. The output indicates whether the key
  is pinned, unpinned, or in a mismatched state.
