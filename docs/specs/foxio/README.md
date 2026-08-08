# The FoxIO specification material

FoxIO publishes JA4+ at `https://github.com/FoxIO-LLC/ja4`. The `technical_details/`
directory holds the published form of every method. This page records what that
directory holds. It also states the procedure that every transcription under
`docs/specs/foxio/` follows.

| Item | Value |
|---|---|
| Source | `https://github.com/FoxIO-LLC/ja4/tree/main/technical_details` |
| Pinned commit | `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8` |
| Retrieval date | 2026-08-08 |

Verified against: https://github.com/FoxIO-LLC/ja4/tree/main/technical_details (retrieved 2026-08-08, commit `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`)

## The inventory

Each hash below comes from `shasum -a 256`, run on 2026-08-08 against a checkout at the
pinned commit. Each size is the exact byte count.

| File | Bytes | SHA-256 | What it holds |
|---|---|---|---|
| `README.md` | 1567 | `f02d776f50c1b805c3c5ad0c6ed6bf33f6d51aeb2888b69f803eb7a35099b8e6` | The table of twelve methods, the nine image links, and the license note. Text |
| `JA4.md` | 9153 | `14a9623ad05d6f8b5ccbff2023dc6fce10ff012dc2d202b497e3bc029aa75c94` | The JA4 algorithm. Text |
| `JA4H.md` | 278 | `7c96d53af6f51f88bb90b0d6582e10c8b2984e449cfe32940cc51b44fd4eec96` | One sentence of purpose and one rule, the header count. Text |
| `JA4.png` | 61637 | `1bd63c14b3b96c2b70bfa8e85632450c9396af9a13e274489c0cb02f2a7e9615` | The JA4 diagram |
| `JA4D.png` | 50518 | `3d862024be16c0b4679179d5433e1dc823a4721ded5b8912de1876edc4895268` | The JA4D diagram |
| `JA4D6.png` | 45911 | `26b06ae218761e532d04687131b52c88f7293f9f6f81b4e9c97f81cd8a078ff9` | The JA4D6 diagram |
| `JA4H.png` | 82051 | `08592925d1371d64bf42eeed90506dddf30e4451ba062485ae437abe6c556b80` | The JA4H diagram |
| `JA4L.png` | 162323 | `04036284edfcf0d8e94f3ca6660b1ab688813df7bfb82b0f001b65d7daa07354` | The JA4L diagram |
| `JA4S.png` | 48611 | `a4d303c3c51c2862d86abd69d6dfe6d28a43e86556a91d2c1c8261fa4de15458` | The JA4S diagram |
| `JA4SSH.png` | 92290 | `98524e55021e9d0bc42efe35e6aa0fdf002df38e65311a34d34a1bcc45e78e8c` | The JA4SSH diagram |
| `JA4T.png` | 39410 | `1a76d4ac7645b794bdb7a29fd00d2eeaf46395af3f66c0b86b76a1f6dcef76f2` | The JA4T diagram |
| `JA4X.png` | 92247 | `71f3bd839ca7e228da8ee69dce69de870d5ee69f3e91534356bae1a48d7f322a` | The JA4X diagram |

Reproduce the measurement with one command, from the root of a checkout at the pinned
commit.

```bash
shasum -a 256 technical_details/*
```

## What the inventory states

1. **The directory holds twelve files: three text files and nine images.**
2. **One method of twelve holds a complete text specification, and that method is JA4.**
   `JA4H.md` is 278 bytes. It names the purpose of JA4H and states one rule, the two-digit
   header count that omits `Cookie` and `Referer`. It builds no fingerprint. Treat JA4H as
   an image method.
3. **Three methods hold no image: JA4LS, JA4TS and JA4TScan.** `technical_details/README.md`
   lists twelve methods and embeds nine images.
4. **`JA4SSH.png` and `JA4X.png` report the same rounded size, 90.1K, and they are
   different files.** Their byte counts differ by 43 and their hashes differ. This note
   exists so that the next reader does not measure it again.

## The open question this page held

`JA4L.png` presumably carries the JA4LS form, and `JA4T.png` presumably carries the JA4TS
form.

**#196 confirmed the JA4T half.** `JA4T.png` titles itself `JA4T/S: TCP Fingerprint`, so it
specifies JA4TS as well as JA4T. `docs/specs/foxio/JA4T.md` holds the transcription.

`JA4L.png` stays unconfirmed. #200 answers it.

## The transcriptions

| Method | Page | State |
|---|---|---|
| JA4T and JA4TS | `docs/specs/foxio/JA4T.md` | Complete. #196 |
| JA4H | `docs/specs/foxio/JA4H.md` | Complete. #203 |

## How to read one image

**Warning: never copy an image into this repository.** JA4+ carries the FoxIO license and
this project publishes to PyPI. Record the SHA-256 and cite the upstream address instead.

1. Read the image at the pinned commit from a checkout outside this repository.
2. Write the transcription as this project's own prose in `docs/specs/foxio/<METHOD>.md`.
3. Open that page with four facts.
   - The source address.
   - The pinned commit.
   - The retrieval date.
   - The SHA-256 of the image you read.
4. Corroborate every rule against two FoxIO-authored sources that are not the image.
5. Cite the source of every statement.
6. Mark a rule that holds fewer than two corroborations as uncertain.
7. Keep the vector fallback for an uncertain rule.

## The two-corroboration rule

An image carries no text that a tool can search. A person reads it, and a person can
misread it. Two FoxIO-authored sources therefore corroborate each transcribed rule. The
image is the transcribed source, and it counts toward neither of the two.

These sources corroborate:

- The `README.md` of the `ja4` repository, and `technical_details/README.md`.
- The Wireshark plugin documentation.
- The doc comments under `rust/ja4/src/`.
- The Zeek scripts.
- A FoxIO blog post.

Each in-repository source counts at the pinned commit. Cite the file path and the commit,
or the URL and the retrieval date.

**A rule with fewer than two corroborations is uncertain.** Mark it uncertain on the
transcription page. Keep the vector fallback for it. An uncertain rule never changes a
fingerprinter on its own.

## The authority rule

The specification decides intent and schema. The vectors decide the exact bytes where
intent runs out. A provable reference defect is declined and recorded.

`.claude/rules/conformance.md` states the two shapes that decline a defect.
`.claude/rules/external-apis.md` states that the vector fallback needs an image that a
person read and found ambiguous. An image nobody read is not a license to use the
fallback.
