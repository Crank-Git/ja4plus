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
   lists twelve methods and embeds nine images. **#196 found JA4TS inside `JA4T.png`, and
   #200 found no JA4LS inside `JA4L.png`.** JA4LS therefore reaches no image at all, and
   the reference implementations state every rule it follows.
4. **`JA4SSH.png` and `JA4X.png` report the same rounded size, 90.1K, and they are
   different files.** Their byte counts differ by 43 and their hashes differ. This note
   exists so that the next reader does not measure it again.

## The open question this page held, and its two answers

`JA4L.png` presumably carried the JA4LS form, and `JA4T.png` presumably carried the JA4TS
form. **The two halves have opposite answers, so read no image by the pattern of another.**

**#196 confirmed the JA4T half.** `JA4T.png` titles itself `JA4T/S: TCP Fingerprint`, so it
specifies JA4TS as well as JA4T. `docs/specs/foxio/JA4T.md` holds the transcription.

**#200 refuted the JA4L half.** `JA4L.png` titles itself
`JA4L: Light Distance/Location Fingerprint`, it labels its one example `JA4L=`, and it
states no server rule. **No image specifies JA4LS.** `docs/specs/foxio/JA4L.md` holds the
transcription and names the two sources that name JA4LS as a separate method.

## The transcriptions

| Method | Page | State |
|---|---|---|
| JA4T and JA4TS | `docs/specs/foxio/JA4T.md` | Complete. #196 |
| JA4H | `docs/specs/foxio/JA4H.md` | Complete. #203 |
| JA4SSH | `docs/specs/foxio/JA4SSH.md` | Complete. #199 |
| JA4L | `docs/specs/foxio/JA4L.md` | Complete. #200. The page covers the client form, because the image specifies no server form. |
| JA4S | `docs/specs/foxio/JA4S.md` | Complete. #201. The method reaches more published reference values than any other, so the page measures where the earlier pages reasoned. |
| JA4D and JA4D6 | `docs/specs/foxio/JA4D.md` | Complete. #204. One page transcribes the two images |
| JA4X | `docs/specs/foxio/JA4X.md` | Complete. #202. The page also answers the tunnel question the register raises. |
| The seven deleted text files | `docs/specs/foxio/deleted-text-specifications.md` | Complete. #221. It transcribes no image and it reconciles the deleted prose |

## A deleted text specification corroborates, and it never outranks the image

**FoxIO published a text specification for seven methods, and commit `b6f3ff4` deleted
all seven.** `technical_details/JA4.md` and `technical_details/JA4H.md` exist again at the
pinned commit. `JA4L.md`, `JA4S.md`, `JA4SSH.md`, `JA4T.md` and `JA4X.md` do not.

**JA4D and JA4D6 hold no deleted text file, because neither file has ever existed.** The
seven deleted names carry no `JA4D.md` and no `JA4D6.md`, and
`git log --all --diff-filter=ADR -- '*JA4D*'` reports one commit, `6239c08`, which adds
the two images and nothing else. **The two images are therefore the only FoxIO prose that
has ever specified the two methods**, and `docs/specs/foxio/JA4D.md` corroborates every
rule from implementations alone. #204 owns that reading.

A deleted file is FoxIO-authored, so it counts as one corroboration. **It is not the
pinned specification, so the image at the pinned commit outranks it.** Cite the path, the
commit that holds the file, and the blob SHA-1.

#199 read the deleted `JA4SSH.md`, and `docs/specs/foxio/JA4SSH.md` holds the provenance
table to follow. **#221 read the other six, and
`docs/specs/foxio/deleted-text-specifications.md` holds the whole reading.** That page
carries the provenance of all seven files, the byte count and the two hashes of each one,
and the reconciliation of each statement against the pinned material.

```bash
git log --oneline --diff-filter=D --name-only -- 'technical_details/*.md'
```

### How a deleted statement ranks

**Rank a statement, and not a file.** #221 measured the two files that carry a deleted
name today, and the two cases are opposite. `JA4.md` came back as the same blob five days
later, so its deletion corrected nothing. `JA4H.md` never came back: a different file of
278 bytes carries the name, and it corrects a defect the 9137-byte file holds. **A
deletion in the FoxIO repository therefore carries no single meaning**, and a reader must
weigh each sentence.

Apply these four readings, which the user set on 2026-08-08.

1. **The material at the pinned commit outranks a deleted file wherever the two
   disagree.**
2. **Where the deleted text agrees with the pinned material, it corroborates**, and it is
   a strong corroboration, because FoxIO wrote it.
3. **Where the deleted text states a rule the pinned material only draws, record it as a
   rule the pinned material does not state.** Mark the rule uncertain until a second
   FoxIO-authored source that is not the deleted file corroborates it.
4. **Where the deleted text contradicts the pinned material, report both readings and
   rule on nothing.** A contradiction is a finding, and the user decides it.

**A deleted file that states nothing about a subject corroborates no rule about it.** #221
read the deleted `JA4SSH.md` for the rule #214 needs, and the file names no FIN packet, no
connection that closes, and no end of a capture. That negative result confirms R11 of
`docs/specs/foxio/JA4SSH.md` and it answers #214 with nothing.

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
- The Zeek scripts. `docs/specs/foxio/zeek.md` records what each one builds, with a file
  path and a line number for each rule.
- A FoxIO blog post.

Each in-repository source counts at the pinned commit. Cite the file path and the commit,
or the URL and the retrieval date.

**A rule with fewer than two corroborations is uncertain.** Mark it uncertain on the
transcription page. Keep the vector fallback for it. An uncertain rule never changes a
fingerprinter on its own.

### A decision settles a reading, and it clears no uncertain mark

**No second FoxIO implementation corroborates JA4D6.** The Wireshark dissector is the only
one that writes a JA4D6 value. `zeek/README.md:15` states
`JA4D6 &rarr; ja4d.log (awaiting Zeek DHCPv6 suppport)`, FoxIO ships no Python and no Rust
for the method, and no deleted text file covers it. R16, R19 and R20 of
`docs/specs/foxio/JA4D.md` are uncertain for that one reason.

**#271 asked the user to settle what those three rules measure, and the user settled it.**
Each rule now reads its field at any nesting depth. **The three marks stay**, because the
mark counts FoxIO-authored corroborations and a decision adds none. Read the two things
apart: a decision settles what this project builds, and a corroboration settles what the
reference states.

## The authority rule

The specification decides intent and schema. The vectors decide the exact bytes where
intent runs out. A provable reference defect is declined and recorded.

`.claude/rules/conformance.md` states the two shapes that decline a defect.
`.claude/rules/external-apis.md` states that the vector fallback needs an image that a
person read and found ambiguous. An image nobody read is not a license to use the
fallback.
