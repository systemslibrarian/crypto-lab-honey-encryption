# Honey Encryption

**Wrong password, plausible plaintext · DTE-then-encrypt · where it stops working**

A browser demo of honey encryption: a distribution-transforming encoder plus a cipher that
never rejects, so every wrong password decrypts to a valid-looking card number and a
brute-force search cannot tell when it has won — beside ordinary password-based encryption,
where it very much can, and the three cases where the protection fails.

**Live demo:** https://systemslibrarian.github.io/crypto-lab-honey-encryption/

---

## What It Is

Brute force needs a way to recognise the right answer. Ordinary password-based encryption
hands an attacker one for free: decrypt a 16-digit card number stored as ASCII under the
wrong password and you get sixteen arbitrary bytes, which are all digits with probability
`(10/256)^16` — about `2.9e-23`, below `2^-74` — so the first all-digit result is the
plaintext. With an authenticated mode it is easier still: the tag fails and the wrong
password is rejected outright.

Honey encryption removes that test. The message is first **encoded** into a seed drawn from
the part of the seed space that message owns, and the seed is then encrypted with a cipher
that has no tag and no padding. Every key yields some seed, and every seed decodes to some
message, so decryption cannot fail — and a search over likely passwords produces a list of
plausible plaintexts with nothing to choose between them.

This lab implements:

- **The distribution-transforming encoder (DTE)** — an inverse-sampling encoder in the style
  of Juels and Ristenpart over a 64-bit seed space. Message `i` of a uniform space of `b`
  owns the seeds in `[ceil(i·2^64/b), ceil((i+1)·2^64/b))`; `decode(S) = floor(S·b/2^64)`.
  All of it in BigInt — a 64-bit seed exceeds what a double holds exactly.
- **DTE-then-encrypt**, the construction of Figure 4 of ePrint 2014/155 (its section 5):
  `HEnc(K, M): S ← encode(M); R ← random n bits; C2 ← H(R, K) ⊕ S`, and
  `HDec(K, (R, C2)): S ← C2 ⊕ H(R, K); return decode(S)`, with
  `H(R, K)` the first 8 bytes, big-endian, of PBKDF2-HMAC-SHA-256 over the password with
  `R` as salt.
- **The comparison schemes** — the same card as 16 ASCII digits under AES-CTR (wrong
  password: bytes that are not digits) and AES-GCM (wrong password: rejected), under a
  PBKDF2-derived key at the same iteration count.
- **The message space** — a 16-digit card: the fixed public test prefix `400000`, nine
  account digits (the message, `b = 10^9`), and one Luhn check digit. The paper notes that
  nine digits commonly constitute the cardholder account number and may be regarded as
  uniform.
- **The three limits** — mauling, one known plaintext, and a typo.

**Not production crypto — a teaching demo.** The PBKDF2 iteration count is **100**,
deliberately far below any real figure, so the brute-force exhibits finish in a browser.
That is honest about what is being shown: honey encryption is about what happens when the
key-derivation cost is *not* enough. SHA-256, HMAC and PBKDF2 are hand-rolled so the cipher
of the construction is inspectable — and because the twenty-thousand-trial measurement needs
millions of evaluations, which WebCrypto's asynchronous `deriveBits` cannot deliver in a
page. All three are checked against FIPS 180-4, RFC 4231, the RFC 7914 §11 PBKDF2 vectors
and WebCrypto itself. AES-CTR and AES-GCM are WebCrypto.

**No real card number is ever requested.** The input accepts the nine account digits only,
and refuses a sixteen-digit paste by name. Nothing is sent anywhere; there is no backend.

### Non-goals

Stated here and on the page:

- **The paper's PIN encoder.** It needs a real PIN-frequency corpus (the paper cites a
  3.4-million-PIN study in which `1234` alone has frequency 10.713%) and the non-uniform
  balls-and-bins analysis of its Corollary 1. Inventing the frequencies would teach
  something false. A `Distribution` interface is shaped in `src/he/dte.ts` and left
  unimplemented.
- **The paper's RSA-key encoder** (its section 7.2).
- **The stronger notions and the modified construction of ePrint 2016/174** —
  target-distribution semantic security and target-distribution non-malleability. A `Cipher`
  seam is named in `src/he/he.ts` and not built.
- **Honeywords**, which are a different idea with a different threat model.
- **Any claim that this protects real card data.** It is a teaching demo, and the limits in
  exhibit 6 are real.

## Exhibits

1. **Ordinary encryption** — the card as 16 ASCII digits under AES-CTR and AES-GCM. Run the
   dictionary attack and watch the column that gives the password away: an all-digit
   plaintext for CTR, a verified tag for GCM. Includes the not-found branch when the
   password is outside the list.
2. **The encoder** — a card's interval of seeds, drawn to scale against its neighbours, and
   `decode` on any seed you type or randomise. Every seed is some valid card; seed `0` and
   seed `2^64 − 1` decode to accounts `000000000` and `999999999`.
3. **Honey encryption** — encrypt, decrypt with the right password, then decrypt with
   anything else and get a different Luhn-valid card each time. Every row is the output of
   `HDec`; no list of plausible-looking cards exists anywhere in the code.
4. **The search, again** — the same dictionary attack against the honey ciphertext. Six
   candidates or a hundred, every one a valid card, nothing to choose between them. Pick a
   row yourself and the page scores your guess against the card it kept back. Many-trial
   mode reports measured attacker success beside `w`.
5. **A small message space** — three-digit verification values, where the message space is
   small enough that candidates collide and the attacker can output the largest pile. Run
   one attack, then measure the rate against the paper's 2.14%.
6. **Where it stops** — mauling (flip the top bit of `C2`), one known plaintext (the search
   works again), and a typo (a wrong card, with no warning), plus the modelling assumption
   underneath all of it.

## When to Use It

Use it to teach why a brute-force attack needs a recognition test, what it costs to remove
one, and what a security bound does and does not promise. It is a good companion to any
password-hashing demo: honey encryption and an expensive KDF defend the same thing by
opposite means, and this lab makes the difference concrete.

**Do NOT** use this page, or its code, to protect real card data. The iteration count is a
hundred, there is no integrity protection at all, and the construction fails outright
against an attacker holding one known plaintext. **Do NOT** read the result as protection
against an attacker who can test a candidate card some other way — if they can ask a payment
network whether a number is live, the decoys evaporate and the bound says nothing.

## Live Demo

https://systemslibrarian.github.io/crypto-lab-honey-encryption/

Encrypt an account number under a weak password, decrypt it under every wrong password you
can think of, watch each one produce a different valid card, then try to tell which is real.
Measure how often a hundred-candidate attacker actually wins. Then break it three ways.

## What Can Go Wrong

Exhibit 6, in full, plus the assumption underneath:

- **Mauling.** `C2` is XORed with a pad, so a flipped ciphertext bit is a flipped *seed*
  bit. Flipping the top bit moves the seed by `2^63` and the decoded account by exactly
  **500,000,000** — up if the seed's top bit was 0, down if 1. The new card passes its check
  digit, there is no tag to notice, and the attacker chose the amount without ever learning
  the card.
- **One known plaintext.** Given one `(card, ciphertext)` pair under the same password, a
  candidate can be tested by decrypting the known ciphertext and comparing: a wrong password
  passes with probability `1e-9`. The recognition test is back and the password falls.
  Jaeger, Ristenpart and Tang prove this is unavoidable for schemes of this kind (ePrint
  2016/174, section 4, "Impossibility of KMA Security with Low-entropy Keys").
- **A typo.** A mistyped password yields a plausible wrong card with no error, because no
  error is possible. This is the usability price of the same property that defeats the
  attacker in exhibit 4; you cannot have one without the other.
- **A wrong model.** The 2014 paper assumes key and message are independent and that the
  message distribution is known and correctly modelled. This lab models nine account digits
  as uniform. If the real distribution differed — if issuers allocated account numbers in
  blocks — the decoys would be drawn from the wrong distribution and an attacker who knew
  the right one could separate the real card from them without touching the cryptography.
  A DTE is only as good as the distribution it encodes.
- **A small message space.** The bound depends on the message space being large next to the
  number of candidate keys. For a three-digit value it is not, and the pile-up attack beats
  `w` by about a factor of two — measured below.

## Real-World Usage

Honey encryption is, as far as can be verified from primary sources, **mainly a research
construction**. The 2016 follow-up notes that schemes based on the Juels–Ristenpart
construction were subsequently proposed for password management systems and for long-term
protection of genetic data; those are proposals in the literature rather than deployments
this README can point at. No shipped product is claimed here, because none could be cited
from a primary source — and a teaching demo that invented one would be doing the thing this
lab exists to argue against.

The underlying idea has a close relative that *is* deployed: honeytokens and honeywords —
decoy credentials and card numbers planted to detect a breach. That is a different
mechanism with a different goal (detection, not confidentiality), and it is not implemented
here.

## How to Run Locally

```bash
npm install
npm run dev            # http://localhost:5173/crypto-lab-honey-encryption/

npm test               # the unit and correctness suite
npm run test:slow      # the tagged rate measurements (several minutes)
npm run build
npm run test:a11y      # the WCAG 2.1 A/AA gate, against the production build
npm run test:claims    # the claims suite, including the negative claim

node scripts/measure-rates.mjs      # the attacker rates, sharded across cores
node scripts/mutate.mjs             # the nine mutations, writing the ledger
```

## Related Demos

- [Shadow Vault](https://systemslibrarian.github.io/crypto-lab-shadow-vault/) — deniable
  encryption. Also produces a plausible plaintext under a second passphrase, but for a
  different purpose and by a different mechanism: there, the owner *chooses* a second real
  message in advance and the decoy is a message they wrote. Here nobody chooses anything —
  every wrong password yields a fresh sample from the message distribution, and there is no
  second plaintext to disclose under coercion.
- [KDF Arena](https://systemslibrarian.github.io/crypto-lab-kdf-arena/) — the other defence
  against the same attack. A KDF makes each guess expensive; honey encryption makes a
  correct guess unrecognisable. This lab deliberately turns the first one down to 100
  iterations so the second is what you are looking at.
- [bcrypt Forge](https://systemslibrarian.github.io/crypto-lab-bcrypt-forge/) — password
  hashing and work factors, for the cost side of the same trade.

## Build & Verify

**99 tests** (plus 3 tagged slow measurements, skipped by default), Vitest, all passing.

Known-answer tests, all from primary sources:

| Vector | Source |
|---|---|
| PBKDF2-HMAC-SHA-256, both vectors, full 64 bytes | RFC 7914 §11 |
| SHA-256 `abc`, multi-block, empty, million-`a` | FIPS 180-4 |
| HMAC-SHA-256 cases 1, 2, 4, over-long key | RFC 4231 |
| AES-CTR, all four blocks | NIST SP 800-38A F.5.1 |
| AES-GCM cases 3 and 4, ciphertext and tag | McGrew–Viega |
| Luhn `79927398713` valid, `79927398710` not | ISO/IEC 7812-1 |

The hand-rolled SHA-256, HMAC and PBKDF2 are additionally checked against WebCrypto over
random inputs at every length from 0 to 200 bytes and across key and message sizes.

**Fixed vector.** Account `123456789` gives card `4000001234567899`. With
`R = 000102030405060708090a0b0c0d0e0f`, password `correct horse`, and seed
`0x1f9add373a86a499` (the interval's lower bound `0x1f9add3739635f32` plus `0x1234567`):
`H(R, K) = 0xe79380776b5f9544` and `C2 = 0xf8095d4051d931dd`. Decrypting `(R, C2)`:

| Password | Card |
|---|---|
| `correct horse` | 4000001234567899 |
| `123456` | 4000002152029847 |
| `password` | 4000004893076335 |
| `letmein` | 4000005600717434 |
| `qwerty` | 4000007943404878 |
| `correct horsf` (a typo) | 4000005684553184 |

All six pass the Luhn check. Flipping the top bit of `C2` gives account `623456789`, card
`4000006234567898` — exactly +500,000,000.

**Measured attacker rates** (`node scripts/measure-rates.mjs`, 15 November 2026, every
figure counted from runs and shown with its denominator):

| Measurement | This build | The paper |
|---|---|---|
| Cards, 100 equally likely passwords, **3,000 trials** | **32 successes, 1.067%**; all 100 decryptions valid and distinct in 3,000/3,000 trials | bound `w = 1%`, tight |
| Verification values, `b = 1000`, **20,000 trials** | **424 successes, 2.120%**; mean largest pile 2.139 (sd 0.376, min 1, max 5) | ≈ 2.14%, twice `w` |
| Balls and bins, 100 balls into 1,000 bins, **100,000 runs** (no cryptography) | mean 2.138, sd 0.371, min 1, max 5 | mean 2.14, sd 0.372, min 1, max 5 |

The real attack and the abstract balls-and-bins model agree to within 0.001 on the mean
largest pile, which is the check that the encoder is behaving as the analysis assumes.

**Mutation discipline.** `node scripts/mutate.mjs` runs nine mutations as concrete patches
and writes [`audits/MUTATION-LEDGER.md`](audits/MUTATION-LEDGER.md) — every observed value
in it produced by the run, never typed. **9 of 9 killed.** A kill requires all four of the
template's rules: the owning test passed unmutated in the same run, the patch changed the
file, the run served the mutated code (a browser mutation must move the built bundle's hash),
and a patch that does not compile is `DOES NOT BUILD` and never a kill.

**Accessibility gate.** `npm run test:a11y` — `@axe-core/playwright` against the production
build, WCAG 2.1 A/AA, at desktop and 380px, driven through every exhibit and every refusal
state. Zero violations, zero unexplained `incomplete` results, and the non-text contrast
baseline is **empty**. The gate found four real defects while being wired, each fixed at the
source rather than baselined; they are listed in the commit that added it.

**Claims suite.** `npm run test:claims` — 28 tests that check the page tells the truth,
including the negative claim required by the template:

> A decryption that looks like a valid card says nothing about whether the password was
> right: here every one of these passwords produced a valid card, and only one of them is
> the real one.

Its evidence fixture is exhibit 4 on the published vector: a state where every verdict the
page renders reports success and the named property is violated anyway.

## Sources

- A. Juels and T. Ristenpart, *Honey Encryption: Security Beyond the Brute-Force Bound*,
  EUROCRYPT 2014 — [IACR ePrint 2014/155](https://eprint.iacr.org/2014/155)
- J. Jaeger, T. Ristenpart and Q. Tang, *Honey Encryption Beyond Message Recovery Security*,
  EUROCRYPT 2016 — [IACR ePrint 2016/174](https://eprint.iacr.org/2016/174)
- RFC 8018 (PBKDF2), RFC 7914 §11 (its SHA-256 vectors), RFC 4231 (HMAC vectors),
  FIPS 180-4 (SHA-256), NIST SP 800-38A (CTR) and SP 800-38D (GCM)

Section numbers above follow the ePrint versions linked here.

---

*One of the browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
