# Build brief — crypto-lab-honey-encryption

Written 15 November 2026. Paste this whole file to the coding agent, or save it as `brief.md`
in the new repo. It is self-contained apart from `_MASTER-TEMPLATE.md`, which must be in the
repo root (or readable at `audits/_MASTER-TEMPLATE.md` in the crypto-lab catalog repo).

Source papers are on the owner's machine at
`~/Downloads/crypto-lab-brief-sources/crypto-lab-honey-encryption/`. Read them there; do not
search the web for copies, do not copy the PDFs into the repo, do not commit them.

---

## KICKOFF (read this first)

Build a new Crypto Lab browser demo (Vite + TypeScript, static site, no backend) in the
repository **`crypto-lab-honey-encryption`**.

Read `_MASTER-TEMPLATE.md` in full and treat it as the BINDING spec for build, teaching,
look, accessibility, README and deploy. If `audits/kickoff.md` has been given to you, it
governs how you work inside this repo. This brief supplies only the demo-specific facts and
the acceptance checks. Where the template and this brief disagree on build/teach/look/a11y,
the template wins. Where this brief states cryptographic facts, check them against the cited
primary sources and by computation; if you find one wrong, do not silently deviate: write
"Brief said X; that is wrong because Y (source or computation)" in your report and build the
correct thing.

Build to every standard in the template, in its order: §1 Build, §3 Look, §2 Teach,
§4 Accessibility (including §4.1a setup rules, §4.1b claims suite, §4.1c mutation
discipline run from a script, §4.1d negative claim), §5 README, §6 Deploy with §6.1 and §6.2.

Hard rules (from the template; repeated because they are the ones that get broken):
real computation only, never a canned or simulated verdict; honest scoping in the page and
the README; do NOT weaken a gate to get a green run; if something cannot pass honestly,
leave it failing and say so. Do not touch the shared catalog files. Copy the top bar from an
existing lab. Copy the accessibility gate and `claims.spec.ts` shape from
`crypto-lab-schnorr-forge` and rewrite every lab-specific passage.

When done, report: one-line summary with the test count; the mutation ledger (each mutation,
killed or not); the attacker success rates your build measures (FACTS 7) next to the expected
ones; confirmation that grouping / auto-merge / PR gate / workflow_dispatch are all present;
and the card metadata listed at the end of this brief.

---

## NEW DEMO BRIEF

- Repo name:         crypto-lab-honey-encryption
- Short name (H1):   Honey Encryption
- Subtitle:          Wrong password, plausible plaintext · DTE-then-encrypt · where it stops working
- One-liner:         Browser-based honey encryption of a card number under a weak password — a distribution-transforming encoder plus a cipher that never rejects, so every wrong password decrypts to a valid-looking card and a brute-force search cannot tell when it has won, beside ordinary password-based encryption where it can, and the three cases where the protection fails
- Concept to teach:  Brute force needs a way to recognise the right answer; encode the message so that every key yields a sample from the same distribution and that test disappears, but only for message recovery, only if the distribution is modelled correctly, and not once the attacker knows one plaintext.
- Primitives/spec:   A. Juels and T. Ristenpart, "Honey Encryption: Security Beyond the Brute-Force Bound" (EUROCRYPT 2014; IACR ePrint 2014/155): DTE-then-encrypt with the hash-based cipher of its Figure 4 and the inverse-sampling encoder. J. Jaeger, T. Ristenpart, Q. Tang, "Honey Encryption Beyond Message Recovery Security" (IACR ePrint 2016/174) for the limits. PBKDF2-HMAC-SHA-256 (RFC 8018), AES-CTR and AES-GCM (NIST SP 800-38A, 800-38D) for the comparison.
- Accent (--accent): #c8b560   (not used by any of the 203 labs whose accent is recorded in the 12 November 2026 snapshot; confirm against the live catalog and against neighbouring cards)
- Favicon emoji:     🍯
- In scope:          see SCOPE below
- Non-goals:         see SCOPE below

GitHub "About" line: use the one-liner above.

---

## PRE-FLIGHT (verify, do not assume)

1. Confirm the repository name is free under `systemslibrarian` and no catalog card is titled
   "Honey Encryption".
2. In the catalog repo, search `CATALOG.md` and the lab READMEs for `honey encryption`,
   `honeyword`, `distribution-transforming`, `DTE`, `decoy`. What the brief author found on
   15 November 2026 (12 November snapshot): no lab teaches honey encryption; the word "decoy"
   appears in a deniable-encryption lab, which has a different goal (a second real plaintext
   under a second passphrase the owner chose). If a lab already runs a DTE or honey
   encryption, STOP and report. Link the deniable-encryption lab and the password-hashing /
   KDF labs you actually find under Related Demos, and say how this lab differs.
3. Playwright port: ask the catalog tool (`node tools/port-sync.js` in the catalog repo). If you
   cannot reach the catalog repo, stop and ask the owner for a port. Never 4173.

---

## SOURCES AND WHAT EACH IS FOR

- **ePrint 2014/155** (in the sources folder). Read by the brief author: abstract,
  introduction, the DTE definition and inverse-sampling encoder (section 5), the
  DTE-then-encrypt construction with Figure 4 (section 6), and section 7.1 (card numbers,
  PINs, verification values). NOT read: Appendix C (the exact fixed-point representation of
  the inverse-sampling encoder), the proofs, section 7.2 (RSA keys), and the paper's own
  discussion of typo-safety in section 7. Read Appendix C and compare it with the encoder in
  FACTS 3; if they differ, keep the brief's encoder (its vectors depend on it), say "an
  inverse-sampling encoder in the style of the paper" and describe the difference.
- **ePrint 2016/174** (in the sources folder). The brief author read the abstract only. It
  says message-recovery security is a weak goal that allows partial leakage and useful
  mauling of ciphertexts, proposes stronger notions met by a variant of the construction, and
  proves that an attacker holding a few encryptions of known plaintexts can always recover
  messages. Read the relevant sections before describing any of this beyond those three
  points.

---

## FACTS (write tests from these, not from your code)

1. **The problem** (2014/155, introduction and section 7.1). A wrong password applied to an
   ordinary password-based ciphertext gives garbage, so a search over likely passwords knows
   when it has succeeded. For a 16-digit card number stored as ASCII, a wrong decryption is
   sixteen ASCII digits with probability (10/256)^16 ≈ 2.9 × 10^-23 (below 2^-74). With an
   authenticated mode the wrong password is rejected outright.
2. **Construction** (Figure 4). HEnc(K, M): S ← encode(M) (randomized); R ← random n bits;
   C2 ← H(R, K) ⊕ S; output (R, C2). HDec(K, (R, C2)): S ← C2 ⊕ H(R, K); output decode(S).
   Every key yields some seed and every seed decodes to a message. The paper notes a
   password-based key-derivation function should be applied to K and omits it for simplicity.
3. **This lab's concrete choices** (the brief's; state them on the page). Seeds are 64-bit
   integers (use BigInt). For a uniform distribution over b messages numbered 0 … b−1,
   message i owns the seeds in [⌈i·2^64 / b⌉, ⌈(i+1)·2^64 / b⌉); encode(i) picks uniformly in
   that interval with `crypto.getRandomValues` and rejection sampling; decode(S) =
   ⌊S·b / 2^64⌋. H(R, K) = the first 8 bytes, as a big-endian integer, of
   PBKDF2-HMAC-SHA-256(password = K as UTF-8, salt = R (16 bytes), 100 iterations). The
   iteration count is deliberately low so the brute-force exhibits run in a browser; say so,
   and say that honey encryption is about what happens when the key-derivation cost is not
   enough.
4. **Card numbers** (section 7.1). A 16-digit number: commonly nine digits are the account
   number and may be regarded as uniform; one digit is the Luhn check. This lab's layout: the
   fixed public prefix `400000`, nine account digits (the message, b = 10^9), one Luhn check
   digit. The prefix is a test value, not an assertion about any issuer.
5. **Bound and tightness** (Theorem 4 as applied in section 7.1). If the most likely password
   has probability w = 1/100 and the message is uniform over 10^9 values, no attacker
   recovers the message with probability much above w, and the attacker who decrypts with the
   most likely password achieves w. With the last four digits public the message space is
   10^5 and the paper's bound is about 1.05%.
6. **Small message spaces** (section 7.1, end). For a uniform 3-digit verification value
   under 100 equally likely passwords, the attacker decrypts under all of them and outputs
   the most frequent result; its success is the expected largest pile when 100 balls fall
   into 1,000 bins, divided by 100. The paper's simulation: mean largest pile 2.14 (minimum 1,
   maximum 5, standard deviation 0.372 over 100,000 runs), i.e. about 2.14%, twice w.
7. **What the brief author measured** with a separate program, 15 November 2026:
   - balls-and-bins rerun, 100,000 runs: mean 2.138, minimum 1, maximum 5, s.d. 0.373;
   - the real attack on 3-digit values with this lab's encoder and H: 421 successes in 20,000
     (2.10%), mean largest pile 2.141;
   - card numbers, 100 equally likely passwords: every one of the 100 decryptions was a
     distinct valid card in all 3,000 trials, and an attacker forced to pick one was right 33
     times in 3,000 (1.1%);
   - a second independent program (different encoder) found 200,000 of 200,000 wrong-key
     decryptions valid and their distribution uniform (chi-square 109.6 on 99 degrees of
     freedom), and attacker success 0.0098 at w = 0.01.
8. **Limits to show.**
   - *Mauling.* C2 is XORed with a pad, so flipping the top bit of C2 moves the seed by 2^63
     and the decoded account number by exactly 500,000,000 (up if the seed's top bit was 0,
     down if 1), under the right password. (Follows from FACTS 3; the 2016 paper's abstract
     states the general point.)
   - *One known plaintext.* If the attacker knows one (card, ciphertext) pair under the same
     password, a wrong password decrypts that ciphertext to the known card with probability
     10^-9, so the search recognises the password again. (The 2016 paper proves the general
     statement.)
   - *Wrong model.* The 2014 paper assumes key and message are independent and the message
     distribution is known; it gives typos as a usability cost (a mistyped password yields a
     plausible wrong card, with no error). Show the typo case with the real code.

---

## SCOPE

In scope, as exhibits in this order:

1. **Ordinary password-based encryption.** The card as 16 ASCII digits under AES-CTR with a
   PBKDF2-derived key (wrong password: bytes that are not digits) and under AES-GCM (wrong
   password: rejected). A dictionary search finds the password; show how it knows.
2. **The encoder.** A card's interval of seeds, a seed drawn from it, and decode on arbitrary
   seeds the learner types or randomises: every seed is some valid card.
3. **Honey encryption.** Encrypt; decrypt with the right password; decrypt with any other
   password and get a valid Luhn-checked card each time.
4. **The search, again.** The same dictionary attack as exhibit 1: now 100 candidates, 100
   valid cards, nothing to choose between them. Many-trial mode reports attacker success
   beside w.
5. **A small message space.** 3-digit verification values: the pile-up attack, measured,
   beside the paper's 2.14%.
6. **Where it stops.** Three panels: mauling (flip the top bit), one known plaintext (the
   search works again), and the typo (a wrong card with no warning).

Non-goals (say so on the page and in the README): the paper's encoders for PINs (they need a
real PIN-frequency corpus) and for RSA keys; the stronger notions and the modified
construction of the 2016 paper; honeywords; any claim that this protects real card data (it
is a teaching demo, and the limits in exhibit 6 are real).

---

## SECURITY / CORRECTNESS INVARIANTS

1. decode(encode(i)) = i for every i, and decode is defined on every 64-bit seed.
2. Every card shown as a decryption result has been produced by running HDec; no list of
   "fake cards" exists anywhere in the code.
3. The attacker code in exhibits 1, 4, 5 and 6 receives ciphertexts and the candidate
   password list only; "attacker succeeded" is decided by comparing its output with the true
   message afterwards.
4. Random values (R, the seed within its interval, trial parameters) come from
   `crypto.getRandomValues` with rejection sampling; no `Math.random`, no modulo bias.
5. All integer arithmetic on seeds uses BigInt; no value passes through a float.
6. Success rates are counted from runs, with the number of runs shown.
7. No real card number is ever requested. The input accepts only the nine account digits; the
   page says not to type a real card number, and nothing is sent anywhere.

---

## ARCHITECTURE

Pure modules, no DOM: `luhn.ts`, `dte.ts` (interval, encode, decode for any b), `he.ts`
(HEnc, HDec), `pbe.ts` (the ordinary schemes), `attacks.ts` (dictionary search, pile-up,
known-plaintext, maul), `trials.ts` (worker). PBKDF2, HMAC, AES-CTR and AES-GCM via WebCrypto.
Many-trial runs in a cancellable Web Worker.

---

## UI AND VISUAL SEMANTICS

Follow §3. Card numbers in grouped tabular figures. The "which one is real?" list in exhibit 4
must not mark the true card by colour, position or any attribute until the learner asks to
reveal it (test this: the DOM carries no distinguishing attribute before reveal). Seeds shown
in hexadecimal with the interval bounds.

---

## EDGE CASES (each fails closed and teaches via its message)

- Account input not exactly nine digits: refused.
- Seed 0 and seed 2^64 − 1: decode to accounts 000000000 and 999999999.
- Empty password: allowed (it is just a bad password); the page says so.
- Ciphertext with C2 outside 64 bits or R not 16 bytes: refused.
- AES-GCM wrong password: reported as "rejected", never as a decryption.
- A typo: no error is possible, by design; the page must say that this is the cost.
- Dictionary that does not contain the true password (exhibit 1): "not found".

---

## EXTENSION SEAMS (shape now, do not build)

A `Distribution` interface (cumulative weights) so a non-uniform encoder (PINs) could be added
with real data; a `Cipher` seam for the 2016 variant. Name both on the page as "not built
here".

---

## ACCEPTANCE CHECKS — expected outcomes, derived independently of any implementation

**A. Primitives.** PBKDF2-HMAC-SHA-256, RFC 7914 section 11, first vector (password "passwd",
salt "salt", 1 iteration, 64 bytes): output begins `55ac046e56e3089f` and ends `41d3a19783`;
take the full value and the second vector from the RFC. Luhn: the classic example
`79927398713` is valid; `79927398710` is not. One AES-CTR vector (NIST SP 800-38A F.5.1) and
one AES-GCM vector longer than one block from the NIST or McGrew-Viega set.

**B. Encoder.** For b = 10^9: account 123456789 owns the seeds from `0x1f9add3739635f32`
(inclusive) to `0x1f9add3b84e6593b` (exclusive), 18,446,744,073 seeds. decode of the lower
bound and of the upper bound minus one is 123456789; decode of the upper bound is 123456790;
decode of the lower bound minus one is 123456788. Every interval has 18,446,744,073 or
18,446,744,074 seeds. For b = 1000 every interval has 18,446,744,073,709,551 or …552 seeds.
decode(0) = 0; decode(2^64 − 1) = b − 1. Property test: decode(encode(i)) = i for 10,000
random i and for i = 0 and b − 1.

**C. Fixed vector.** Account 123456789 gives card `4000001234567899`. With
R = `000102030405060708090a0b0c0d0e0f`, password `correct horse`, and seed
`0x1f9add373a86a499` (lower bound + 0x1234567): H(R, K) = `0xe79380776b5f9544` and
C2 = `0xf8095d4051d931dd`. Decrypting (R, C2) gives:

| Password | Card |
|---|---|
| `correct horse` | 4000001234567899 |
| `123456` | 4000002152029847 |
| `password` | 4000004893076335 |
| `letmein` | 4000005600717434 |
| `qwerty` | 4000007943404878 |
| `correct horsf` (a typo) | 4000005684553184 |

All six pass the Luhn check. (Computed by the brief author with Python's `hashlib`.)

**D. Ordinary encryption.** With AES-CTR, 2,000 wrong-password decryptions of a card contain
no all-digit result (expected count 2,000 × 2.9 × 10^-23); the dictionary attacker returns
the true password in every one of 200 trials. With AES-GCM every wrong password is rejected.

**E. Rates** (slow tests, tagged). Cards, 100 equally likely passwords, at least 3,000
trials: all 100 decryptions valid; attacker success between 0.4% and 1.8%. Verification
values, at least 20,000 trials: pile-up attacker success between 1.8% and 2.5%; mean largest
pile between 2.10 and 2.18. If the numbers fall outside, check the encoder first.

**F. Limits.** Mauling: for the vector in C, flipping the top bit of C2 gives, under
`correct horse`, account 623456789 (the seed's top bit is 0), card `4000006234567898`.
Property: for random encryptions the account moves by exactly ±500,000,000. Known plaintext:
with one known pair and 100 candidates, the search returns the true password in every one of
200 trials. Typo: decrypting with a one-character change never throws and returns a valid
card different from the true one (vector C, last row).

**G. Mutations that must be killed (§4.1c, run from a script, each a concrete patch).**
(1) decode uses floating-point division; (2) interval bounds use floor instead of ceiling
(check B's bounds change); (3) encode always returns the lower bound (a test must show seeds
vary across the interval: the fixed vector alone does not catch this); (4) the Luhn digit is
computed doubling the wrong positions; (5) H reads the pad little-endian; (6) PBKDF2 called
with 1 iteration instead of 100 (vector C fails); (7) the attacker's success is decided by
"returned a valid card" instead of "returned the true card" (rates in E jump to 100%);
(8) the reveal attribute is present in the DOM before reveal (killed by the UI test);
(9) AES-GCM failure is caught and shown as a garbage decryption. A surviving mutation is
reported, not explained away.

**H. Fail-closed paths, each a NAMED test:** every item under EDGE CASES; invariant 3;
invariant 7 (a 16-digit paste into the account field is refused).

**I. Claims suite (§4.1b).** At minimum: every card on screen passes a Luhn check written in
the test; the cards listed in exhibit 4 number exactly the dictionary size and are distinct
(or the page states the collision); the true card appears among them exactly once; the
success count and trial count on screen give the percentage on screen; under the right
password the decryption on screen equals the card entered; stale verdicts are retired when
the password, account or dictionary changes; the no-op guard; the `[hidden]` probe.

---

## NEGATIVE CLAIM (§4.1d)

Claim, scoped to what is on the page: **"A decryption that looks like a valid card says
nothing about whether the password was right: here every one of these passwords produced a
valid card, and only one of them is the real one."**

Evidence fixture: exhibit 4 on vector C with the six passwords of the table as the
dictionary. Every result passes the Luhn check and the verdict reads
`6 PASSWORDS TRIED — 6 VALID CARDS — NO WAY TO TELL`, with the negative-claim sentence
visible in that state.

Bite fixture for mutation (7): the attacker picks the `qwerty` row; the page must report the
attack as failed for that trial even though the card is valid. The three assertions and two
bite tests are as §4.1d specifies.

---

## README NOTES

Follow §5. "What It Is" names the construction, the encoder, the comparison schemes, the
three limits, and "not production crypto — a teaching demo". "When to Use It" must include a
"do NOT": do not use this page or its code to protect real card data, and do not read the
result as protection against an attacker who can test a candidate card some other way.
"What Can Go Wrong" is exhibit 6 plus the modelling assumption. "Real-World Usage": only
deployments you can cite from a primary source; if you find none you can verify, say the
idea is mainly a research construction and leave it there. "Build & Verify" states the test
count, the RFC vectors, fixed vector C, the measured rates with their trial counts, and the
a11y gate. Credit both papers by title and authors with ePrint links; no links to PDF copies
elsewhere.

---

## CARD METADATA TO REPORT BACK (for the catalog session; do not edit the catalog yourself)

Title: Honey Encryption. Subtitle as above. Suggested categories: PASSWORDS & KDFS, SYMMETRIC
(confirm both exist in the catalog's CATEGORIES). Suggested level: intermediate. Chips: only
what the source implements (distribution-transforming encoder, honey encryption,
PBKDF2-HMAC-SHA-256, AES-CTR, AES-GCM, Luhn check). Accent #c8b560.

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
