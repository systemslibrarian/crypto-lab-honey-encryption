# Mutation ledger

Written by `scripts/mutate.mjs`. **Every observed value here is produced by the
run, never typed.** Re-running the script rewrites this file; a hand-edit is a
second, unenforceable copy of an answer the script already holds.

Run: 2026-11-16 00:42 UTC
Mutations: 9 · killed: 9 · survived: 0 · other: 0

A kill requires all four rules of template §4.1c, and the script enforces each:
the owning test passed unmutated in the same run; the patch changed the file;
the run served the mutated code (a browser mutation must move the built
bundle's hash, a unit mutation the source file's); and a patch that does not
compile is DOES NOT BUILD, never a kill.

| # | Mutation | File | Owning test | Verdict |
|---|---|---|---|---|
| 1 | decode uses floating-point division | `src/he/dte.ts` | dte.test.ts — the documented interval, its edges, and decode(encode(i)) | **KILLED** |
| 2 | interval bounds use floor instead of ceiling | `src/he/dte.ts` | dte.test.ts — the documented bounds for account 123456789 change | **KILLED** |
| 3 | encode always returns the lower bound | `src/he/dte.ts` | dte.test.ts — "draws seeds that vary across the interval, not just its lower bound" | **KILLED** |
| 4 | the Luhn digit doubles the wrong positions | `src/he/luhn.ts` | luhn.test.ts — the classic 79927398713 example and the reversal re-derivation | **KILLED** |
| 5 | H reads the pad little-endian | `src/he/he.ts` | he.test.ts — the published fixed vector C | **KILLED** |
| 6 | PBKDF2 called with 1 iteration instead of 100 | `src/he/he.ts` | he.test.ts — vector C and the stated iteration count | **KILLED** |
| 7 | attacker success decided by "returned a card" instead of "returned the true password" | `src/he/attacks.ts` | attacks.test.ts — "separates \"produced a valid card\" from \"recovered the password\"" | **KILLED** |
| 8 | the reveal marker is present in the DOM before the learner asks | `src/ui/ex4-search.ts` | claims.spec.ts — "the true card appears among the candidates exactly once, and only after the reveal" | **KILLED** |
| 9 | an AES-GCM rejection is shown as a garbage decryption | `src/he/pbe.ts` | pbe.test.ts — "AES-GCM: every wrong password is rejected, not decrypted" | **KILLED** |

---

### (1) decode uses floating-point division

**Verdict: KILLED**

A 64-bit seed exceeds what a double holds exactly, so a float rounds a seed onto its neighbour and, at an interval edge, onto the neighbouring card.

Patch — `src/he/dte.ts`, anchor must occur exactly once:

```diff
-  return (S * b) / SEED_SPACE;
+  return BigInt(Math.floor((Number(S) * Number(b)) / Number(SEED_SPACE)));
```

Owning test: dte.test.ts — the documented interval, its edges, and decode(encode(i))

Observed in this run: source `1fc0b0ab2746` → `8e29e83727f1`, bundle `d648048add21` → `9888892e0d74`.

### (2) interval bounds use floor instead of ceiling

**Verdict: KILLED**

With a floor, a card's first seed falls inside the previous card's floor-division bucket and decode stops inverting encode.

Patch — `src/he/dte.ts`, anchor must occur exactly once:

```diff
-  return (num + b - 1n) / b;
+  return num / b;
```

Owning test: dte.test.ts — the documented bounds for account 123456789 change

Observed in this run: source `1fc0b0ab2746` → `b0c9204726e5`, bundle `d648048add21` → `f9ebbe9bfb43`.

### (3) encode always returns the lower bound

**Verdict: KILLED**

The published fixed vector supplies its own seed, so it cannot see this. Only a test that watches seeds VARY across the interval can.

Patch — `src/he/dte.ts`, anchor must occur exactly once:

```diff
-  return lo + randomBelow(size, rng);
+  return lo + 0n * randomBelow(size, rng);
```

Owning test: dte.test.ts — "draws seeds that vary across the interval, not just its lower bound"

Observed in this run: source `1fc0b0ab2746` → `1e3c1989091b`, bundle `d648048add21` → `d92740028342`.

### (4) the Luhn digit doubles the wrong positions

**Verdict: KILLED**

Every card on screen would carry a wrong check digit while still looking like a card.

Patch — `src/he/luhn.ts`, anchor must occur exactly once:

```diff
-  return i % 2 === length % 2;
+  return i % 2 !== length % 2;
```

Owning test: luhn.test.ts — the classic 79927398713 example and the reversal re-derivation

Observed in this run: source `ca58b15ed75f` → `3567ec0a50cb`, bundle `d648048add21` → `ee1e34588940`.

### (5) H reads the pad little-endian

**Verdict: KILLED**

A different pad. Every password would still produce a valid card, so the exhibits would look right and only the published vector would be wrong.

Patch — `src/he/he.ts`, anchor must occur exactly once:

```diff
-  const bytes = pbkdf2WithKey(key, R, PBKDF2_ITERATIONS, 8);
-  let v = 0n;
-  for (const byte of bytes) v = (v << 8n) | BigInt(byte);
+  const bytes = pbkdf2WithKey(key, R, PBKDF2_ITERATIONS, 8);
+  let v = 0n;
+  for (const byte of [...bytes].reverse()) v = (v << 8n) | BigInt(byte);
```

Owning test: he.test.ts — the published fixed vector C

Observed in this run: source `f2ae45f7484e` → `76b2000611ba`, bundle `d648048add21` → `cb914eab3999`.

### (6) PBKDF2 called with 1 iteration instead of 100

**Verdict: KILLED**

The construction still works; the published vector no longer holds, and the page would be stating an iteration count it does not use.

Patch — `src/he/he.ts`, anchor must occur exactly once:

```diff
-export const PBKDF2_ITERATIONS = 100;
+export const PBKDF2_ITERATIONS = 1;
```

Owning test: he.test.ts — vector C and the stated iteration count

Observed in this run: source `f2ae45f7484e` → `6f3d739a3d81`, bundle `d648048add21` → `71a1b52aec30`.

### (7) attacker success decided by "returned a card" instead of "returned the true password"

**Verdict: KILLED**

This is the mistake the whole lab exists to refute. Every honey-encryption attack would score 100% and the page would report the opposite of its subject.

Patch — `src/he/attacks.ts`, anchor must occur exactly once:

```diff
-  return { succeeded: guess !== null && guess === truePassword, guess };
+  return { succeeded: guess !== null && truePassword.length >= 0, guess };
```

Owning test: attacks.test.ts — "separates \"produced a valid card\" from \"recovered the password\""

Observed in this run: source `b693adc91a1e` → `2f9126cd99a0`, bundle `d648048add21` → `692d068f4759`.

### (8) the reveal marker is present in the DOM before the learner asks

**Verdict: KILLED**

The exhibit asks which card is real. Marking the row answers it, and nothing in a screenshot would look wrong.

Patch — `src/ui/ex4-search.ts`, anchor must occur exactly once:

```diff
-      const isTrue = run!.revealed && r.password === run!.truePassword;
+      const isTrue = r.password === run!.truePassword;
```

Owning test: claims.spec.ts — "the true card appears among the candidates exactly once, and only after the reveal"

Observed in this run: source `58dfdeb748ce` → `a9f72dc291e8`, bundle `d648048add21` → `f4d4067b94a0`.

### (9) an AES-GCM rejection is shown as a garbage decryption

**Verdict: KILLED**

Collapses the difference between CTR and GCM, which is half of what exhibit 1 teaches: GCM's refusal is a RESULT the attacker gets for free.

Patch — `src/he/pbe.ts`, anchor must occur exactly once:

```diff
-  } catch {
-    return { kind: 'rejected' };
-  }
+  } catch {
+    raw = new ArrayBuffer(16);
+  }
```

Owning test: pbe.test.ts — "AES-GCM: every wrong password is rejected, not decrypted"

Observed in this run: source `f2acd1ea2243` → `a86cadf22055`, bundle `d648048add21` → `31e84aa94fd5`.

