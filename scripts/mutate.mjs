/**
 * Mutation discipline, run from a script (template §4.1c).
 *
 * A green suite is not evidence until you have watched it fail. This file is
 * the record of that, and it is a RUNNABLE record: each mutation below is a
 * concrete patch — a file, an anchor that must occur exactly once, and its
 * replacement — never a sentence describing an edit. A sentence cannot be
 * replayed; this can.
 *
 * A KILL REQUIRES ALL FOUR RULES, and the script enforces every one:
 *
 *   1. the owning test PASSED UNMUTATED in this same run;
 *   2. the patch actually CHANGED the file (anchor found exactly once, and
 *      the bytes on disk differ afterwards);
 *   3. the run SERVED THE MUTATED CODE — for a browser test, the built
 *      bundle's hash must move, so a stale `dist/` cannot be what was
 *      scanned; for a unit test, the source file's own hash must move, since
 *      vitest transforms the file from disk on every run;
 *   4. a patch that does not compile is DOES NOT BUILD and is NEVER a kill —
 *      a failed build leaves the previous good bundle in place and the suite
 *      passes green against code that no longer compiles, which proves
 *      nothing.
 *
 * Every `observed` value in the ledger this writes is produced by the run, not
 * typed by its author.
 *
 * Usage:
 *   node scripts/mutate.mjs            run every mutation, write the ledger
 *   node scripts/mutate.mjs 3 7        run only those mutations
 *   node scripts/mutate.mjs --list     list them without running anything
 */

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const LEDGER = path.join(ROOT, 'audits', 'MUTATION-LEDGER.md');

/**
 * The mutations.
 *
 * `kind` decides how rule 3 is proved: a `browser` mutation must move the
 * built bundle, a `unit` mutation must move the source vitest reads.
 */
const MUTATIONS = [
  {
    id: 1,
    name: 'decode uses floating-point division',
    why: 'A 64-bit seed exceeds what a double holds exactly, so a float rounds a seed onto its neighbour and, at an interval edge, onto the neighbouring card.',
    file: 'src/he/dte.ts',
    anchor: '  return (S * b) / SEED_SPACE;',
    replacement: '  return BigInt(Math.floor((Number(S) * Number(b)) / Number(SEED_SPACE)));',
    kind: 'unit',
    test: ['src/he/dte.test.ts'],
    owner: 'dte.test.ts — the documented interval, its edges, and decode(encode(i))',
  },
  {
    id: 2,
    name: 'interval bounds use floor instead of ceiling',
    why: "With a floor, a card's first seed falls inside the previous card's floor-division bucket and decode stops inverting encode.",
    file: 'src/he/dte.ts',
    anchor: '  return (num + b - 1n) / b;',
    replacement: '  return num / b;',
    kind: 'unit',
    test: ['src/he/dte.test.ts'],
    owner: "dte.test.ts — the documented bounds for account 123456789 change",
  },
  {
    id: 3,
    name: 'encode always returns the lower bound',
    why: 'The published fixed vector supplies its own seed, so it cannot see this. Only a test that watches seeds VARY across the interval can.',
    file: 'src/he/dte.ts',
    anchor: '  return lo + randomBelow(size, rng);',
    replacement: '  return lo + 0n * randomBelow(size, rng);',
    kind: 'unit',
    test: ['src/he/dte.test.ts'],
    owner: 'dte.test.ts — "draws seeds that vary across the interval, not just its lower bound"',
  },
  {
    id: 4,
    name: 'the Luhn digit doubles the wrong positions',
    why: 'Every card on screen would carry a wrong check digit while still looking like a card.',
    file: 'src/he/luhn.ts',
    anchor: '  return i % 2 === length % 2;',
    replacement: '  return i % 2 !== length % 2;',
    kind: 'unit',
    test: ['src/he/luhn.test.ts'],
    owner: 'luhn.test.ts — the classic 79927398713 example and the reversal re-derivation',
  },
  {
    id: 5,
    name: 'H reads the pad little-endian',
    why: 'A different pad. Every password would still produce a valid card, so the exhibits would look right and only the published vector would be wrong.',
    file: 'src/he/he.ts',
    anchor: '  const bytes = pbkdf2WithKey(key, R, PBKDF2_ITERATIONS, 8);\n  let v = 0n;\n  for (const byte of bytes) v = (v << 8n) | BigInt(byte);',
    replacement: '  const bytes = pbkdf2WithKey(key, R, PBKDF2_ITERATIONS, 8);\n  let v = 0n;\n  for (const byte of [...bytes].reverse()) v = (v << 8n) | BigInt(byte);',
    kind: 'unit',
    test: ['src/he/he.test.ts'],
    owner: 'he.test.ts — the published fixed vector C',
  },
  {
    id: 6,
    name: 'PBKDF2 called with 1 iteration instead of 100',
    why: 'The construction still works; the published vector no longer holds, and the page would be stating an iteration count it does not use.',
    file: 'src/he/he.ts',
    anchor: 'export const PBKDF2_ITERATIONS = 100;',
    replacement: 'export const PBKDF2_ITERATIONS = 1;',
    kind: 'unit',
    test: ['src/he/he.test.ts'],
    owner: 'he.test.ts — vector C and the stated iteration count',
  },
  {
    id: 7,
    name: 'attacker success decided by "returned a card" instead of "returned the true password"',
    why: 'This is the mistake the whole lab exists to refute. Every honey-encryption attack would score 100% and the page would report the opposite of its subject.',
    file: 'src/he/attacks.ts',
    anchor: '  return { succeeded: guess !== null && guess === truePassword, guess };',
    replacement: '  return { succeeded: guess !== null && truePassword.length >= 0, guess };',
    kind: 'unit',
    test: ['src/he/attacks.test.ts'],
    owner: 'attacks.test.ts — "separates \\"produced a valid card\\" from \\"recovered the password\\""',
  },
  {
    id: 8,
    name: 'the reveal marker is present in the DOM before the learner asks',
    why: 'The exhibit asks which card is real. Marking the row answers it, and nothing in a screenshot would look wrong.',
    file: 'src/ui/ex4-search.ts',
    anchor: "      const isTrue = run!.revealed && r.password === run!.truePassword;",
    replacement: "      const isTrue = r.password === run!.truePassword;",
    kind: 'browser',
    test: ['--project=claims', '--grep', 'exactly once, and only after the reveal'],
    owner: 'claims.spec.ts — "the true card appears among the candidates exactly once, and only after the reveal"',
  },
  {
    id: 9,
    name: 'an AES-GCM rejection is shown as a garbage decryption',
    why: "Collapses the difference between CTR and GCM, which is half of what exhibit 1 teaches: GCM's refusal is a RESULT the attacker gets for free.",
    file: 'src/he/pbe.ts',
    anchor: '  } catch {\n    return { kind: \'rejected\' };\n  }',
    replacement: '  } catch {\n    raw = new ArrayBuffer(16);\n  }',
    kind: 'unit',
    test: ['src/he/pbe.test.ts'],
    owner: 'pbe.test.ts — "AES-GCM: every wrong password is rejected, not decrypted"',
  },
];

/* ── mechanics ───────────────────────────────────────────────────────────── */

const sha = (buf) => createHash('sha256').update(buf).digest('hex').slice(0, 12);

function hashFile(rel) {
  return sha(fs.readFileSync(path.join(ROOT, rel)));
}

/** The hash of every built asset, so rule 3 can ask whether the bundle moved. */
function bundleHash() {
  const dir = path.join(ROOT, 'dist', 'assets');
  if (!fs.existsSync(dir)) return 'no-dist';
  const names = fs.readdirSync(dir).sort();
  const h = createHash('sha256');
  for (const n of names) h.update(n).update(fs.readFileSync(path.join(dir, n)));
  return h.digest('hex').slice(0, 12);
}

function run(cmd, args, opts = {}) {
  try {
    const out = execFileSync(cmd, args, {
      cwd: ROOT,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, CI: '1' },
      timeout: opts.timeout ?? 1_800_000,
      maxBuffer: 64 * 1024 * 1024,
    });
    return { ok: true, out };
  } catch (e) {
    return { ok: false, out: `${e.stdout ?? ''}${e.stderr ?? ''}` };
  }
}

const typecheck = () => run('npx', ['tsc', '--noEmit']);
const build = () => run('npx', ['vite', 'build']);
const runTest = (m) =>
  m.kind === 'browser'
    ? run('npx', ['playwright', 'test', ...m.test])
    : run('npx', ['vitest', 'run', ...m.test]);

/**
 * Apply a patch, asserting the anchor occurs EXACTLY ONCE.
 *
 * An anchor matching twice would patch the wrong site as well as the right
 * one; an anchor matching zero times is a ledger entry describing code that
 * no longer exists, which is the failure mode a prose record has permanently.
 */
function applyPatch(m) {
  const abs = path.join(ROOT, m.file);
  const before = fs.readFileSync(abs, 'utf8');
  const count = before.split(m.anchor).length - 1;
  if (count !== 1) {
    return { applied: false, reason: `anchor occurs ${count} times in ${m.file}, expected exactly 1` };
  }
  fs.writeFileSync(abs, before.replace(m.anchor, m.replacement));
  return { applied: true, before };
}

function restore(m, before) {
  fs.writeFileSync(path.join(ROOT, m.file), before);
}

/* ── the run ─────────────────────────────────────────────────────────────── */

const argv = process.argv.slice(2);
if (argv.includes('--list')) {
  for (const m of MUTATIONS) console.log(`(${m.id}) ${m.name}\n      ${m.file} — ${m.owner}`);
  process.exit(0);
}
const only = argv.filter((a) => /^\d+$/.test(a)).map(Number);
const selected = only.length ? MUTATIONS.filter((m) => only.includes(m.id)) : MUTATIONS;

// A mutation stranded in the tree by a dying session is the failure mode this
// guard exists for: refuse to start from a dirty worktree, so a restore can
// always be verified against committed bytes.
const dirty = run('git', ['status', '--porcelain', '--', 'src']).out.trim();
if (dirty) {
  console.error('REFUSING TO RUN: src/ has uncommitted changes.\n' + dirty);
  console.error('\nCommit the real work BEFORE mutating. A session that dies mid-check otherwise');
  console.error('strands an inverted condition in the tree.');
  process.exit(2);
}

console.log('baseline: typecheck + build');
const baseTc = typecheck();
if (!baseTc.ok) {
  console.error('baseline does not typecheck; fix that first\n' + baseTc.out);
  process.exit(2);
}
const baseBuild = build();
if (!baseBuild.ok) {
  console.error('baseline does not build; fix that first\n' + baseBuild.out);
  process.exit(2);
}
const baseBundle = bundleHash();
console.log(`baseline bundle ${baseBundle}\n`);

const results = [];
for (const m of selected) {
  console.log(`\n── (${m.id}) ${m.name} ──`);
  const srcBefore = hashFile(m.file);

  // RULE 1: the owning test must pass UNMUTATED, in this same run. Without
  // this a mutation "kill" could be a test that was already failing.
  process.stdout.write('  rule 1 — owning test passes unmutated ... ');
  const clean = runTest(m);
  console.log(clean.ok ? 'PASS' : 'FAIL');
  if (!clean.ok) {
    results.push({ m, verdict: 'INVALID — owning test already failing', srcBefore });
    continue;
  }

  // RULE 2: the patch changes the file.
  const patch = applyPatch(m);
  if (!patch.applied) {
    console.log(`  rule 2 — ${patch.reason}`);
    results.push({ m, verdict: `INVALID — ${patch.reason}`, srcBefore });
    continue;
  }
  const srcAfter = hashFile(m.file);
  const changed = srcAfter !== srcBefore;
  console.log(`  rule 2 — file changed: ${changed} (${srcBefore} -> ${srcAfter})`);

  let verdict;
  let bundleAfter = '';
  try {
    // RULE 4: it must compile. A patch that does not is DOES NOT BUILD and is
    // never a kill.
    const tc = typecheck();
    if (!tc.ok) {
      console.log('  rule 4 — DOES NOT BUILD (tsc)');
      verdict = 'DOES NOT BUILD';
    } else {
      const b = build();
      if (!b.ok) {
        console.log('  rule 4 — DOES NOT BUILD (vite)');
        verdict = 'DOES NOT BUILD';
      } else {
        bundleAfter = bundleHash();
        // RULE 3: the run must serve the mutated code.
        const served =
          m.kind === 'browser' ? bundleAfter !== baseBundle : changed;
        console.log(
          `  rule 3 — served the mutation: ${served}` +
            (m.kind === 'browser' ? ` (bundle ${baseBundle} -> ${bundleAfter})` : ' (source hash moved)'),
        );
        if (!served) {
          verdict = 'INVALID — the run did not serve the mutated code';
        } else {
          process.stdout.write('  owning test under mutation ... ');
          const mutated = runTest(m);
          console.log(mutated.ok ? 'STILL PASSES' : 'FAILS');
          verdict = mutated.ok ? 'SURVIVED' : 'KILLED';
        }
      }
    }
  } finally {
    // A surgical revert of the one string, never `git checkout --`: that file
    // may also hold real work.
    restore(m, patch.before);
    const srcRestored = hashFile(m.file);
    if (srcRestored !== srcBefore) {
      console.error(`  RESTORE FAILED for ${m.file} — ${srcBefore} != ${srcRestored}`);
      process.exitCode = 3;
    } else {
      console.log(`  restored (${srcRestored})`);
    }
  }
  console.log(`  => ${verdict}`);
  results.push({ m, verdict, srcBefore, srcAfter, bundleAfter });
}

// Put the tree back the way it was found, bundle included.
build();
const finalBundle = bundleHash();
console.log(`\nfinal bundle ${finalBundle} (baseline ${baseBundle}) — ${finalBundle === baseBundle ? 'restored' : 'DIFFERS'}`);

/* ── the ledger, written by the run ──────────────────────────────────────── */

const stamp = new Date().toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
const rows = results
  .map(
    (r) =>
      `| ${r.m.id} | ${r.m.name} | \`${r.m.file}\` | ${r.m.owner} | **${r.verdict}** |`,
  )
  .join('\n');

const detail = results
  .map((r) => {
    const q = (s) => s.split('\n').map((l) => `  ${l}`).join('\n');
    return `### (${r.m.id}) ${r.m.name}

**Verdict: ${r.verdict}**

${r.m.why}

Patch — \`${r.m.file}\`, anchor must occur exactly once:

\`\`\`diff
${q(r.m.anchor).split('\n').map((l) => `-${l.slice(2)}`).join('\n')}
${q(r.m.replacement).split('\n').map((l) => `+${l.slice(2)}`).join('\n')}
\`\`\`

Owning test: ${r.m.owner}

Observed in this run: source \`${r.srcBefore}\` → \`${r.srcAfter ?? '(not applied)'}\`${
      r.bundleAfter ? `, bundle \`${baseBundle}\` → \`${r.bundleAfter}\`` : ''
    }.
`;
  })
  .join('\n');

const killed = results.filter((r) => r.verdict === 'KILLED').length;
const ledger = `# Mutation ledger

Written by \`scripts/mutate.mjs\`. **Every observed value here is produced by the
run, never typed.** Re-running the script rewrites this file; a hand-edit is a
second, unenforceable copy of an answer the script already holds.

Run: ${stamp}
Mutations: ${results.length} · killed: ${killed} · survived: ${
  results.filter((r) => r.verdict === 'SURVIVED').length
} · other: ${results.filter((r) => !['KILLED', 'SURVIVED'].includes(r.verdict)).length}

A kill requires all four rules of template §4.1c, and the script enforces each:
the owning test passed unmutated in the same run; the patch changed the file;
the run served the mutated code (a browser mutation must move the built
bundle's hash, a unit mutation the source file's); and a patch that does not
compile is DOES NOT BUILD, never a kill.

| # | Mutation | File | Owning test | Verdict |
|---|---|---|---|---|
${rows}

---

${detail}
`;

fs.mkdirSync(path.dirname(LEDGER), { recursive: true });
fs.writeFileSync(LEDGER, ledger);
console.log(`\nledger written: ${path.relative(ROOT, LEDGER)}`);
console.log(`${killed}/${results.length} killed`);
if (results.some((r) => r.verdict !== 'KILLED')) process.exitCode = 1;
