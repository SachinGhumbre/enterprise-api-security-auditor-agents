/**
 * Regression test for the webpack DefinePlugin env guard.
 *
 * `process.env` is inlined as an object literal in the browser bundle, but
 * bare `process` does not exist there — so a `typeof process` check is always
 * false in the browser and silently discards every env value (login passwords
 * showed "(not set)" and every sign-in failed, no matter how often the dev
 * server was restarted). Jest runs in Node where `process` exists, so ordinary
 * component tests cannot catch this; this test scans the shipped sources for
 * the known-bad pattern instead. Tests themselves are excluded: they run in
 * Node, where referring to `process` is fine.
 */
import fs from 'fs';
import path from 'path';

const SRC_DIR = path.resolve(__dirname);
// Bare `typeof process` NOT followed by `.env`.
const BAD_PATTERN = /typeof\s+process(?!\s*\.\s*env\b)/;

function shippedSources(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...shippedSources(full));
    } else if (
      /\.(js|jsx|ts|tsx)$/.test(entry.name) &&
      !/\.test\.(js|jsx|ts|tsx)$/.test(entry.name)
    ) {
      out.push(full);
    }
  }
  return out;
}

function stripComments(text) {
  return (
    text
      // Block comments first so URLs in line comments cannot leak.
      .replace(/\/\*[\s\S]*?\*\//g, ' ')
      // Line comments (naive but safe here: truncation cannot fabricate the
      // pattern, since matching needs `typeof` and `process` on one line).
      .split('\n')
      .map((line) => line.replace(/\/\/.*$/, ''))
      .join('\n')
  );
}

test('shipped sources never guard on bare `typeof process`', () => {
  const files = shippedSources(SRC_DIR);
  // The scan must actually cover the known env readers, not pass vacuously.
  const rel = files.map((f) => path.relative(SRC_DIR, f).replace(/\\/g, '/'));
  expect(rel).toEqual(expect.arrayContaining(['api/client.js', 'components/Login.jsx']));

  const offenders = [];
  for (const file of files) {
    const code = stripComments(fs.readFileSync(file, 'utf8'));
    if (BAD_PATTERN.test(code)) {
      offenders.push(path.relative(SRC_DIR, file).replace(/\\/g, '/'));
    }
  }
  expect(
    offenders.join(', ') ||
      'ok: guard on `typeof process.env`, never on bare `typeof process`'
  ).toBe('ok: guard on `typeof process.env`, never on bare `typeof process`');
});
