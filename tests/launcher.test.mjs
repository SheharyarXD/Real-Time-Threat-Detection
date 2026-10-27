import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createServer } from 'node:net';
import { nodeSupported, dependencyFingerprint, dependenciesNeeded, installCommand, ensureDependencies, parseOptions, portAvailable } from '../scripts/start-dashboard.mjs';

function fixture() {
  const directory = mkdtempSync(path.join(tmpdir(), 'sentinel launcher '));
  writeFileSync(path.join(directory, 'package.json'), JSON.stringify({ packageManager: 'pnpm@11.25.0' }));
  writeFileSync(path.join(directory, 'pnpm-lock.yaml'), 'lockfileVersion: 9.0\n');
  return directory;
}
function createPackages(directory) {
  for (const name of ['next/dist/bin/next','react/package.json','react-dom/package.json','typescript/bin/tsc']) {
    const file = path.join(directory, 'node_modules', name);
    mkdirSync(path.dirname(file), { recursive: true });
    writeFileSync(file, '{}');
  }
}
const quiet = () => {};
test('launcher enforces the supported Node baseline', () => {
  for (const version of ['18.20.0','20.19.0','22.12.9']) assert.equal(nodeSupported(version), false);
  for (const version of ['22.13.0','v22.20.0','24.1.0']) assert.equal(nodeSupported(version), true);
});
test('missing dependencies install once; unchanged requirements skip installation', () => {
  const directory = fixture(); let calls = 0;
  try {
    assert.equal(dependenciesNeeded(directory), true);
    const run = () => { calls++; createPackages(directory); return { status: 0 }; };
    assert.equal(ensureDependencies(directory, { run, log: quiet }), true);
    assert.equal(dependenciesNeeded(directory), false);
    assert.equal(ensureDependencies(directory, { run, log: quiet }), false);
    assert.equal(calls, 1);
    writeFileSync(path.join(directory, 'pnpm-lock.yaml'), 'lockfileVersion: 9.0\n# updated requirements\n');
    assert.equal(dependenciesNeeded(directory), true);
    ensureDependencies(directory, { run, log: quiet });
    assert.equal(calls, 2);
    ensureDependencies(directory, { force: true, run, log: quiet });
    assert.equal(calls, 3);
    rmSync(path.join(directory, 'node_modules/react/package.json'));
    assert.equal(dependenciesNeeded(directory), true);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
test('failed and incomplete installs never mark the setup successful', () => {
  const directory = fixture();
  try {
    assert.throws(() => ensureDependencies(directory, { run: () => ({ status: 1 }), log: quiet }), /installation failed/);
    assert.throws(() => ensureDependencies(directory, { run: () => ({ status: 0 }), log: quiet }), /packages are missing/);
    assert.equal(dependenciesNeeded(directory), true);
    ensureDependencies(directory, { run: () => { createPackages(directory); return { status: 0 }; }, log: quiet });
    assert.equal(dependenciesNeeded(directory), false);
    assert.throws(() => ensureDependencies(directory, { force: true, run: () => ({ status: 1 }), log: quiet }), /installation failed/);
    assert.equal(dependenciesNeeded(directory), true);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
test('platform, architecture, Node and package-policy changes invalidate the stamp', () => {
  const directory = fixture();
  try {
    const runtime = { platform: 'win32', arch: 'x64', versions: { node: '22.13.0' } };
    const original = dependencyFingerprint(directory, runtime);
    assert.notEqual(dependencyFingerprint(directory, { ...runtime, arch: 'arm64' }), original);
    assert.notEqual(dependencyFingerprint(directory, { ...runtime, versions: { node: '24.1.0' } }), original);
    writeFileSync(path.join(directory, '.npmrc'), 'registry=https://registry.npmjs.org/\n');
    assert.notEqual(dependencyFingerprint(directory, runtime), original);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
test('Windows invokes npm.cmd safely with the exact pinned pnpm version', () => {
  const directory = fixture();
  try {
    assert.deepEqual(installCommand(directory, 'win32'), { command: 'cmd.exe', args: ['/d','/s','/c','npm.cmd exec --yes --package=pnpm@11.25.0 -- pnpm install --frozen-lockfile'] });
    writeFileSync(path.join(directory, 'package.json'), JSON.stringify({ packageManager: 'pnpm@11.25.0 & echo unsafe' }));
    assert.throws(() => installCommand(directory, 'win32'), /exact pnpm version/);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
test('launcher supports reinstall and setup-only options and validates ports', () => {
  assert.deepEqual(parseOptions(['--reinstall','--no-open','--setup-only','--port=3001']), { reinstall: true, open: false, setupOnly: true, check: false, port: 3001 });
  for (const args of [['--port=0'],['--port=65536'],['--port=abc'],['--unexpected']]) assert.throws(() => parseOptions(args));
});
test('occupied local ports are detected without stopping another service', async () => {
  const server = createServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  try { await assert.rejects(portAvailable(port), error => error.code === 'EADDRINUSE'); }
  finally { await new Promise(resolve => server.close(resolve)); }
  assert.equal(await portAvailable(port), true);
});
test('batch entrypoint has Windows line endings and keeps setup errors visible', () => {
  const bytes = readFileSync(new URL('../start-dashboard.bat', import.meta.url));
  const content = bytes.toString('ascii');
  assert.ok(content.startsWith('@echo off\r\n'));
  assert.equal(content.replaceAll('\r\n','').includes('\n'), false);
  assert.match(content, /DisableDelayedExpansion/);
  assert.match(content, /pushd "%~dp0"/);
  assert.match(content, /node "scripts\\start-dashboard\.mjs" %\*/);
  assert.match(content, /winget\.exe install --id OpenJS\.NodeJS\.LTS --exact --source winget/);
  assert.match(content, /:failure\r\npause/);
});
