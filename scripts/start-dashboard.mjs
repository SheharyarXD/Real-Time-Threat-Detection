/** Local development launcher. No backend, agent or mitigation service is started. */
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { spawn, spawnSync } from 'node:child_process';
import { createServer } from 'node:net';

const root = fileURLToPath(new URL('../', import.meta.url));
const requiredFiles = ['next/dist/bin/next', 'react/package.json', 'react-dom/package.json', 'typescript/bin/tsc'];
const stampPath = (directory) => path.join(directory, 'node_modules', '.sentinel-install.json');

export function nodeSupported(version) {
  const [major, minor] = version.replace(/^v/, '').split('.').map(Number);
  return major > 22 || (major === 22 && minor >= 13);
}

export function dependencyFingerprint(directory, runtime = process) {
  const hash = createHash('sha256');
  for (const filename of ['package.json', 'pnpm-lock.yaml', 'pnpm-workspace.yaml', '.npmrc']) {
    const file = path.join(directory, filename);
    hash.update(filename);
    hash.update(existsSync(file) ? readFileSync(file) : '<missing>');
  }
  hash.update(`${runtime.platform}/${runtime.arch}/${runtime.versions.node}`);
  return hash.digest('hex');
}

export function dependenciesNeeded(directory, runtime = process) {
  if (requiredFiles.some(file => !existsSync(path.join(directory, 'node_modules', file)))) return true;
  try {
    return JSON.parse(readFileSync(stampPath(directory), 'utf8')).fingerprint !== dependencyFingerprint(directory, runtime);
  } catch { return true; }
}

export function pnpmVersion(directory) {
  const manifest = JSON.parse(readFileSync(path.join(directory, 'package.json'), 'utf8'));
  const match = /^pnpm@(\d+\.\d+\.\d+)$/.exec(manifest.packageManager ?? '');
  if (!match) throw new Error('package.json must declare an exact pnpm version.');
  return match[1];
}

export function installCommand(directory, platform = process.platform) {
  const version = pnpmVersion(directory);
  const args = ['exec', '--yes', `--package=pnpm@${version}`, '--', 'pnpm', 'install', '--frozen-lockfile'];
  // cmd.exe is required for npm.cmd on Windows. Every argument here is fixed or validated above.
  return platform === 'win32'
    ? { command: 'cmd.exe', args: ['/d', '/s', '/c', `npm.cmd ${args.join(' ')}`] }
    : { command: 'npm', args };
}

export function ensureDependencies(directory, { force = false, runtime = process, run = spawnSync, log = console.log } = {}) {
  if (!force && !dependenciesNeeded(directory, runtime)) {
    log('[OK] Dependencies are already installed and current.');
    return false;
  }
  log('[SETUP] Installing pinned dependencies. The first run needs an internet connection.');
  const command = installCommand(directory, runtime.platform);
  // A failed repair must not leave a previously valid stamp behind.
  rmSync(stampPath(directory), { force: true });
  const result = run(command.command, command.args, { cwd: directory, stdio: 'inherit', env: process.env });
  if (result.error) throw new Error(`Could not start npm: ${result.error.message}`);
  if (result.status !== 0) throw new Error(`Dependency installation failed (exit ${result.status ?? 'unknown'}). Check the output above, your internet connection, and available disk space.`);
  if (requiredFiles.some(file => !existsSync(path.join(directory, 'node_modules', file)))) {
    throw new Error('Installation finished but required packages are missing. Run start-dashboard.bat --reinstall.');
  }
  mkdirSync(path.dirname(stampPath(directory)), { recursive: true });
  writeFileSync(stampPath(directory), JSON.stringify({ fingerprint: dependencyFingerprint(directory, runtime), installedAt: new Date().toISOString() }, null, 2) + '\n');
  log('[OK] Dependency installation completed.');
  return true;
}

export function parseOptions(args) {
  const options = { reinstall: false, open: true, setupOnly: false, check: false, port: 3000 };
  for (const argument of args) {
    if (argument === '--reinstall') options.reinstall = true;
    else if (argument === '--no-open') options.open = false;
    else if (argument === '--setup-only') options.setupOnly = true;
    else if (argument === '--check') options.check = true;
    else if (/^--port=\d+$/.test(argument)) options.port = Number(argument.slice(7));
    else throw new Error(`Unknown option: ${argument}. Use --reinstall, --no-open, --setup-only, --check, or --port=3001.`);
  }
  if (!Number.isInteger(options.port) || options.port < 1024 || options.port > 65535) throw new Error('Choose a local port between 1024 and 65535.');
  return options;
}

export function portAvailable(port) {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => server.close(() => resolve(true)));
  });
}

function openBrowser(url) {
  const command = process.platform === 'win32'
    ? ['rundll32.exe', ['url.dll,FileProtocolHandler', url]]
    : process.platform === 'darwin' ? ['open', [url]] : ['xdg-open', [url]];
  const child = spawn(command[0], command[1], { detached: true, stdio: 'ignore' });
  child.on('error', () => console.log(`[INFO] Open ${url} manually in your browser.`));
  child.unref();
}

async function waitAndOpen(url, signal) {
  const deadline = Date.now() + 120_000;
  while (!signal.aborted && Date.now() < deadline) {
    try {
      const result = await fetch(url, { signal: AbortSignal.any([signal, AbortSignal.timeout(3000)]) });
      await result.body?.cancel();
      if (result.ok && !signal.aborted) { openBrowser(url); return; }
    } catch { /* Next may still be compiling its first page. */ }
    await new Promise(resolve => {
      if (signal.aborted) return resolve();
      const done = () => { clearTimeout(timer); signal.removeEventListener('abort', done); resolve(); };
      const timer = setTimeout(done, 500);
      signal.addEventListener('abort', done, { once: true });
    });
  }
  if (!signal.aborted) console.log(`[INFO] The browser did not open automatically. Check the server output, then open ${url}.`);
}

export async function main(args = process.argv.slice(2)) {
  if (!nodeSupported(process.versions.node)) throw new Error('Node.js 22.13 or later is required. Install Node.js LTS from https://nodejs.org/.');
  const options = parseOptions(args);
  if (!existsSync(path.join(root, 'pnpm-lock.yaml'))) throw new Error('The project lockfile is missing. Download/extract the complete repository before running this launcher.');
  const url = `http://127.0.0.1:${options.port}`;
  if (options.check) {
    console.log(JSON.stringify({ node: process.versions.node, platform: process.platform, root, pnpm: pnpmVersion(root), installNeeded: dependenciesNeeded(root), install: installCommand(root), url, runtime: 'standard Next.js' }, null, 2));
    return 0;
  }
  if (!options.setupOnly) {
    try { await portAvailable(options.port); }
    catch { throw new Error(`Port ${options.port} is already in use. Close the existing server or run start-dashboard.bat --port=3001.`); }
  }
  ensureDependencies(root, { force: options.reinstall });
  if (options.setupOnly) return 0;
  console.log(`\n[START] Sentinel dashboard: ${url}`);
  console.log('[INFO] This is the Milestone 1 frontend with simulated data.');
  console.log('[INFO] Keep this window open. Press Ctrl+C to stop the dashboard.\n');
  const child = spawn(process.execPath, [path.join(root, 'node_modules', 'next', 'dist', 'bin', 'next'), 'dev', '--hostname', '127.0.0.1', '--port', String(options.port)], { cwd: root, stdio: 'inherit', env: { ...process.env, NEXT_TELEMETRY_DISABLED: '1' } });
  const controller = new AbortController();
  const forwardInterrupt = () => child.kill('SIGINT');
  process.on('SIGINT', forwardInterrupt);
  if (options.open) void waitAndOpen(url, controller.signal).catch(error => console.log(`[INFO] Open ${url} manually: ${error.message}`));
  return new Promise((resolve, reject) => {
    const cleanup = () => { controller.abort(); process.removeListener('SIGINT', forwardInterrupt); };
    child.once('error', error => { cleanup(); reject(new Error(`Could not start Next.js: ${error.message}`)); });
    child.once('exit', (code, signal) => { cleanup(); resolve(signal === 'SIGINT' ? 0 : (code ?? 1)); });
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().then(code => { process.exitCode = code; }).catch(error => {
    console.error(`\n[ERROR] ${error.message}\n`);
    process.exitCode = 1;
  });
}
