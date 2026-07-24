import { describe, it, expect, afterAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { makeTempDir, makeDir, cleanupTempDirs } from './helpers/tmp.js';

afterAll(cleanupTempDirs);

const projectRoot = fileURLToPath(new URL('..', import.meta.url));

/** Corre el CLI real vía tsx (sin build previo). Devuelve stdout + exit status. */
function runCli(args: string[]): { stdout: string; status: number } {
  try {
    const stdout = execFileSync(process.execPath, ['--import', 'tsx', 'src/cli.ts', ...args], {
      cwd: projectRoot,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    return { stdout, status: 0 };
  } catch (e) {
    const err = e as { stdout?: string; status?: number };
    return { stdout: String(err.stdout ?? ''), status: err.status ?? 1 };
  }
}

function makeRepo(root: string, name: string, files: Record<string, string>): void {
  const dir = makeDir(root, name);
  mkdirSync(join(dir, '.git'), { recursive: true });
  for (const [rel, content] of Object.entries(files)) writeFileSync(join(dir, rel), content);
}

describe('el-filtro CLI (e2e, offline)', () => {
  it('escanea una carpeta y emite JSON estable (repo pip auditado o no-audit, none n/a)', () => {
    const root = makeTempDir();
    makeRepo(root, 'un-pip', { 'requirements.txt': 'flask\n' });
    makeRepo(root, 'un-none', { 'README.md': 'hola' });

    const { stdout, status } = runCli(['--path', root, '--json', '--no-write']);
    expect(status).toBe(0);

    const report = JSON.parse(stdout);
    expect(report.tool).toBe('el-filtro');
    expect(report.schemaVersion).toBe(1);
    const byName = Object.fromEntries(report.repos.map((r: { name: string }) => [r.name, r]));
    // Etapa 2: pip ya NO queda 'pending'; se audita, o queda no-audit con razón clara.
    expect(['audited', 'no-audit']).toContain(byName['un-pip'].status);
    expect(byName['un-pip'].status).not.toBe('pending');
    expect(byName['un-none'].status).toBe('not-applicable');
  });

  it('un proyecto pip SIN .git se descubre por el fallback y no rompe si falta pip-audit', () => {
    // Caso real: agents/carousel-creator tiene requirements.txt pero no es repo git propio.
    // pip-audit no está instalado en esta máquina, así que se ejercita esa ruta de verdad.
    const root = makeTempDir({ 'requirements.txt': 'flask>=3.0.3\n' });

    const { stdout, status } = runCli(['--path', root, '--json', '--no-write']);
    expect(status).toBe(0); // no revienta

    const report = JSON.parse(stdout);
    expect(report.summary.reposScanned).toBe(1); // el fallback lo encontró
    const repo = report.repos[0];
    expect(repo.ecosystem).toBe('pip');
    // O bien se auditó (si hay pip-audit en PATH), o quedó no-audit con el comando exacto.
    expect(['audited', 'no-audit']).toContain(repo.status);
    if (repo.status === 'no-audit') {
      expect(repo.statusReason).toContain('pip install pip-audit');
    }
  });

  it('incluye unknownSeverity y secondaryEcosystems en el JSON (contrato El Repuesto)', () => {
    const root = makeTempDir();
    makeRepo(root, 'un-none', { 'README.md': 'hola' });

    const { stdout } = runCli(['--path', root, '--json', '--no-write']);
    const report = JSON.parse(stdout);
    expect(report.summary).toHaveProperty('unknownSeverity');
    expect(report.repos[0]).toHaveProperty('secondaryEcosystems');
  });

  it('sin --no-write escribe el reporte en .el-filtro/', () => {
    const root = makeTempDir();
    makeRepo(root, 'un-none', { 'README.md': 'hola' });

    const { status } = runCli(['--path', root]);
    expect(status).toBe(0);

    const dir = join(root, '.el-filtro');
    expect(existsSync(dir)).toBe(true);
    expect(readdirSync(dir).some((f) => /^report-.*\.json$/.test(f))).toBe(true);
  });
});
