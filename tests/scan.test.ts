import { describe, it, expect, afterAll, vi } from 'vitest';
import { mkdirSync, writeFileSync } from 'node:fs';
import { basename, join } from 'node:path';
import { scan } from '../src/scan.js';
import type { NpmAuditOutcome } from '../src/audit/npm.js';
import type { PipAuditOutcome } from '../src/audit/pip.js';
import type { Finding } from '../src/types.js';
import { makeTempDir, makeDir, cleanupTempDirs } from './helpers/tmp.js';

afterAll(cleanupTempDirs);

function makeRepo(root: string, name: string, files: Record<string, string>): string {
  const dir = makeDir(root, name);
  mkdirSync(join(dir, '.git'), { recursive: true });
  for (const [rel, content] of Object.entries(files)) {
    writeFileSync(join(dir, rel), content);
  }
  return dir;
}

const oneFinding: Finding = {
  type: 'vulnerability',
  package: 'lodash',
  installedVersions: ['4.17.11'],
  severity: 'critical',
  bucket: 'fix-now',
  direct: true,
  fixAvailable: true,
  explanation: 'urgente',
  advisory: { titles: ['x'], urls: ['https://x.test'], range: '<4.17.21' },
};

function buildTree() {
  const root = makeTempDir();
  makeRepo(root, 'repo-npm-a', { 'package.json': '{}' });
  makeRepo(root, 'repo-npm-b', { 'package.json': '{}' });
  makeRepo(root, 'repo-npm-c', { 'package.json': '{}' });
  makeRepo(root, 'repo-pip', { 'requirements.txt': 'flask\n' });
  makeRepo(root, 'repo-none', { 'README.md': 'hola' });
  return root;
}

const pipFinding: Finding = {
  type: 'vulnerability',
  package: 'jinja2',
  installedVersions: ['2.10'],
  severity: 'high',
  bucket: 'fix-now',
  direct: true,
  fixAvailable: true,
  explanation: 'urgente',
  advisory: { titles: ['PYSEC-2019-217'], urls: [], range: '< 2.10.1' },
};

// Fake del motor pip: por defecto audita bien; 'repo-pip-roto' lanza (aislamiento).
const fakeAuditPip = async (repoPath: string): Promise<PipAuditOutcome> => {
  if (basename(repoPath) === 'repo-pip-roto') throw new Error('pip-audit reventó');
  if (basename(repoPath) === 'repo-pip-sin') return { ok: false, reason: 'falta pip-audit. Corre: pip install pip-audit' };
  return { ok: true, findings: [pipFinding] };
};

// Fake del motor npm: a=éxito con hallazgo, b=fallo controlado, c=lanza (aislamiento).
const fakeAuditNpm = async (repoPath: string): Promise<NpmAuditOutcome> => {
  const name = basename(repoPath);
  if (name === 'repo-npm-b') return { ok: false, reason: 'sin conexión' };
  if (name === 'repo-npm-c') throw new Error('boom en npm audit');
  return { ok: true, findings: [oneFinding] };
};

describe('scan', () => {
  it('clasifica cada repo por su ecosistema y estado', async () => {
    const root = buildTree();
    const report = await scan(root, { auditNpm: fakeAuditNpm, auditPip: fakeAuditPip });
    const byName = Object.fromEntries(report.repos.map((r) => [r.name, r]));

    expect(byName['repo-npm-a'].status).toBe('audited');
    expect(byName['repo-npm-a'].findings).toHaveLength(1);
    expect(byName['repo-npm-b'].status).toBe('no-audit');
    expect(byName['repo-npm-b'].statusReason).toBe('sin conexión');
    expect(byName['repo-none'].status).toBe('not-applicable');
  });

  it('los repos pip YA se auditan (dejaron de quedar pendientes)', async () => {
    const root = buildTree();
    const report = await scan(root, { auditNpm: fakeAuditNpm, auditPip: fakeAuditPip });
    const pip = report.repos.find((r) => r.name === 'repo-pip')!;
    expect(pip.ecosystem).toBe('pip');
    expect(pip.status).toBe('audited');
    expect(pip.findings).toHaveLength(1);
    expect(pip.findings[0].package).toBe('jinja2');
    expect(report.repos.some((r) => r.status === 'pending')).toBe(false);
  });

  it('un fallo controlado de pip (falta pip-audit) queda no-audit con el comando exacto', async () => {
    const root = makeTempDir();
    makeRepo(root, 'repo-pip-sin', { 'requirements.txt': 'flask\n' });
    makeRepo(root, 'repo-npm-a', { 'package.json': '{}' });
    const report = await scan(root, { auditNpm: fakeAuditNpm, auditPip: fakeAuditPip });
    const sin = report.repos.find((r) => r.name === 'repo-pip-sin')!;
    expect(sin.status).toBe('no-audit');
    expect(sin.statusReason).toContain('pip install pip-audit');
    // el repo npm siguió auditándose
    expect(report.repos.find((r) => r.name === 'repo-npm-a')!.status).toBe('audited');
  });

  it('aísla el error de un repo pip: si el motor lanza, queda no-audit y el resto sigue', async () => {
    const root = makeTempDir();
    makeRepo(root, 'repo-pip-roto', { 'requirements.txt': 'flask\n' });
    makeRepo(root, 'repo-npm-a', { 'package.json': '{}' });
    const report = await scan(root, { auditNpm: fakeAuditNpm, auditPip: fakeAuditPip });
    const roto = report.repos.find((r) => r.name === 'repo-pip-roto')!;
    expect(roto.status).toBe('no-audit');
    expect(roto.statusReason).toContain('pip-audit reventó');
    expect(report.summary.reposAudited).toBe(1);
  });

  it('registra el ecosistema secundario cuando conviven npm y pip (npm gana, no en silencio)', async () => {
    const root = makeTempDir();
    makeRepo(root, 'repo-poliglota', { 'package.json': '{}', 'requirements.txt': 'flask\n' });
    const report = await scan(root, { auditNpm: fakeAuditNpm, auditPip: fakeAuditPip });
    const p = report.repos[0];
    expect(p.ecosystem).toBe('npm');
    expect(p.secondaryEcosystems).toEqual(['pip']);
  });

  it('aísla el error de un repo: si el motor lanza, ese repo queda no-audit y el resto sigue', async () => {
    const root = buildTree();
    const report = await scan(root, { auditNpm: fakeAuditNpm, auditPip: fakeAuditPip });
    const c = report.repos.find((r) => r.name === 'repo-npm-c')!;
    expect(c.status).toBe('no-audit');
    expect(c.statusReason).toContain('boom en npm audit');
    // el resto sí se procesó: npm-a + pip
    expect(report.summary.reposScanned).toBe(5);
    expect(report.summary.reposAudited).toBe(2);
  });

  it('reporta progreso "repo N/M" por cada repo', async () => {
    const root = buildTree();
    const onProgress = vi.fn();
    await scan(root, { auditNpm: fakeAuditNpm, auditPip: fakeAuditPip, onProgress });
    expect(onProgress).toHaveBeenCalledTimes(5);
    const calls = onProgress.mock.calls;
    expect(calls[0][1]).toBe(5); // total
    expect(calls.map((c) => c[0])).toEqual([1, 2, 3, 4, 5]); // current
  });

  it('agrega los hallazgos de AMBOS ecosistemas en el resumen', async () => {
    const root = buildTree();
    const report = await scan(root, { auditNpm: fakeAuditNpm, auditPip: fakeAuditPip });
    expect(report.summary.findings.total).toBe(2); // 1 npm + 1 pip
    expect(report.summary.findings.fixNow).toBe(2);
    expect(report.summary.bySeverity.critical).toBe(1); // npm
    expect(report.summary.bySeverity.high).toBe(1); // pip
    expect(report.summary.unknownSeverity).toBe(0);
  });
});
