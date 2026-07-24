import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import {
  parseNpmAudit,
  installedVersionsFromLockfile,
  enrichFindings,
  deprecatedFindingsFor,
} from '../src/audit/npm.js';
import type { Finding } from '../src/types.js';

function loadFixture(name: string): unknown {
  return JSON.parse(readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8'));
}

describe('parseNpmAudit', () => {
  const findings = parseNpmAudit(loadFixture('npm-audit-vuln.json'));
  const byName = Object.fromEntries(findings.map((f) => [f.package, f]));

  it('extrae un hallazgo por paquete vulnerable', () => {
    expect(findings.map((f) => f.package).sort()).toEqual(['axios', 'lodash', 'minimist']);
  });

  it('lee la severidad agregada de cada paquete', () => {
    expect(byName.axios.severity).toBe('high');
    expect(byName.lodash.severity).toBe('critical');
    expect(byName.minimist.severity).toBe('critical');
  });

  it('normaliza direct y fixAvailable a booleanos (fixAvailable objeto → true)', () => {
    expect(byName.axios.direct).toBe(true);
    expect(byName.axios.fixAvailable).toBe(true);
  });

  it('reúne títulos y urls desde los objetos de `via`, ignorando las entradas string', () => {
    expect(byName.lodash.titles.some((t: string) => /lodash/i.test(t))).toBe(true);
    expect(byName.lodash.urls.length).toBeGreaterThan(0);
    expect(byName.lodash.urls.every((u: string) => u.startsWith('https://'))).toBe(true);
  });

  it('conserva el rango vulnerable del paquete', () => {
    expect(byName.minimist.range).toBe('1.0.0 - 1.2.5');
  });

  it('conserva los nodes (paths) para mapear versiones desde el lockfile', () => {
    expect(byName.axios.nodes).toContain('node_modules/axios');
  });

  it('un audit limpio (0 vulns) devuelve arreglo vacío', () => {
    expect(parseNpmAudit(loadFixture('npm-audit-clean.json'))).toEqual([]);
  });

  it('un audit con error o roto lanza, para que el orquestador lo marque no-audit', () => {
    expect(() => parseNpmAudit(loadFixture('npm-audit-error.json'))).toThrow();
    expect(() => parseNpmAudit({})).toThrow();
    expect(() => parseNpmAudit(null)).toThrow();
  });
});

describe('deprecatedFindingsFor — hallazgos de paquetes abandonados en un repo npm', () => {
  const packageJson = {
    dependencies: { request: '^2.88.0', lodash: '^4.17.11' },
    devDependencies: { 'node-uuid': '^1.4.8' },
  };
  const lock = {
    lockfileVersion: 3,
    packages: {
      'node_modules/request': { version: '2.88.0' },
      'node_modules/lodash': { version: '4.17.11' },
      'node_modules/node-uuid': { version: '1.4.8' },
    },
  };
  // Resolvedor fake: solo request y node-uuid están deprecated.
  const fakeResolve = async (name: string) => {
    if (name === 'request') return 'request has been deprecated, see https://x.test/issues/1';
    if (name === 'node-uuid') return 'Use uuid module instead';
    return null;
  };

  it('reporta solo las dependencias directas marcadas como deprecated', async () => {
    const findings = await deprecatedFindingsFor(packageJson, lock, fakeResolve);
    expect(findings.map((f) => f.package).sort()).toEqual(['node-uuid', 'request']);
    expect(findings.every((f) => f.type === 'deprecated')).toBe(true);
  });

  it('aplica la regla de bucket según haya o no alternativa', async () => {
    const findings = await deprecatedFindingsFor(packageJson, lock, fakeResolve);
    const byName = Object.fromEntries(findings.map((f) => [f.package, f]));
    expect(byName.request.bucket).toBe('fix-now'); // sin alternativa
    expect(byName['node-uuid'].bucket).toBe('can-wait'); // "Use uuid module instead"
  });

  it('usa la versión instalada del lockfile', async () => {
    const findings = await deprecatedFindingsFor(packageJson, lock, fakeResolve);
    const req = findings.find((f) => f.package === 'request')!;
    expect(req.installedVersions).toEqual(['2.88.0']);
  });

  it('sin deprecaciones no inventa hallazgos', async () => {
    const findings = await deprecatedFindingsFor(packageJson, lock, async () => null);
    expect(findings).toEqual([]);
  });

  it('un paquete ausente del lockfile no se reporta (no se puede afirmar la versión)', async () => {
    const findings = await deprecatedFindingsFor(
      { dependencies: { fantasma: '^1.0.0' } },
      lock,
      async () => 'deprecated',
    );
    expect(findings).toEqual([]);
  });

  it('si el resolvedor falla (sin red) no rompe: devuelve lo que pudo', async () => {
    const findings = await deprecatedFindingsFor(packageJson, lock, async () => {
      throw new Error('sin red');
    });
    expect(findings).toEqual([]);
  });
});

describe('installedVersionsFromLockfile', () => {
  const lock = loadFixture('package-lock.real.json');

  it('resuelve la versión instalada de un node path', () => {
    expect(installedVersionsFromLockfile(lock, ['node_modules/lodash'])).toEqual(['4.17.11']);
  });

  it('devuelve versiones únicas cuando un paquete está duplicado en dos versiones', () => {
    const dupLock = {
      lockfileVersion: 3,
      packages: {
        'node_modules/foo': { version: '1.0.0' },
        'node_modules/bar/node_modules/foo': { version: '2.0.0' },
      },
    };
    const versions = installedVersionsFromLockfile(dupLock, [
      'node_modules/foo',
      'node_modules/bar/node_modules/foo',
    ]);
    expect(versions.sort()).toEqual(['1.0.0', '2.0.0']);
  });

  it('ignora node paths que no están en el lockfile', () => {
    expect(installedVersionsFromLockfile(lock, ['node_modules/no-existe'])).toEqual([]);
  });
});

describe('enrichFindings', () => {
  const findings = enrichFindings(
    loadFixture('npm-audit-vuln.json'),
    loadFixture('package-lock.real.json'),
  );
  const byName = Object.fromEntries(findings.map((f: Finding) => [f.package, f]));

  it('adjunta a cada paquete la versión que está instalada hoy (del lockfile)', () => {
    expect(byName.axios.installedVersions).toEqual(['0.21.1']);
    expect(byName.lodash.installedVersions).toEqual(['4.17.11']);
    expect(byName.minimist.installedVersions).toEqual(['1.2.0']);
  });

  it('clasifica critical/high en el bucket fix-now con explicación en lenguaje simple', () => {
    expect(byName.lodash.severity).toBe('critical');
    expect(byName.lodash.bucket).toBe('fix-now');
    expect(byName.lodash.explanation).toMatch(/vulnerabilidad/i);
    expect(byName.lodash.explanation).not.toMatch(/CVE|GHSA/);
  });

  it('produce Findings con la forma completa del contrato', () => {
    const f = byName.axios;
    expect(f.type).toBe('vulnerability');
    expect(f.advisory?.urls.length).toBeGreaterThan(0);
    expect(f.advisory?.range).toBeTruthy();
    expect(typeof f.direct).toBe('boolean');
    expect(typeof f.fixAvailable).toBe('boolean');
  });
});
