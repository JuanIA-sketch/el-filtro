import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import {
  hasKnownAlternative,
  deprecatedFromPackument,
  directDependencies,
  buildDeprecatedFinding,
} from '../src/audit/deprecated.js';

function loadFixture(name: string): unknown {
  return JSON.parse(readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8'));
}

describe('hasKnownAlternative', () => {
  // Mensajes REALES capturados del registro de npm.
  it('reconoce "Use X instead" como alternativa conocida', () => {
    expect(hasKnownAlternative('Use uuid module instead')).toBe(true);
  });

  it('reconoce "we recommend using X now"', () => {
    expect(
      hasKnownAlternative(
        '🙌  Thanks for using Babel: we recommend using babel-preset-env now: please read https://babeljs.io/env to update!',
      ),
    ).toBe(true);
  });

  it('NO ve alternativa cuando el mensaje solo enlaza a un issue', () => {
    expect(
      hasKnownAlternative('request has been deprecated, see https://github.com/request/request/issues/3142'),
    ).toBe(false);
  });

  it('no se confunde con "use" suelto sin paquete detrás', () => {
    expect(hasKnownAlternative('This package is no longer in use.')).toBe(false);
  });

  it('reconoce otras formas comunes de nombrar reemplazo', () => {
    expect(hasKnownAlternative('replaced by fast-glob')).toBe(true);
    expect(hasKnownAlternative('please migrate to @scope/nuevo')).toBe(true);
    expect(hasKnownAlternative('superseded by @scope/otro')).toBe(true);
    expect(hasKnownAlternative('deprecated in favor of vite')).toBe(true);
  });
});

describe('hasKnownAlternative — se equivoca SIEMPRE hacia 🔴, nunca hacia 🟡', () => {
  /**
   * El mensaje de deprecación es texto libre. Si no reconocemos el patrón, el hallazgo
   * debe quedar 🔴 (más urgente de lo necesario). El error inaceptable es el contrario:
   * decir que hay salida cuando no la hay. Estas frases contienen "use"/"using" en
   * contexto NEGATIVO o de advertencia — ninguna ofrece reemplazo.
   */
  const sinAlternativa = [
    'Do not use this package',
    'Please do not use this in production',
    "don't use this anymore",
    'This package is no longer in use by anyone',
    'use at your own risk, unmaintained',
    'deprecated, using it is unsafe',
    'never use this in new projects',
    'avoid using this package',
  ];

  for (const msg of sinAlternativa) {
    it(`no ve alternativa en: ${JSON.stringify(msg)}`, () => {
      expect(hasKnownAlternative(msg)).toBe(false);
    });
  }

  it('un mensaje vacío o raro tampoco cuenta como alternativa', () => {
    expect(hasKnownAlternative('')).toBe(false);
    expect(hasKnownAlternative('deprecated')).toBe(false);
    expect(hasKnownAlternative('⚠️')).toBe(false);
  });

  it('ante la duda, buildDeprecatedFinding manda el hallazgo a 🔴', () => {
    const f = buildDeprecatedFinding('x', '1.0.0', 'Do not use this package');
    expect(f.bucket).toBe('fix-now');
    expect(f.fixAvailable).toBe(false);
  });
});

describe('deprecatedFromPackument', () => {
  it('devuelve el mensaje de la versión instalada', () => {
    expect(deprecatedFromPackument(loadFixture('packument-request.json'), '2.88.0')).toMatch(
      /has been deprecated/,
    );
  });

  it('devuelve null si esa versión no está marcada', () => {
    expect(deprecatedFromPackument(loadFixture('packument-lodash.json'), '4.17.11')).toBeNull();
  });

  it('devuelve null si la versión no existe en el packument', () => {
    expect(deprecatedFromPackument(loadFixture('packument-request.json'), '9.9.9')).toBeNull();
  });

  it('tolera payloads inválidos sin lanzar', () => {
    expect(deprecatedFromPackument(null, '1.0.0')).toBeNull();
    expect(deprecatedFromPackument({}, '1.0.0')).toBeNull();
    expect(deprecatedFromPackument({ versions: 'roto' }, '1.0.0')).toBeNull();
  });
});

describe('directDependencies', () => {
  it('reúne dependencies y devDependencies (lo que de verdad puedes reemplazar)', () => {
    const pkg = {
      dependencies: { request: '^2.88.0', lodash: '^4.17.11' },
      devDependencies: { vitest: '^2.1.0' },
    };
    expect(directDependencies(pkg).sort()).toEqual(['lodash', 'request', 'vitest']);
  });

  it('sin dependencias devuelve lista vacía y no lanza', () => {
    expect(directDependencies({})).toEqual([]);
    expect(directDependencies(null)).toEqual([]);
    expect(directDependencies({ dependencies: 'roto' })).toEqual([]);
  });

  it('no duplica un paquete que esté en ambas listas', () => {
    const pkg = { dependencies: { tar: '^6' }, devDependencies: { tar: '^6' } };
    expect(directDependencies(pkg)).toEqual(['tar']);
  });
});

describe('buildDeprecatedFinding', () => {
  it('sin alternativa conocida va a 🔴 (regla del brief §6.5)', () => {
    const f = buildDeprecatedFinding(
      'request',
      '2.88.0',
      'request has been deprecated, see https://github.com/request/request/issues/3142',
    );
    expect(f.type).toBe('deprecated');
    expect(f.bucket).toBe('fix-now');
    expect(f.severity).toBeNull();
    expect(f.installedVersions).toEqual(['2.88.0']);
  });

  it('con alternativa conocida va a 🟡: hay a dónde migrar, no es una emergencia', () => {
    const f = buildDeprecatedFinding('node-uuid', '1.4.8', 'Use uuid module instead');
    expect(f.bucket).toBe('can-wait');
  });

  it('explica en lenguaje simple que el paquete está abandonado, sin jerga', () => {
    const f = buildDeprecatedFinding('request', '2.88.0', 'request has been deprecated');
    expect(f.explanation).toMatch(/abandon|ya no|mantiene/i);
    expect(f.explanation).not.toMatch(/CVE|GHSA/);
  });

  it('conserva el mensaje original del registro para El Repuesto', () => {
    const f = buildDeprecatedFinding('node-uuid', '1.4.8', 'Use uuid module instead');
    expect(f.advisory?.titles).toContain('Use uuid module instead');
  });

  it('un hallazgo deprecated no lleva severidad (no es una vulnerabilidad)', () => {
    const f = buildDeprecatedFinding('request', '2.88.0', 'deprecated');
    expect(f.severity).toBeNull();
    expect(f.unresolvedAdvisories).toBe(0);
  });
});
