import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { normalizeOsvSeverity, severityIndexFromOsv } from '../src/osv.js';

function loadFixture(name: string): unknown {
  return JSON.parse(readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8'));
}

describe('normalizeOsvSeverity', () => {
  it('convierte las etiquetas de OSV al vocabulario interno (mismo que npm)', () => {
    expect(normalizeOsvSeverity('CRITICAL')).toBe('critical');
    expect(normalizeOsvSeverity('HIGH')).toBe('high');
    expect(normalizeOsvSeverity('MODERATE')).toBe('moderate');
    expect(normalizeOsvSeverity('LOW')).toBe('low');
  });

  it('acepta minúsculas y espacios', () => {
    expect(normalizeOsvSeverity('critical')).toBe('critical');
    expect(normalizeOsvSeverity('  High  ')).toBe('high');
  });

  it('devuelve null para ausente o desconocido, en vez de inventar severidad', () => {
    expect(normalizeOsvSeverity(null)).toBeNull();
    expect(normalizeOsvSeverity(undefined)).toBeNull();
    expect(normalizeOsvSeverity('')).toBeNull();
    expect(normalizeOsvSeverity('SEVERIDAD_RARA')).toBeNull();
    expect(normalizeOsvSeverity(42 as unknown as string)).toBeNull();
  });
});

describe('severityIndexFromOsv', () => {
  // Fixture real: POST /v1/query para jinja2 2.10 (12 vulns; los GHSA traen
  // database_specific.severity, los PYSEC no).
  const index = severityIndexFromOsv(loadFixture('osv-query-jinja2.json'));

  it('resuelve la severidad por id GHSA directo', () => {
    expect(index['GHSA-462w-v97r-4m45']).toBe('high');
    expect(index['GHSA-g3rq-g295-4j3m']).toBe('moderate');
  });

  it('resuelve también por ALIAS, para que un id PYSEC herede la severidad de su gemelo GHSA', () => {
    // PYSEC-2019-217 no trae label propio; su alias es GHSA-462w-v97r-4m45 (HIGH).
    expect(index['PYSEC-2019-217']).toBe('high');
    // También debe resolver por alias CVE.
    expect(index['CVE-2019-10906']).toBe('high');
  });

  it('no inventa entradas para ids que no aparecen', () => {
    expect(index['GHSA-no-existe']).toBeUndefined();
  });

  it('tolera un payload vacío o inválido sin lanzar', () => {
    expect(severityIndexFromOsv({})).toEqual({});
    expect(severityIndexFromOsv(null)).toEqual({});
    expect(severityIndexFromOsv({ vulns: 'no-es-array' })).toEqual({});
  });
});
