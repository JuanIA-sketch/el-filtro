import { describe, it, expect } from 'vitest';
import {
  classifySeverity,
  vulnerabilityExplanation,
  classifyUnknownSeverity,
  unknownSeverityExplanation,
} from '../src/classify.js';

describe('classifySeverity', () => {
  it('pone critical en el bucket fix-now', () => {
    expect(classifySeverity('critical')).toBe('fix-now');
  });
  it('pone high en el bucket fix-now', () => {
    expect(classifySeverity('high')).toBe('fix-now');
  });
  it('pone moderate en el bucket can-wait', () => {
    expect(classifySeverity('moderate')).toBe('can-wait');
  });
  it('pone low en el bucket can-wait', () => {
    expect(classifySeverity('low')).toBe('can-wait');
  });
  it('pone info en el bucket can-wait', () => {
    expect(classifySeverity('info')).toBe('can-wait');
  });
});

describe('vulnerabilityExplanation', () => {
  it('para fix-now explica la urgencia en lenguaje simple, sin jerga de CVE', () => {
    const text = vulnerabilityExplanation('fix-now');
    expect(text).toMatch(/vulnerabilidad/i);
    expect(text).not.toMatch(/CVE|GHSA/);
    expect(text.length).toBeGreaterThan(20);
  });
  it('para can-wait comunica que no es urgente, sin jerga de CVE', () => {
    const text = vulnerabilityExplanation('can-wait');
    expect(text).toMatch(/no es urgente|puede esperar/i);
    expect(text).not.toMatch(/CVE|GHSA/);
    expect(text.length).toBeGreaterThan(20);
  });
});

describe('severidad desconocida (pip sin dato de OSV o sin red)', () => {
  it('cae en can-wait: no se infla la urgencia sin evidencia', () => {
    expect(classifyUnknownSeverity()).toBe('can-wait');
  });

  it('explica en lenguaje simple que no se pudo determinar la gravedad, sin jerga', () => {
    const text = unknownSeverityExplanation();
    expect(text).toMatch(/gravedad|no se pudo/i);
    expect(text).not.toMatch(/CVE|GHSA|PYSEC|OSV/);
    expect(text.length).toBeGreaterThan(20);
  });
});
