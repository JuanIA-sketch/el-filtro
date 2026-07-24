import { describe, it, expect, afterAll } from 'vitest';
import { detectEcosystem, detectSecondaryEcosystems } from '../src/ecosystem.js';
import { makeTempDir, cleanupTempDirs } from './helpers/tmp.js';

afterAll(cleanupTempDirs);

describe('detectEcosystem', () => {
  it('detecta npm cuando hay package.json', () => {
    expect(detectEcosystem(makeTempDir({ 'package.json': '{}' }))).toBe('npm');
  });

  it('detecta pip con requirements.txt', () => {
    expect(detectEcosystem(makeTempDir({ 'requirements.txt': 'flask==2.0.0\n' }))).toBe('pip');
  });

  it('detecta pip con pyproject.toml', () => {
    expect(detectEcosystem(makeTempDir({ 'pyproject.toml': '[project]\nname="x"\n' }))).toBe('pip');
  });

  it('detecta pip con Pipfile', () => {
    expect(detectEcosystem(makeTempDir({ Pipfile: '[packages]\n' }))).toBe('pip');
  });

  it('devuelve none cuando no hay ningún marcador', () => {
    expect(detectEcosystem(makeTempDir({ 'README.md': 'hola' }))).toBe('none');
  });

  it('npm tiene precedencia si conviven package.json y marcadores de pip', () => {
    expect(detectEcosystem(makeTempDir({ 'package.json': '{}', 'requirements.txt': 'flask\n' }))).toBe(
      'npm',
    );
  });
});

describe('detectSecondaryEcosystems — la regla de precedencia no es silenciosa', () => {
  it('con package.json Y requirements.txt reporta pip como ecosistema secundario', () => {
    const dir = makeTempDir({ 'package.json': '{}', 'requirements.txt': 'flask\n' });
    expect(detectEcosystem(dir)).toBe('npm');
    expect(detectSecondaryEcosystems(dir)).toEqual(['pip']);
  });

  it('un proyecto de un solo ecosistema no reporta secundarios', () => {
    expect(detectSecondaryEcosystems(makeTempDir({ 'package.json': '{}' }))).toEqual([]);
    expect(detectSecondaryEcosystems(makeTempDir({ 'requirements.txt': 'flask\n' }))).toEqual([]);
  });

  it('una carpeta sin marcadores no reporta secundarios', () => {
    expect(detectSecondaryEcosystems(makeTempDir({ 'README.md': 'hola' }))).toEqual([]);
  });
});
