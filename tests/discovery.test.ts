import { describe, it, expect, afterAll } from 'vitest';
import { mkdirSync } from 'node:fs';
import { basename, join } from 'node:path';
import { discoverRepos } from '../src/discovery.js';
import { makeTempDir, makeDir, cleanupTempDirs } from './helpers/tmp.js';

afterAll(cleanupTempDirs);

/** Crea una subcarpeta con un `.git` dentro → luce como repo para el barrido. */
function makeRepo(root: string, name: string): string {
  const dir = makeDir(root, name);
  mkdirSync(join(dir, '.git'), { recursive: true });
  return dir;
}

const names = (paths: string[]) => paths.map((p) => basename(p)).sort();

describe('discoverRepos', () => {
  it('encuentra los repos hijos que tienen .git, ignorando carpetas sin .git', () => {
    const root = makeTempDir();
    makeRepo(root, 'repo-a');
    makeRepo(root, 'repo-b');
    makeDir(root, 'no-es-repo');
    expect(names(discoverRepos(root))).toEqual(['repo-a', 'repo-b']);
  });

  it('no desciende dentro de un repo hallado (ignora repos anidados y su node_modules)', () => {
    const root = makeTempDir();
    const repo = makeRepo(root, 'repo-a');
    makeRepo(repo, 'repo-anidado');
    mkdirSync(join(repo, 'node_modules', 'dep', '.git'), { recursive: true });
    expect(names(discoverRepos(root))).toEqual(['repo-a']);
  });

  it('no entra a node_modules al barrer la raíz', () => {
    const root = makeTempDir();
    makeRepo(root, 'repo-a');
    mkdirSync(join(root, 'node_modules', 'pkg', '.git'), { recursive: true });
    expect(names(discoverRepos(root))).toEqual(['repo-a']);
  });

  it('respeta la lista exclude de .el-filtro.json en la raíz', () => {
    const root = makeTempDir({ '.el-filtro.json': JSON.stringify({ exclude: ['archivado'] }) });
    makeRepo(root, 'repo-a');
    makeRepo(root, 'archivado');
    expect(names(discoverRepos(root))).toEqual(['repo-a']);
  });

  it('si el root mismo es un repo, lo devuelve a él (parado dentro de un repo)', () => {
    const root = makeTempDir();
    mkdirSync(join(root, '.git'), { recursive: true });
    expect(discoverRepos(root)).toEqual([root]);
  });

  it('encuentra repos dentro de subcarpetas intermedias que no son repos', () => {
    const root = makeTempDir();
    const grupo = makeDir(root, 'grupo');
    makeRepo(grupo, 'repo-c');
    expect(names(discoverRepos(root))).toEqual(['repo-c']);
  });
});

describe('discoverRepos — fallback a la raíz (proyectos que no son repos git)', () => {
  it('sin ningún repo git, trata la raíz como proyecto si tiene requirements.txt', () => {
    // Caso real: agents/carousel-creator tiene requirements.txt pero no .git propio.
    const root = makeTempDir({ 'requirements.txt': 'flask>=3.0.3\n' });
    expect(discoverRepos(root)).toEqual([root]);
  });

  it('sin ningún repo git, trata la raíz como proyecto si tiene package.json', () => {
    const root = makeTempDir({ 'package.json': '{}' });
    expect(discoverRepos(root)).toEqual([root]);
  });

  it('sin repos git y sin marcadores de ecosistema, no inventa nada', () => {
    const root = makeTempDir({ 'README.md': 'hola' });
    expect(discoverRepos(root)).toEqual([]);
  });

  it('NO regresa: si hay repos git, mandan ellos aunque la raíz tenga marcadores', () => {
    const root = makeTempDir({ 'package.json': '{}' });
    makeRepo(root, 'repo-a');
    expect(names(discoverRepos(root))).toEqual(['repo-a']);
  });
});
