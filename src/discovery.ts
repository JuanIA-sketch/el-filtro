import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { detectEcosystem } from './ecosystem.js';

export interface DiscoverOptions {
  /** Nombres de carpeta a excluir del barrido (además de los de .el-filtro.json). */
  exclude?: string[];
}

// Nunca se barren ni se tratan como repos candidatos.
const ALWAYS_IGNORE: ReadonlySet<string> = new Set(['node_modules', '.git']);

function isRepo(dir: string): boolean {
  return existsSync(join(dir, '.git'));
}

/** Lee `exclude` de un `.el-filtro.json` en la raíz (config opcional, §6.1). */
function readConfigExcludes(root: string): string[] {
  const p = join(root, '.el-filtro.json');
  if (!existsSync(p)) return [];
  try {
    const cfg = JSON.parse(readFileSync(p, 'utf8')) as { exclude?: unknown };
    return Array.isArray(cfg.exclude)
      ? cfg.exclude.filter((x): x is string => typeof x === 'string')
      : [];
  } catch {
    return []; // config rota no debe tumbar el barrido
  }
}

/**
 * Barre `root` buscando repos (carpetas con `.git`). No desciende una vez hallado
 * un repo (evita repos anidados y su node_modules) ni entra a node_modules (§6.1).
 * Si el root mismo es un repo, lo devuelve a él. Orden determinístico.
 */
export function discoverRepos(root: string, opts: DiscoverOptions = {}): string[] {
  const exclude = new Set([...(opts.exclude ?? []), ...readConfigExcludes(root)]);
  const found: string[] = [];

  function walk(dir: string): void {
    if (isRepo(dir)) {
      found.push(dir);
      return; // no descender dentro de un repo
    }
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return; // carpeta ilegible: se ignora, el resto sigue
    }
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      if (ALWAYS_IGNORE.has(entry.name) || exclude.has(entry.name)) continue;
      walk(join(dir, entry.name));
    }
  }

  walk(root);

  // Fallback: no todo proyecto auditable es un repo git propio. Caso real: proyectos pip
  // con requirements.txt anidados dentro del repo de otra cosa. Si el barrido no encontró
  // NINGÚN repo, y la carpeta apuntada es en sí un proyecto, se audita esa carpeta. Así
  // funciona "párate en tu proyecto y corre el comando". Los subproyectos anidados dentro
  // de un repo siguen fuera de alcance (limitación conocida).
  if (found.length === 0 && detectEcosystem(root) !== 'none') return [root];

  return found.sort();
}
