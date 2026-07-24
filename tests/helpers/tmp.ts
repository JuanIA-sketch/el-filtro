import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

const created: string[] = [];

/**
 * Crea un directorio temporal real y siembra los archivos dados (rutas relativas →
 * contenido). Registra el dir para limpiarlo con cleanupTempDirs(). Sin mocks: usa
 * el filesystem de verdad, igual que los fixtures de El Doctor.
 */
export function makeTempDir(files: Record<string, string> = {}): string {
  const dir = mkdtempSync(join(tmpdir(), 'el-filtro-test-'));
  created.push(dir);
  for (const [rel, content] of Object.entries(files)) {
    const abs = join(dir, rel);
    mkdirSync(dirname(abs), { recursive: true });
    writeFileSync(abs, content);
  }
  return dir;
}

/** Crea un subdirectorio vacío dentro de un dir ya creado (para árboles de repos). */
export function makeDir(parent: string, rel: string): string {
  const abs = join(parent, rel);
  mkdirSync(abs, { recursive: true });
  return abs;
}

export function cleanupTempDirs(): void {
  for (const dir of created) {
    rmSync(dir, { recursive: true, force: true });
  }
  created.length = 0;
}
