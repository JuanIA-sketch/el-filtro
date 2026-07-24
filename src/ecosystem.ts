import { existsSync } from 'node:fs';
import { join } from 'node:path';
import type { Ecosystem } from './types.js';

// Marcadores de un repo Python (§6.2). npm se detecta aparte con package.json.
const PIP_MARKERS = ['requirements.txt', 'pyproject.toml', 'Pipfile'] as const;

/**
 * Detecta el ecosistema de un repo por sus archivos marcadores (§6.2). npm tiene
 * precedencia: si hay package.json, es el motor de la Etapa 1. Un repo sin ninguno
 * devuelve 'none' — se lista como "no aplica", nunca como error.
 */
export function detectEcosystem(repoPath: string): Ecosystem {
  if (existsSync(join(repoPath, 'package.json'))) return 'npm';
  if (PIP_MARKERS.some((marker) => existsSync(join(repoPath, marker)))) return 'pip';
  return 'none';
}

function hasNpm(repoPath: string): boolean {
  return existsSync(join(repoPath, 'package.json'));
}

function hasPip(repoPath: string): boolean {
  return PIP_MARKERS.some((marker) => existsSync(join(repoPath, marker)));
}

/**
 * Ecosistemas presentes que NO ganaron la precedencia de `detectEcosystem`.
 *
 * La regla es explícita: npm gana cuando conviven (mismo early return de arriba, fijado por
 * test). Pero no debe ser silenciosa — una carpeta políglota tiene dependencias del otro
 * ecosistema sin auditar, y El Filtro las reporta en vez de esconderlas. Auditar ambos
 * queda fuera de esta versión: `ecosystem` es un valor único del contrato que lee El Repuesto.
 */
export function detectSecondaryEcosystems(repoPath: string): Ecosystem[] {
  const primary = detectEcosystem(repoPath);
  if (primary === 'npm' && hasPip(repoPath)) return ['pip'];
  if (primary === 'pip' && hasNpm(repoPath)) return ['npm']; // inalcanzable hoy; explícito por si cambia la precedencia
  return [];
}
