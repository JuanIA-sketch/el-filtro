/**
 * Adaptador de I/O para correr procesos reales (npm). Es el BORDE: no se testea por
 * unidad; la lógica que lo usa se prueba con fakes de esta misma firma, y este
 * adaptador queda cubierto por el e2e y la demo real.
 *
 * Nunca rechaza por exit code ≠ 0 (npm audit sale con 1 cuando HAY vulnerabilidades,
 * lo cual es normal): devuelve el `code` para que la capa de arriba decida. Solo
 * rechaza si el binario no se pudo lanzar (ENOENT). Mismo patrón que Las Llantas.
 */
import { execFile } from 'node:child_process';

export interface ExecResult {
  code: number;
  stdout: string;
  stderr: string;
}

export interface ExecOptions {
  cwd?: string;
}

export type RunCommand = (
  command: string,
  args: string[],
  options?: ExecOptions,
) => Promise<ExecResult>;

/** true si el error es "no se pudo lanzar el binario" (binario ausente). */
function isSpawnFailure(err: unknown): boolean {
  const e = err as NodeJS.ErrnoException & { syscall?: string };
  return typeof e?.code === 'string' && typeof e.syscall === 'string' && e.syscall.startsWith('spawn');
}

// Solo tokens simples: letras, dígitos y `-_@:./\+=~,`. Sin espacios ni metacaracteres.
const SAFE_ARG = /^[\w@:./\\+=~,-]*$/;

export function isShellSafeArg(arg: string): boolean {
  return SAFE_ARG.test(arg);
}

/**
 * Con shell:true (necesario en Windows para resolver npm.cmd) Node NO escapa los
 * argumentos. Esta barrera impide que un valor externo se vuelva un comando aparte
 * vía `&`, `;`, `|`… El cwd (que sí puede tener espacios) va como opción, no como arg.
 */
function assertShellSafe(command: string, args: string[]): void {
  for (const value of [command, ...args]) {
    if (!isShellSafeArg(value)) {
      throw new Error(
        `Argumento no seguro para exec (posible inyección de comandos): ${JSON.stringify(value)}.`,
      );
    }
  }
}

export const runCommand: RunCommand = (command, args, options = {}) => {
  assertShellSafe(command, args);
  return new Promise<ExecResult>((resolve, reject) => {
    execFile(
      command,
      args,
      { cwd: options.cwd, shell: process.platform === 'win32', maxBuffer: 32 * 1024 * 1024 },
      (error, stdout, stderr) => {
        if (error && isSpawnFailure(error)) {
          reject(error);
          return;
        }
        const code =
          error && typeof (error as { code?: unknown }).code === 'number'
            ? (error as { code: number }).code
            : 0;
        resolve({ code, stdout: String(stdout), stderr: String(stderr) });
      },
    );
  });
};
