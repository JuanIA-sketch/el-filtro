import { resolve } from 'node:path';
import { Command } from 'commander';
import { scan } from './scan.js';
import { auditNpmRepo } from './audit/npm.js';
import { auditPipRepo } from './audit/pip.js';
import { createDeprecationResolver } from './audit/deprecated.js';
import { fetchOsvSeverities } from './osv.js';
import { runCommand } from './runners/exec.js';
import { renderConsole, renderJson, writeReport } from './report.js';

// \r vuelve al inicio de la línea; ESC[K borra hasta el final. fromCharCode(27) es
// el byte ESC, escrito así para evitar ambigüedad de escape en el fuente.
const CLEAR_LINE = '\r' + String.fromCharCode(27) + '[K';

const program = new Command();

program
  .name('el-filtro')
  .description('🔎 Escanea tus repos npm/pip y te dice, en lenguaje simple, qué dependencias arreglar ya')
  .version('0.1.0')
  .option('--path <ruta>', 'carpeta raíz a escanear', '.')
  .option('--json', 'salida JSON máquina-legible, sin colores ni progreso')
  .option('--no-write', 'no escribir el reporte a disco')
  .action(async (opts: { path: string; json?: boolean; write?: boolean }) => {
    const root = resolve(opts.path);

    // Un solo resolvedor para todo el escaneo: cachea packuments entre repos (la familia
    // comparte muchas dependencias).
    const resolveDeprecation = createDeprecationResolver();

    const report = await scan(root, {
      auditNpm: (repoPath) => auditNpmRepo(repoPath, runCommand, resolveDeprecation),
      auditPip: (repoPath) => auditPipRepo(repoPath, runCommand, fetchOsvSeverities),
      onProgress: opts.json
        ? undefined
        : (current, total, name) => {
            // Progreso en stderr para no ensuciar stdout (§11).
            process.stderr.write(`${CLEAR_LINE}  Escaneando repo ${current}/${total}: ${name}...`);
          },
    });

    if (!opts.json) process.stderr.write(CLEAR_LINE); // limpia la línea de progreso

    if (opts.json) {
      console.log(renderJson(report));
    } else {
      console.log(renderConsole(report, { colors: process.stdout.isTTY === true }));
    }

    if (opts.write !== false) {
      const written = writeReport(report, root);
      if (!opts.json) console.log(`\nReporte guardado en: ${written}`);
    }
  });

program.parseAsync().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exitCode = 1;
});
