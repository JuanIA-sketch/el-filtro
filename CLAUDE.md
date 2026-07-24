# CLAUDE.md — El Filtro

Auditor de dependencias para repos npm y pip. Escanea una carpeta de proyectos de una
pasada y clasifica cada hallazgo en dos niveles de urgencia, en lenguaje simple.
100% determinístico: **sin LLM, sin API key, sin credenciales**.

## Reglas del proyecto

- **TDD rojo→verde con Vitest, sin excepciones.** Ningún código de producción sin un test
  que haya fallado primero. Si escribiste código antes del test, bórralo y empieza de nuevo.
- **Nunca `grep -n` para buscar secretos** — solo `grep -l` o `grep -q`.
- **Nunca metas secretos reales** en el repo ni en la sesión.
- **Confirmación explícita antes de `git push` o `gh repo create`.**
- Los fixtures son **salidas reales capturadas** (`npm audit`, `pip-audit`, OSV, packuments
  del registro), no inventadas. Si necesitas uno nuevo, captúralo de verdad.

## Arquitectura

Funciones **puras** para toda la lógica (parseo, clasificación, agregación, reporte), y
**bordes** finos e inyectables para I/O (subprocesos, red, filesystem). Los bordes se
prueban por e2e; la lógica, por unidad con fixtures reales.

```
src/
  cli.ts                 Commander; cablea los bordes reales
  scan.ts                Orquestador: descubre → detecta → audita → reporta
  discovery.ts           Barrido de repos (.git) + fallback a la raíz
  ecosystem.ts           npm | pip | none  (+ ecosistemas secundarios)
  classify.ts            severidad → 🔴/🟡 + plantillas en lenguaje simple
  report.ts              Contrato JSON, render de consola, escritura a disco
  osv.ts                 Severidad de pip vía API pública de OSV
  types.ts               Tipos del contrato
  audit/
    npm.ts               npm audit + versiones del lockfile + abandonados
    pip.ts               pip-audit + agregación por paquete
    deprecated.ts        Flag deprecated del registro npm
  runners/exec.ts        Subprocesos (shell en Windows, barrera anti-inyección)
```

**Regla de inyección:** todo lo que toque red, disco o subprocesos entra como parámetro
(`RunCommand`, `ResolveSeverities`, `ResolveDeprecation`), para poder testear con fakes.

## Decisiones que NO deben revertirse sin pensarlo

- **`npm audit` sale con exit 1 cuando hay vulnerabilidades**: eso es normal, no un error.
  El runner nunca rechaza por exit code; devuelve el código y decide la capa de arriba.
- **En Windows se corre con `shell: true`** (para resolver `.cmd`), y ahí un binario ausente
  **no lanza ENOENT**: el shell devuelve un mensaje localizado. Por eso existe
  `looksLikeMissingPipAudit`.
- **Sin lockfile → copia temporal.** Jamás modificar el repo de la persona.
- **`pip-audit` no da severidad**; se resuelve contra OSV por alias GHSA. Sin red →
  `severity: null` → 🟡, dicho explícitamente. Nunca inventar gravedad.
- **Los hallazgos pip se agregan por paquete**, como hace npm, para que los conteos sean
  comparables entre ecosistemas.
- **`hasKnownAlternative` se equivoca a propósito hacia 🔴.** Ante texto libre que no
  reconoce, asume que no hay reemplazo. El error inaceptable es el contrario.
- **Un repo que falla nunca tumba el escaneo**: se marca `no-audit` con razón legible.
- **Campos aditivos del contrato** (`secondaryEcosystems`, `unknownSeverity`,
  `unresolvedAdvisories`) se normalizan en `buildReport` para que el JSON siempre los traiga.

## Invariantes (hay tests que los fijan)

- `findings.total === fixNow + canWait`
- `suma(bySeverity) + unknownSeverity === # hallazgos type:'vulnerability'`
- `reposAudited + reposSkipped === reposScanned`

Si un cambio los rompe, el problema es el cambio.

## Comandos

```bash
npm test          # build + suite completa
npm run test:watch
npm run dev -- --path ./algo    # correr sin build
```

## Contrato con El Repuesto

El JSON de `.el-filtro/report-<ts>.json` es **estable** (`schemaVersion: 1`). El Repuesto lo
lee para proponer reemplazos. Cambios aditivos: sí. Cambios que alteren el significado de un
campo existente: suben `schemaVersion`.

**Ojo:** `severity` puede ser `null` en hallazgos `type: "vulnerability"` (pip sin dato de
OSV) y siempre lo es en `type: "deprecated"`. `bucket` siempre viene poblado.
