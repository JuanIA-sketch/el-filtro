# 🔎 El Filtro

**Escanea todos tus repos de una pasada y te dice, en lenguaje simple, qué dependencias hay que arreglar ya y cuáles pueden esperar.**

Reemplaza el ritual de entrar repo por repo, correr `npm audit`, y descifrar qué tan grave es cada hallazgo. El Filtro descubre tus proyectos, corre la auditoría que toque (npm o pip), detecta paquetes abandonados, y traduce todo a **dos niveles de urgencia** — sin jerga de CVE.

Es 100% determinístico: **sin LLM, sin API key, sin registro**.

Forma parte del kit de **Charly.marketing**:

| Herramienta | Qué hace |
|---|---|
| El Freno de Mano | Previene |
| El Doctor | Diagnostica la salud del proyecto |
| La Alarma | Busca secretos expuestos |
| **El Filtro** | **Audita las dependencias** |
| El Repuesto | Propone los reemplazos |

## Instalación y uso

```bash
npx el-filtro                          # escanea desde la carpeta actual
npx el-filtro --path ./mis-proyectos   # escanea otra ruta
npx el-filtro --json                   # salida JSON máquina-legible
npx el-filtro --no-write               # no escribe el reporte a disco
```

**Cero configuración.** Te paras en tu carpeta de proyectos, corres el comando, y ya.

Para auditar repos Python necesitas `pip-audit` (no viene con pip):

```bash
pip install pip-audit
```

Si falta, El Filtro te lo dice con el comando exacto y **salta solo ese repo** — el resto del escaneo sigue.

## Qué hace

1. **Descubre** todos los repos con `.git` bajo la carpeta que le indiques, sin bajar a `node_modules` ni a repos anidados.
2. **Detecta el ecosistema** de cada uno (npm, pip, o ninguno).
3. **Audita**: `npm audit` o `pip-audit`, según toque.
4. **Detecta paquetes abandonados** (flag `deprecated` del registro de npm).
5. **Clasifica** cada hallazgo en 🔴 o 🟡 con una explicación de una línea.
6. **Reporta** en consola y en `.el-filtro/report-<timestamp>.json`.

### Los dos niveles

| | Cuándo |
|---|---|
| 🔴 **Arréglalo ya** | Vulnerabilidad `critical` o `high` · paquete abandonado sin reemplazo conocido |
| 🟡 **Puede esperar** | Vulnerabilidad `moderate` o `low` · paquete abandonado que sí señala reemplazo · gravedad que no se pudo determinar |

## Configuración opcional

Un `.el-filtro.json` en la raíz escaneada permite excluir carpetas:

```json
{ "exclude": ["archivado", "experimentos"] }
```

## El reporte JSON

Es el contrato estable que consume **El Repuesto**. `schemaVersion: 1`.

```jsonc
{
  "schemaVersion": 1,
  "tool": "el-filtro",
  "generatedAt": "2026-07-24T19:30:14.735Z",
  "root": "C:\\...\\proyectos",
  "summary": {
    "reposScanned": 22, "reposAudited": 22, "reposSkipped": 0,
    "findings": { "total": 53, "fixNow": 28, "canWait": 25 },
    "bySeverity": { "critical": 8, "high": 19, "moderate": 25, "low": 0, "info": 0 },
    "unknownSeverity": 0,        // vulnerabilidades sin gravedad determinada
    "abandonedPackages": 1
  },
  "repos": [{
    "name": "mi-repo",
    "path": "C:\\...\\mi-repo",
    "ecosystem": "npm",              // npm | pip | none
    "secondaryEcosystems": [],       // otros ecosistemas presentes, NO auditados
    "status": "audited",             // audited | no-audit | not-applicable
    "statusReason": null,
    "findings": [{
      "type": "vulnerability",       // vulnerability | deprecated
      "package": "lodash",
      "installedVersions": ["4.17.11"],
      "severity": "critical",        // null si no se pudo determinar, o si es deprecated
      "bucket": "fix-now",           // fix-now | can-wait — SIEMPRE presente
      "direct": true,
      "fixAvailable": true,
      "explanation": "Esta librería tiene una vulnerabilidad conocida...",
      "advisory": { "titles": [...], "urls": [...], "range": "<4.17.21" },
      "unresolvedAdvisories": 0      // advisories sin gravedad resuelta dentro de este hallazgo
    }]
  }]
}
```

**Para quien consuma este JSON:** `severity` puede venir en `null` aunque el hallazgo sea una vulnerabilidad (ver limitaciones). `bucket` siempre viene poblado — úsalo como señal principal.

📄 **Ejemplo completo:** [`examples/report-ejemplo.json`](examples/report-ejemplo.json) — generado de corridas reales (rutas saneadas). Cubre los tres estados de repo, los dos tipos de hallazgo, un caso de gravedad sin resolver y un repo políglota.

### Invariantes garantizados

- `findings.total === findings.fixNow + findings.canWait`
- `suma(bySeverity) + unknownSeverity === número de hallazgos type:"vulnerability"`
- `reposAudited + reposSkipped === reposScanned`

## ⚠️ Limitaciones conocidas

### La detección de "¿hay reemplazo?" es imperfecta — y falla a propósito hacia 🔴

Cuando un paquete está marcado como `deprecated`, El Filtro decide entre 🔴 y 🟡 según si el mensaje **nombra un reemplazo**. Ese mensaje es **texto libre** que cada quien escribe distinto (`"Use uuid module instead"`, `"we recommend using babel-preset-env now"`, `"replaced by X"`…), así que la detección es por patrones y **no puede ser perfecta**.

**El sesgo es deliberado: ante la duda, 🔴.** Si El Filtro no reconoce la frase, asume que **no hay salida conocida** y marca el hallazgo como urgente. Preferimos molestarte de más a hacerte creer que hay una alternativa cuando no la hay.

En concreto:
- Se descartan primero los contextos negativos (`"do not use"`, `"use at your own risk"`, `"no longer in use"`) — ahí no hay reemplazo, hay advertencia.
- Solo cuentan marcadores explícitos: `use X instead`, `recommend using X`, `replaced by X`, `superseded by X`, `in favor of X`, `migrate to X`, `switch to X`.
- Cualquier otra redacción → 🔴.

Si ves un 🔴 por abandono, **lee el mensaje original** en `advisory.titles[0]`: puede que sí haya reemplazo escrito de una forma que no reconocimos.

### La gravedad en pip no viene de pip-audit

`pip-audit` **no expone severidad** en su JSON (ni con el servicio `pypi` ni con `osv`): solo devuelve `id`, `fix_versions`, `aliases` y `description`. El Filtro la resuelve consultando la **API pública de OSV** (sin API key), cruzando por el alias `GHSA` de cada advisory.

Consecuencias:
- **Sin conexión**, o si un advisory no tiene etiqueta de gravedad, el hallazgo queda con `severity: null` → 🟡 y lo dice explícitamente.
- Si un paquete tiene varios advisories y solo algunos resuelven, se usa **la gravedad más alta conocida** y se reporta cuántos quedaron sin evaluar (`unresolvedAdvisories`), porque la gravedad real podría ser mayor.

### Otras

- **Paquetes abandonados: solo npm.** PyPI no tiene un flag `deprecated` estándar equivalente.
- **Solo dependencias directas** se revisan por abandono (las de `package.json`) — son las que puedes reemplazar de verdad.
- **Solo la señal `deprecated` explícita.** No usamos "meses sin publicar" como señal: marcaría como muerto algo que solo está maduro y estable.
- **Monorepos / workspaces**: los subproyectos anidados *dentro* de un repo git no se auditan por separado.
- **Una carpeta con `package.json` y `requirements.txt` a la vez** se audita como npm; el otro ecosistema se reporta en `secondaryEcosystems` pero **no se audita**.
- **`pyproject.toml` / Poetry sin `requirements.txt`**: no soportado todavía; el repo se marca como no auditado con la razón.

## Cómo se comporta cuando algo falla

Un repo que no se puede auditar **nunca tumba el escaneo**: se marca `no-audit` con la razón en lenguaje simple y el resto continúa. Vale para: falta `pip-audit`, no hay lockfile y no hay red, `requirements.txt` con versiones en conflicto, o registro caído.

Si un repo npm **no tiene lockfile**, El Filtro genera uno en una **carpeta temporal** para poder auditar — **nunca modifica tu repo**.

## Desarrollo

```bash
npm install
npm test          # build + suite completa (TDD, fixtures reales como oráculo)
npm run test:watch
```

## Licencia

MIT © [Charly.marketing](https://charly.marketing)
