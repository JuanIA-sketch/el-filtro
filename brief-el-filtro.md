# BRIEF — El Filtro

**Fecha:** 24 de julio, 2026
**Posición en Juegos Imperiales:** Proyecto #2 de las 6 ideas nuevas (después de Las Llantas)
**Pareja directa:** El Repuesto (mañana), que retoma exactamente donde El Filtro se detiene
**Pipeline de construcción:** brief → plan mode → TDD rojo→verde (Vitest) → demo → auditoría de git → publish
**Modelo de construcción:** Opus 4.8 (Claude Code) o Fable 5

---

## 1. Resumen ejecutivo

El Filtro escanea, de una sola pasada, todos tus repos activos (npm y pip) y te dice — en lenguaje simple, no en jerga de CVE — cuáles dependencias hay que arreglar ya y cuáles pueden esperar. Reemplaza el ritual manual de entrar repo por repo a correr `npm audit` y descifrar qué tan grave es cada hallazgo.

## 2. El problema

Cada proyecto depende de librerías escritas por terceros. Esas librerías reciben parches de seguridad o simplemente dejan de mantenerse, y sin revisión activa, un proyecto sigue corriendo versiones viejas sin que nadie se entere. Hoy, revisar esto significa:

- Entrar repo por repo
- Correr `npm audit` (o el equivalente en Python) en cada uno
- Interpretar jerga técnica (CVEs, severity scores) para decidir qué es urgente de verdad

Ese último paso es el que más cuesta — sobre todo para alguien de la comunidad que apenas empieza y no tiene el criterio para distinguir un hallazgo crítico de uno cosmético.

## 3. Para quién es

- **Hoy:** para ti, corriendo contra tus propios repos reales como primera validación.
- **Después de publicarlo:** para cualquier miembro de Imperio Agéntico con sus propios repos npm/pip, sin que tengan que entender jerga de seguridad para usarlo.

## Riesgos de adopción y mitigaciones

La idea no es solo que El Filtro funcione — es que alguien de la comunidad lo pruebe y vuelva a usarlo. Estos son los puntos que más pueden matar eso en el primer intento, y cómo quedan resueltos en el diseño:

- **`pip-audit` no viene instalado por defecto** (a diferencia de `npm audit`, que ya viene con npm). Si falta, El Filtro avisa con el comando exacto para instalarlo y salta solo ese repo — no revienta el escaneo completo (ver 6.3).
- **Pedir configuración antes de mostrar el primer resultado mata la adopción.** Cero configuración obligatoria: te paras en tu carpeta de proyectos, corres el comando, y ya (ver 6.1).
- **Un falso positivo el día 1 rompe la confianza más rápido de lo que la construye un acierto.** Para el MVP, "abandonado" se basa solo en la señal 100% confiable (`deprecated` explícito) — no en un umbral de meses que puede marcar como muerto algo que solo está maduro y estable (ver 6.4).
- **El silencio durante un escaneo largo genera duda de si se colgó.** Mostrar progreso por repo mientras corre (ver 11).
- **Prometer dos ecosistemas y entregar uno a medias es peor que prometer uno bien.** Si el tiempo aprieta, npm sale completo y validado; pip queda documentado como "en progreso" en el README, no publicado a medias (ver 9).

## 4. Qué NO es — límites y no-solapamiento

| Herramienta | Qué cubre | El Filtro NO hace esto |
|---|---|---|
| El Doctor | Salud general del proyecto (14 checks, 100 pts) | ⚠️ Confirmar antes de plan mode que ninguno de esos 14 checks ya audita dependencias — si hay solapamiento real, hay que decidir quién se queda con esa responsabilidad |
| La Alarma | Secretos e infraestructura | No busca credenciales expuestas |
| El Blindaje | Capa de prompts/instrucciones | No toca CLAUDE.md ni system prompts |
| El Repuesto (mañana) | Sugiere reemplazos para dependencias problemáticas | Detecta el problema; no lo resuelve |

## 5. Alcance funcional — qué sí hace

1. Descubre todos los repos relevantes en una pasada
2. Detecta el ecosistema de cada uno (npm, pip, o ninguno)
3. Corre la auditoría de vulnerabilidades correspondiente
4. Detecta paquetes abandonados o sin mantenimiento (más allá de solo CVEs)
5. Traduce cada hallazgo a lenguaje simple, clasificado en 2 niveles de urgencia
6. Genera un reporte consolidado — en consola y en disco

## 6. Diseño técnico propuesto

### 6.1 Descubrimiento de repos

Propuesta: barrido automático de una carpeta raíz configurable, buscando subcarpetas con `.git` — sin bajar más allá una vez encontrado uno (para no entrar a `node_modules` ni a repos anidados). Config opcional (`.el-filtro.json`) para excluir carpetas puntuales.

**Cero configuración para el primer uso:** si no se especifica una raíz, escanea desde el directorio actual (`process.cwd()`). Así el primer comando que alguien corre es literalmente pararse en su carpeta de proyectos y ejecutar `npx el-filtro`, sin tocar ningún archivo de config antes de ver el primer resultado.

✅ **Confirmado:** todos los repos activos están clonados localmente (en la PC, además de existir en GitHub) — el barrido de carpeta local cubre el caso real, sin necesidad de sumar un modo de descubrimiento vía GitHub API.

### 6.2 Detección de ecosistema

- `package.json` presente → repo npm
- `requirements.txt`, `pyproject.toml` o `Pipfile` presente → repo pip
- Ninguno de los dos → se salta y se lista como "no aplica" (no como error)

### 6.3 Auditoría de vulnerabilidades

- **npm:** `npm audit --json`. Si falta el lockfile, generar solo el lockfile (sin instalar todo `node_modules`) — a validar en plan mode si eso es suficiente para que `npm audit` funcione.
- **pip:** `pip-audit -r requirements.txt --format json`. Recomiendo `pip-audit` (herramienta oficial de PyPA) sobre `safety`, porque usa la base de datos abierta de PyPI/OSV sin necesitar registro ni API key — coherente con mantener El Filtro fácil de instalar.
- **Manejo si falta `pip-audit`:** no debe fallar con un error críptico. El Filtro detecta que no está instalado y muestra un mensaje claro con el comando exacto para instalarlo (`pip install pip-audit`), saltando solo la auditoría de ese repo y siguiendo con el resto. Esto es lo que evita que alguien de la comunidad con un solo repo Python rebote en el primer uso.

⚠️ **Punto técnico incierto:** `npm audit` trae severidad estructurada (critical/high/moderate/low) de forma consistente. No tengo la misma certeza de que `pip-audit` exponga severidad de forma tan uniforme en su JSON — confirmar esto en plan mode antes de comprometerse con el mapeo de la sección 6.5, porque es la pieza que más puede cambiar el diseño.

### 6.4 Detección de abandono

Más allá de vulnerabilidades conocidas, un paquete puede estar "muerto" sin tener un CVE activo:

- **Señal 1 (determinística, alta confianza):** flag `deprecated` explícito — npm lo expone directo en la metadata del registro.
- **Señal 2 (heurística, requiere umbral):** última publicación hace más de X meses (propongo 18 como punto de partida, ajustable). Más ruidosa — puede marcar como "abandonado" algo que simplemente ya está maduro y estable.
- Para pip, el equivalente de "deprecated" no siempre existe en la metadata del paquete — revisar en plan mode si vale la pena chequear si el repo de origen está archivado, o si eso queda para una versión futura.

✅ **Confirmado:** solo la Señal 1 (deprecated) entra en el alcance de hoy. La Señal 2 (umbral de meses) queda fuera del MVP — se evalúa en una iteración futura si hace falta.

### 6.5 Clasificación en lenguaje simple

Para mantener la misma línea de Las Llantas (cero IA, cero API key, fácil de instalar), propongo un mapeo 100% determinístico:

- 🔴 **Arréglalo ya** → severidad critical/high, o deprecated sin alternativa conocida
- 🟡 **Puede esperar** → severidad moderate/low, o solo desactualizado (sin ser deprecated)

Cada hallazgo lleva una explicación de una línea desde una plantilla fija (no la jerga cruda del CVE) — ej: *"Esta librería tiene una vulnerabilidad conocida que se puede explotar directamente — actualízala antes de publicar algo que dependa de ella."*

✅ **Confirmado:** 100% determinístico, sin IA ni API key. La capa de IA opcional queda fuera del alcance de hoy (posible iteración futura, no descartada).

### 6.6 Reporte consolidado — el contrato con El Repuesto

- **Consola:** resumen humano, agrupado por los 2 buckets, con desglose por repo.
- **Disco:** JSON estructurado en `.el-filtro/report-<timestamp>.json`. Esta es la pieza que El Repuesto va a leer mañana, así que su forma tiene que quedar clara y estable desde hoy — vale la pena fijar el esquema en plan mode antes de escribir el primer test.
- **Métricas para el post de Logro:** # repos escaneados, # vulnerabilidades totales, # críticas, # paquetes abandonados, tiempo estimado ahorrado vs. revisar repo por repo a mano.

## 7. Manejo de errores y casos límite

- Un repo sin conexión, sin lockfile, o con la auditoría fallida no debe tumbar el escaneo completo — se marca como "no se pudo auditar" y el resto sigue.
- ⚠️ Monorepos con npm workspaces: ¿entran en el alcance de hoy o quedan fuera (como Las Llantas dejó fuera Docker/K8s)? Recomiendo dejarlos fuera del MVP y documentarlo como limitación conocida.

## 8. Fuera de alcance — hoy

- Sugerir reemplazos (El Repuesto, mañana)
- Escaneo de secretos (La Alarma)
- Auditoría de la capa de prompts (El Blindaje)
- Ecosistemas fuera de npm/pip (Go, Rust, etc.)
- Monorepos con workspaces complejos (a confirmar)

## 9. Plan de construcción por etapas (TDD rojo→verde)

1. **Motor npm** — descubrimiento + detección de ecosistema + `npm audit` + clasificación + reporte (consola + JSON), validado contra 2-3 repos reales tuyos.
2. **Motor pip** — mismo pipeline para requirements.txt/pyproject.toml, validado contra un repo Python real (ej. charly-prospecting).
3. **Detección de abandono** — flag `deprecated` primero; umbral de antigüedad después, si el tiempo alcanza.
4. **Pulido** — README, LICENSE, CLAUDE.md, tests en verde, auditoría de La Alarma, git init + commit.

**Salvaguarda de tiempo:** si el día se acaba antes de terminar la Etapa 2, el motor npm sale completo y validado; el soporte de pip se documenta en el README como "en progreso" en vez de publicarse a medias. Mejor prometer menos y cumplir, que prometer los dos ecosistemas y fallar en uno frente a la comunidad.

## 10. Validación real

Correr El Filtro contra tus repos reales ya indexados en La Guantera (la-guantera, ancla-precios, el-retrovisor, el-chasis, la-alarma, batallas-imperio-agentico, freno-de-mano, el-doctor, model-shift-windows, paracaidas, instalador-un-clic, trazo, las-llantas, el-tablero) — mismo patrón que la validación real de Las Llantas contra Ancla de Precios. Esto también te da las cifras reales para el post de Logro.

## 11. Criterios de aceptación

- [ ] Escanea una carpeta raíz y encuentra todos los repos con `.git`, sin bajar dentro de `node_modules` ni repos anidados
- [ ] Clasifica correctamente un repo npm y un repo pip en la misma corrida
- [ ] Un repo sin auditoría posible no rompe el resto del escaneo
- [ ] Cada hallazgo queda en 🔴 o 🟡, con una explicación en lenguaje simple, no en jerga cruda
- [ ] El JSON de salida es legible y estable (contrato para El Repuesto)
- [ ] Validado de punta a punta contra al menos 3 repos reales tuyos, con al menos un repo pip real
- [ ] Tests en verde, auditoría de La Alarma sin hallazgos, README claro para alguien nuevo
- [ ] Correr `el-filtro` sin ningún argumento ni archivo de configuración, parado en una carpeta de proyectos, produce un resultado útil en el primer intento
- [ ] Durante un escaneo de varios repos se muestra progreso (ej. "repo 3/14") en vez de quedarse en silencio

## 12. Entregables

- Repo público en GitHub (JuanIA-sketch) — confirmación explícita antes de `git push` / `gh repo create`
- README + LICENSE + CLAUDE.md
- Tests en verde (Vitest)
- Un reporte JSON de ejemplo commiteado como referencia para El Repuesto
- Post de Logro en Skool (formato de 5 partes) con las métricas reales de la validación

## 13. Stack técnico

- Node.js + TypeScript, Vitest (coherente con el resto de la familia)
- `child_process`/`execa` para invocar `npm audit` y `pip-audit`
- Sin necesidad de API key en el escenario determinístico de hoy
- Nombre de paquete sugerido: `el-filtro` (consistente con el-chasis, el-doctor, la-alarma) — a confirmar

## 14. Decisiones — estado final

1. ✅ Repos confirmados como clonados localmente (además de en GitHub) — el barrido de carpeta local (6.1) cubre el caso real.
2. Solapamiento con los 14 checks de El Doctor — sigue pendiente de verificación en plan mode por Claude Code (o antes, si compartes el README/checks).
3. ✅ Clasificación 100% determinística confirmada, sin IA ni API key (6.5).
4. ✅ Detección de abandono confirmada: solo flag deprecated, sin umbral de meses (6.4).
5. Monorepos / npm workspaces — sin objeción hasta ahora, queda fuera del alcance de hoy (7 y 8).

**Brief listo para plan mode**, salvo el punto 2, que Claude Code resuelve al arrancar.
