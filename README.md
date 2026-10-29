# sdjwt-diff

Arnés diferencial de SD-JWT ([RFC 9901](https://www.rfc-editor.org/rfc/rfc9901.txt)) entre crates de Rust: la misma presentación pasa por cada verificador y se compara el veredicto, y el payload procesado, con lo que exige el RFC.

Differential harness for SD-JWT (RFC 9901) across Rust crates: the same presentation goes through every verifier, and each verdict and processed payload is compared with what the RFC requires.

> **ES** primero · **EN** abajo. Nivel de verificación: **B**.

---

## ES

### Qué se compara

| Implementación | Versión | Cómo se llama | Lo que deja al integrador |
|---|---|---|---|
| [`sd-jwt-payload`](https://crates.io/api/v1/crates/sd-jwt-payload) (IOTA) | 0.5.1 | `SdJwt::parse` + `into_disclosed_object` | firma del emisor y KB-JWT (no los verifica) |
| [`affinidi-sd-jwt`](https://crates.io/api/v1/crates/affinidi-sd-jwt) | 0.1.8 | `verifier::verify` / `verify_with_kb_freshness` | verificación JWS (`JwtVerifier`), también la del holder |
| [`bh-sd-jwt`](https://crates.io/api/v1/crates/bh-sd-jwt) (TBTL) | 0.7.1 | `NoHolderBindingVerifier` / `Verifier` + `Es256Verifier` | — |
| [`sdjwt`](https://crates.io/api/v1/crates/sdjwt) | 0.8.1 | `Verifier::verify` con PEM ES256 | — (Key Binding sólo con `cnf` RSA) |
| [`sd-jwt-rs`](https://crates.io/api/v1/crates/sd-jwt-rs) (OpenWallet Foundation Labs) | 0.7.1 | `SDJWTVerifier::new`, formato compacto | — |
| `reference` (`src/reference.rs`) | — | escrita desde RFC 9901 §4, §4.3, §7.1, §7.3 | — |

Las cinco versiones son las últimas publicadas según la API de crates.io al momento de medir. Ojo: varios crates dicen implementar borradores del IETF (por ejemplo, `sd-jwt-rs` declara la versión 7 del borrador); acá se los mide contra el texto final del RFC 9901.

Cuando un crate deja una parte al integrador por diseño, el adaptador la provee con el código ES256 del arnés y esas celdas salen como `delegated` y **no se puntúan**: firma del emisor para `sd-jwt-payload` y `affinidi-sd-jwt`, firma del KB-JWT para `affinidi-sd-jwt`, todo Key Binding para `sd-jwt-payload`. `sdjwt` sólo acepta claves RSA en `cnf`; con la clave P-256 del corpus sus 20 casos de Key Binding salen `unsupported` y tampoco se puntúan. `bh-sd-jwt` verifica SD-JWT VC, así que todo el corpus usa `typ: dc+sd-jwt` y `vct`.

### Corpus (72 casos, prerregistrado en [`PREREGISTRO.md`](PREREGISTRO.md))

- 21 válidos (`V*`): rechazarlos es un **rechazo espurio**. Incluye recursión de Disclosures, decoys, `_sd_alg` ausente, codificaciones distintas del mismo JSON (§4.2.1) y presentaciones con KB.
- 29 alterados o mal formados (`T*`) y 16 de Key Binding (`K*`): aceptarlos es una **aceptación indebida**.
- 6 abiertos (`P*`): el texto no fija qué hace el Verifier; se reportan, no se puntúan.
- Controles: positivos `V01` y `V12`; negativos `T07` (alg none), `T08` (otra clave), `T09` (payload alterado), `T12` (Disclosure alterada por el holder).

Política fija del Verifier: ES256, `sha-256`, `NOW = T0 + 30`, ventana de `iat` del KB-JWT de 300 s hacia atrás y 60 s hacia adelante, `aud` y `nonce` conocidos. Cada caso dice si el Verifier espera SD-JWT o SD-JWT+KB.

### Resultados

Reproducir (determinista; dos corridas y un clon limpio dieron salida idéntica byte a byte; el CI exige la misma salida):

```sh
cargo run --release --bin sdjwt-diff -- --csv results/matrix.csv \
  --details results/details.csv --json results/summary.json
```

[`results/matrix.csv`](results/matrix.csv) tiene un caso por fila, el veredicto de cada crate y en la columna `repro` la presentación exacta, que alcanza para reproducir el caso. [`results/details.csv`](results/details.csv) tiene el texto de error de cada celda.

| | reference | sd-jwt-payload | affinidi-sd-jwt | bh-sd-jwt | sdjwt | sd-jwt-rs |
|---|---|---|---|---|---|---|
| Casos puntuados | 66 | 42 | 58 | 66 | 47 | 66 |
| Coincide con el RFC | 66 | 36 | 52 | **66** | 33 | 53 |
| Rechazos espurios | 0 | 0 | 0 | 0 | 2 | 0 |
| Aceptaciones indebidas | 0 | 6 | 6 | 0 | 12 | 13 |
| Payload procesado distinto | 0 | 1 | 0 | 0 | 7 | 0 |
| Pánicos | 0 | 0 | 0 | 0 | 0 | 1 |
| Delegados / no soportados | 0 | 25 / 0 | 8 / 0 | 0 | 0 / 20 | 0 |
| Controles OK | 6/6 | 2/2 | 3/3 | 6/6 | **4/5** | **5/6** |

Divergencias de veredicto: **30 de 72 casos**.

### Hallazgos

**Quién controla la entrada importa.** En `T01`–`T03`, `T12`, `T13`, `T26` y `K*` el holder o un atacante arma la presentación con material que ya tiene. En `T14`–`T25` y `T27`–`T29` hace falta que el digest o el claim esté dentro del JWT firmado por el emisor: modelan un emisor con errores o malicioso, no un holder.

Aceptaciones indebidas que el holder puede provocar:

| Caso | Crate(s) | Qué pasa | Sección |
|---|---|---|---|
| `T12`, `T13`, `T26` | sdjwt, sd-jwt-rs | Disclosure alterada, ajena o re-serializada: aceptan la presentación e ignoran la Disclosure. El valor falso **no** llega al payload, pero el RFC exige rechazar (paso 5). `T12` es control negativo: falla en estos dos crates | 9901 §7.1 paso 5, §9.2 |
| `T01` | affinidi, sd-jwt-rs | Sin la tilde final: aceptan. sd-jwt-rs toma la última Disclosure como KB-JWT y la descarta sin aviso (`nationalities` queda `["DE"]`) | 9901 §4 |
| `T02` | sd-jwt-payload, affinidi, sd-jwt-rs | El Verifier espera SD-JWT y llega SD-JWT+KB: aceptan e ignoran el KB-JWT. El RFC exige que el último componente esté vacío | 9901 §4 |
| `T03` | affinidi | Disclosure vacía (`~~`): acepta | 9901 §4 |
| `K10`, `K11`, `K15` | sd-jwt-rs | No mira `iat` del KB-JWT: acepta uno de hace un día, uno sin `iat` y uno de dentro de una hora. Sólo `nonce` limita el replay | 9901 §4.3, §7.3 paso 5e |

Aceptaciones indebidas con payload firmado por el emisor:

- **sdjwt**: no detecta digests repetidos (`T14`–`T16`); acepta nombres `_sd` y `...` (`T19`, `T20`); deja que una Disclosure **pise un claim en claro**: en `T21` el payload procesado sale con `iss` = `https://attacker.example`; con dos Disclosures del mismo nombre gana la última (`T22`, `given_name` = `Eva`); con un nombre numérico inserta la clave `""` (`T25`); no valida `nbf` (`T28`).
- **sd-jwt-rs**: una Disclosure de tres elementos referida desde un array mete **el nombre del claim** como valor (`T17`: `nationalities` = `["given_name"]`); con nombre `_sd` deja un `_sd` en el payload de salida (`T19`); acepta `...` (`T20`) y Disclosures de cuatro elementos (`T24`); no valida `nbf` (`T28`); con una Disclosure de dos elementos referida desde `_sd` entra en **pánico** (`T18`, índice fuera de rango en `src/verifier.rs`). Un probe exploratorio posterior (`examples/panic_probe.rs`) muestra que con Disclosures no referenciadas no hay pánico: hace falta el digest firmado.
- **sd-jwt-payload**: acepta el nombre `...` (`T20`) y un `_sd_alg` desconocido (`T23`; el crate recibe el hasher del integrador y no lo compara con `_sd_alg`); no valida `exp`/`nbf` (`T27`–`T29`).
- **affinidi-sd-jwt**: no valida `exp`/`nbf` (`T27`–`T29`). En los dos crates que delegan el JWS se puede discutir que eso sea tarea del integrador; el RFC lo pone en el paso 6 del Verifier, y se cuenta.

Rechazos espurios y payload distinto:

- **sdjwt** exige `_sd_alg` aunque el RFC define `sha-256` por defecto (`V06`) y exige KB-JWT si hay `cnf` aunque la política no pida Key Binding (`V14`; el RFC dice que esa decisión no puede depender de lo que manda el holder). Invierte el orden de los arrays con elementos divulgados (`nationalities` sale `["DE","US"]` en `V01`, `V04`, `V05`, `V07`, `V09`) y **pierde** claims divulgados dentro de Disclosures de elementos de array (`V15`: falta `city`; `V18`: falta `"X"`), sin rechazar.
- **sd-jwt-payload** deja `_sd` con decoys en un objeto que no tuvo Disclosures (`V21`); el RFC dice que se quitan todas las claves `_sd`.

**bh-sd-jwt** coincide con el RFC en los 66 casos puntuados, controles incluidos, y es el único que rechaza los 6 casos abiertos (entre ellos `_sd_alg` anidado, `P03`).

Casos abiertos que dividen: `P01` (misma Disclosure dos veces: sd-jwt-payload y sdjwt aceptan; el RFC sólo le prohíbe al holder mandarla), `P02` (salt numérico), `P03` (`_sd_alg` anidado), `P04` (`aud` en array: sd-jwt-rs acepta), `P05` (`_sd` que no es array).

### Criterios de aceptación (handoff)

| Criterio | Estado |
|---|---|
| ≥40 casos borde de RFC 9901 | **Cumplido**: 66 puntuables + 6 abiertos |
| Contra ≥4 crates (sd-jwt-payload, affinidi-sd-jwt, bh-sd-jwt, sdjwt) | **Cumplido**: los cuatro nombrados más sd-jwt-rs. Con salvedades: sd-jwt-payload y affinidi delegan partes (no puntuadas) y sdjwt no corre Key Binding con P-256 |
| Matriz de divergencias CSV con repro mínimo | **Cumplido**: `results/matrix.csv`, columna `repro` con la presentación exacta |
| Casos maliciosos que todos deben rechazar como control | **No cumplido para sdjwt y sd-jwt-rs**: aceptan `T12` (Disclosure alterada, sin que el valor falso llegue al payload). `T07`–`T09` los rechazan todos los que los corren |

### Nivel de verificación

- **A**: compila, `cargo fmt --check` y `clippy --all-targets -D warnings` limpios, 15/15 tests, ninguno ignorado.
- **B**: medición prerregistrada, reproducible y determinista, con controles positivos y negativos, y un control del control (una implementación que acepta todo falla los cuatro negativos). La referencia coincide con la expectativa en los 66 casos puntuables y reproduce los vectores de §4.2.1 y §4.2.3.
- No B+/C: no hay línea base de rendimiento ni uso real; los hallazgos no los confirmó ningún mantenedor.

### Límites

- Sólo serialización compacta (sin JSON de §8), sólo ES256 y `sha-256`, una sola clave de emisor conocida (sin búsqueda de claves ni `x5c`).
- El corpus usa la forma SD-JWT VC para que `bh-sd-jwt` lo acepte; no se prueban reglas propias de SD-JWT VC.
- Las celdas delegadas miden el código del arnés, no el del crate, y por eso no se puntúan; quien use esos crates tiene que hacer esas partes bien por su cuenta.
- Casos escritos a mano, sin fuzzing. Los hallazgos no se reportaron a los mantenedores (lo decide Federico).
- La interpretación de `T02` (§4: "A Verifier that expects an SD-JWT MUST verify that the final tilde-separated component is empty") y de `T27`–`T29` para crates que delegan el JWS está explicada arriba; quien lea distinto puede recalcular desde `results/matrix.csv`.

### Fuentes leídas

- RFC 9901: §4, §4.1.1, §4.1.2, §4.2.1–§4.2.5, §4.3, §4.3.1, §4.3.2, §7.1–§7.3, §9.1–§9.4, §9.7 — <https://www.rfc-editor.org/rfc/rfc9901.txt>
- Metadatos de crates.io (API) de los cinco crates y su código fuente publicado en las versiones fijadas, más el README de `sdjwt` 0.8.1 y el ejemplo `sd_jwt_vc_e2e.rs` de `bh-sd-jwt` 0.7.1.

---

## EN

**What:** 72 hand-written RFC 9901 cases (21 valid, 29 tampered or malformed, 16 Key Binding, 6 open points not scored) run through `sd-jwt-payload` 0.5.1, `affinidi-sd-jwt` 0.1.8, `bh-sd-jwt` 0.7.1, `sdjwt` 0.8.1, `sd-jwt-rs` 0.7.1 and a reference verifier written from RFC 9901 §4, §4.3, §7.1 and §7.3. Parts a crate leaves to the integrator by design (JWS verification in sd-jwt-payload and affinidi, Key Binding in sd-jwt-payload) are supplied by the harness and not scored; sdjwt only supports RSA `cnf` keys, so its Key Binding cases are marked unsupported.

**Results** (deterministic; two runs and a clean clone were byte-identical):

| | reference | sd-jwt-payload | affinidi-sd-jwt | bh-sd-jwt | sdjwt | sd-jwt-rs |
|---|---|---|---|---|---|---|
| Scored | 66 | 42 | 58 | 66 | 47 | 66 |
| Agree with RFC | 66 | 36 | 52 | 66 | 33 | 53 |
| Spurious rejections | 0 | 0 | 0 | 0 | 2 | 0 |
| Undue acceptances | 0 | 6 | 6 | 0 | 12 | 13 |
| Processed payload differs | 0 | 1 | 0 | 0 | 7 | 0 |
| Panics | 0 | 0 | 0 | 0 | 0 | 1 |
| Controls OK | 6/6 | 2/2 | 3/3 | 6/6 | 4/5 | 5/6 |

30/72 cases divergent.

**Notable:**
- Holder-reachable: sdjwt and sd-jwt-rs accept presentations carrying altered, foreign or re-serialized Disclosures and silently drop them (T12, T13, T26; T12 is a negative control). The forged value does not reach the payload, but §7.1 step 5 requires rejection.
- affinidi and sd-jwt-rs accept a presentation without the final `~`. sd-jwt-rs drops the last Disclosure as a fake KB-JWT.
- Three crates accept SD-JWT+KB where an SD-JWT was expected (T02).
- sd-jwt-rs never checks KB-JWT `iat` (K10, K11, K15).
- Issuer-signed malformed input:
  - sdjwt lets a Disclosure override a plaintext claim (T21, `iss` becomes the attacker's) and keeps the last of two same-name Disclosures (T22).
  - sd-jwt-rs puts the claim *name* into an array slot (T17) and panics on a two-element Disclosure referenced from `_sd` (T18). A post-hoc probe shows this is not reachable with unreferenced Disclosures.
- sdjwt reorders arrays and loses claims nested in array-element Disclosures (V15, V18) without rejecting.
- bh-sd-jwt matches the RFC on all 66 scored cases.

**Acceptance criteria:**
- ≥40 cases: met.
- ≥4 named crates: met, with the delegation caveats above.
- CSV with minimal repro: met.
- All must reject the malicious controls: **not met** for sdjwt and sd-jwt-rs (T12).

**Verification level: B.**

**Limits:**
- Compact serialization only.
- ES256 and sha-256 only, with a single known issuer key.
- SD-JWT VC shape used only to satisfy bh-sd-jwt.
- No fuzzing, and findings were not reported upstream.

## License

Apache-2.0
