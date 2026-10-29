# Prerregistro / Pre-registration

Escrito y commiteado antes de la primera corrida completa de la matriz contra
los crates. Antes de este commit sólo se ejecutaron los controles positivos
`V01` y `V12` para comprobar que cada adaptador compila y acepta un SD-JWT
correcto. Written and committed before the first full matrix run; only the
positive controls V01 and V12 were run before, to debug the adapters.

Comando / command:

```sh
cargo run --release --bin sdjwt-diff -- --csv results/matrix.csv \
  --details results/details.csv --json results/summary.json
```

## Implementaciones / implementations

| Crate | Versión | Entrada usada | Delegado al integrador |
|---|---|---|---|
| `sd-jwt-payload` | 0.5.1 | `SdJwt::parse` + `into_disclosed_object(&Sha256Hasher)` | firma del emisor (la hace el adaptador); no verifica KB-JWT |
| `affinidi-sd-jwt` | 0.1.8 | `SdJwt::parse` + `verifier::verify` / `verify_with_kb_freshness` | verificación JWS (`JwtVerifier`) del emisor y del holder |
| `bh-sd-jwt` | 0.7.1 | `NoHolderBindingVerifier::verify` / `Verifier::verify` con `Es256Verifier` | — |
| `sdjwt` | 0.8.1 | `Verifier::verify` con `KeyForDecoding::from_ec_pem` | — (KB sólo con `cnf` RSA: casos KB no soportados) |
| `sd-jwt-rs` | 0.7.1 | `SDJWTVerifier::new` con callback de clave, `Compact` | — |
| `reference` (este repo) | — | escrita desde RFC 9901 §4, §4.3, §7.1, §7.3 | — |

Celdas `delegated` (la parte la provee el arnés por diseño del crate) y
`unsupported` (el crate no puede correr el caso) no se puntúan.

## Política fija del Verifier / fixed verifier policy

- Clave del emisor conocida (P-256, ES256); sólo se acepta `alg: ES256`.
- `_sd_alg` aceptado: `sha-256` o ausente (default de §4.1.1).
- `NOW = T0 + 30` para las bibliotecas que reciben la hora; las que usan el
  reloj del sistema ven `exp` en 2100, así que no cambia el veredicto.
- Ventana de `iat` del KB-JWT: `[NOW - 300, NOW + 60]`.
- `aud` esperado `https://verifier.example`, `nonce` esperado `n-0S6_WzA2Mj`.
- Cada caso fija si el Verifier espera SD-JWT o SD-JWT+KB (§7.3 paso 1).

## Corpus

72 casos: 21 válidos (`V*`, el RFC acepta), 29 alterados o mal formados
(`T*`, el RFC rechaza), 16 de Key Binding (`K*`, el RFC rechaza) y 6 abiertos
(`P*`, el texto no decide la respuesta del Verifier; se reportan, no se
puntúan). Puntuables: 66 (mínimo del handoff: 40).

## Métricas

| Id | Métrica | Definición |
|---|---|---|
| D1 | Divergencias | casos donde las implementaciones que lo corren no dan el mismo veredicto |
| D2 | Rechazos espurios | casos `accept` que el crate rechaza |
| D3 | Aceptaciones indebidas | casos `reject` que el crate acepta |
| D4 | Payload distinto | casos `accept` aceptados con payload procesado distinto al de la referencia (se ignora sólo `_sd_alg` de primer nivel) |
| D5 | Pánicos | casos donde el crate entra en pánico (cuenta como rechazo para D2/D3) |

## Controles

- Positivos (todos deben aceptar): `V01` (SD-JWT base) y `V12` (SD-JWT+KB base).
- Negativos (todos deben rechazar): `T07` (alg none), `T08` (otra clave),
  `T09` (payload alterado tras firmar), `T12` (Disclosure alterada por el holder).
- Control del control: una implementación que acepta todo tiene que fallar los
  cuatro negativos (test `a_verifier_that_skips_checks_is_caught_by_the_negative_controls`).
- La referencia tiene que coincidir con la expectativa de los 66 casos puntuables
  (test `reference_matches_every_scored_expectation`).

## Criterio del handoff

">=40 casos borde RFC 9901 contra >=4 crates (sd-jwt-payload, affinidi-sd-jwt,
bh-sd-jwt, sdjwt); matriz de divergencias CSV con repro minimo; casos
maliciosos que todos deben rechazar como control". Se considera cumplido si:
66 >= 40 casos puntuables, los 4 crates nombrados corren, el CSV tiene una
columna `repro` con la presentación exacta de cada caso, y los cuatro
negativos son rechazados por todo crate que los corre. Si un control negativo
es aceptado por algún crate, eso se reporta como hallazgo y el criterio de
controles queda no cumplido para ese crate.

## Repetición

Dos corridas en esta máquina y una en un clon limpio; el resultado tiene que
ser idéntico byte a byte (las firmas ES256 son deterministas por RFC 6979).
