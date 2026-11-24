# Diccionario de datos

Archivo principal: `data/processed/dataset.csv`, UTF-8 y CSV con campos multilínea
entrecomillados. Una fila representa un fragmento y su contexto de etiquetado.

| Columna | Tipo | Significado |
|---|---|---|
| record_id | texto | Identificador estable del caso de origen |
| code | texto | Fragmento sin comentarios ni IDs de Benchmark; única entrada del clasificador |
| language | texto | Java o Python |
| artifact_type | texto | source o configuration |
| source | texto | OWASP Benchmark Java 1.2 o controlled |
| project | texto | Proyecto original o familia controlada |
| source_url | texto | URL fijada por commit o ruta al generador local |
| source_revision | texto | Commit público o hash del fragmento controlado |
| license | texto | GPL-2.0-only o CC0-1.0 según procedencia |
| scenario | texto | Tipo de prueba o escenario; no se usa como característica |
| cwe | texto | Debilidad objetivo, también en casos mitigados para conservar el contexto |
| vulnerable | entero | 1: presenta la debilidad objetivo; 0: mitigada/no presente según la fuente |
| labels | array JSON en texto | Categorías aplicables a un caso vulnerable; [] para mitigados |
| group | texto | Grupo de clones/familia que no se divide entre particiones |
| split | texto | train, validation o test |
| label_basis | texto | Evidencia y criterio del etiquetado |
| review_status | texto | Estado de revisión de las etiquetas; no representa vulnerabilidad confirmada |
| code_hash | texto | SHA-256 del fragmento normalizado |

`cwe`, `scenario`, `labels`, `vulnerable`, `project`, identificadores y procedencia no
son entradas del vectorizador. Los casos mitigados conservan CWE como riesgo objetivo,
pero nunca reciben categorías positivas de vulnerabilidad por esa sola presencia.

Archivos complementarios:

- `partitions.csv`: ID, grupo, hash, fuente y partición de cada registro.
- `catalogo_owasp.json`: veinte categorías y estado experimental de cobertura.
- `excluded_conflicts.csv`: posibles textos duplicados con etiquetas incompatibles.
- `X_*.npz`: matrices TF-IDF dispersas de train, validation y test.
- `y_*.npy`: objetivos binarios/multietiqueta en el orden de `models/metadata.json`.
- `feature_names.csv`: vocabulario, en el mismo orden de columnas de X.

No hay una etiqueta artificial `seguro` dentro del catálogo OWASP. La ausencia de
etiquetas positivas se modela junto con un objetivo binario separado de vulnerabilidad.
