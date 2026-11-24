"""Generate a Spanish technical report from actual saved experiment outputs."""
import json
from .common import ROOT
import pandas as pd


def table(frame):
    frame = frame.copy()
    for col in frame.select_dtypes('number'):
        frame[col] = frame[col].map(lambda x: f'{x:.4f}' if isinstance(x, float) else str(x))
    rows = [[str(x).replace('|', '/').replace('\n', ' ') for x in row] for row in frame.itertuples(index=False, name=None)]
    return '\n'.join(['| ' + ' | '.join(frame.columns) + ' |', '| ' + ' | '.join(['---'] * len(frame.columns)) + ' |'] + ['| ' + ' | '.join(row) + ' |' for row in rows])


def build_report():
    result = ROOT / 'results'
    audit = json.loads((result / 'sample_audit.json').read_text(encoding='utf-8'))
    selection = json.loads((result / 'model_selection.json').read_text(encoding='utf-8'))
    modify = json.loads((result / 'modify_audit.json').read_text(encoding='utf-8'))
    comparison = pd.read_csv(result / 'model_comparison.csv')
    family = selection['family']
    row = comparison[comparison.family == family].iloc[0]
    category = pd.read_csv(result / f'{family}_por_categoria.csv')
    category = category[category.categoria.str.match(r'^(A\d\d:2025|API\d+:2023)$')]
    by_source = pd.read_csv(result / f'{family}_por_fuente_lenguaje.csv')
    errors = pd.read_csv(result / f'{family}_errores.csv', keep_default_na=False)
    preds = pd.read_csv(result / f'{family}_test_predictions.csv')
    fp = preds[(preds.true_vulnerable == 0) & (preds.predicted_vulnerable == 1)]
    fn = preds[(preds.true_vulnerable == 1) & (preds.predicted_vulnerable == 0)]
    pending = int(preds.status.eq('pendiente_revision').sum())
    sample = pd.read_csv(ROOT / 'data/processed/dataset.csv')
    partitions = pd.crosstab(sample.split, sample.vulnerable).reset_index()
    partitions.columns = ['partición', 'no vulnerable objetivo', 'vulnerable']
    partitions['porcentaje'] = partitions.iloc[:, 1:3].sum(axis=1) / len(sample) * 100
    catalog = json.loads((ROOT / 'data/processed/catalogo_owasp.json').read_text(encoding='utf-8'))
    unsupported = ', '.join(c['id'] for c in catalog if c['estado'] == 'no_evaluada')
    error_examples = []
    chosen = pd.concat([
        errors[(errors.true_vulnerable == 0) & (errors.predicted_vulnerable == 1)].head(1),
        errors[(errors.true_vulnerable == 1) & (errors.predicted_vulnerable == 0)].head(1),
        errors[errors.source == 'controlled'].head(2),
    ]).drop_duplicates('record_id')
    for record in chosen.to_dict('records'):
        explanation = (
            'Hipótesis: el vocabulario de la operación peligrosa pesa más que la mitigación o la ruta de datos efectiva. La etiqueta de Benchmark corresponde únicamente a la CWE objetivo.'
            if record['source'] != 'controlled' else
            'Hipótesis: hay poco soporte de entrenamiento para este escenario y la representación textual no modela de forma fiable las guardas, propiedades permitidas ni contratos externos.')
        error_examples.append(f"### Caso {record['record_id']}\n\nFuente: {record['source']}. "
                              f"Real binario: {record['true_vulnerable']}; predicho: {record['predicted_vulnerable']}. "
                              f"FP de etiquetas: `{record['false_positive_labels']}`; FN: `{record['false_negative_labels']}`.\n\n"
                              f"```{record['language'].lower()}\n{record['code']}\n```\n\n{explanation}\n\nProcedencia: {record['source_url']}")
    sources = table(pd.DataFrame(audit['sources'].items(), columns=['fuente', 'registros']))
    metrics = table(comparison[['family', 'candidate', 'threshold', 'train_category_f1_macro', 'validation_category_f1_macro',
                                'test_category_f1_macro', 'test_binary_precision', 'test_binary_recall', 'test_binary_f1']])
    text = f'''# Informe técnico del avance SEMMA

## Problema y alcance

Clasificar posibles debilidades en fragmentos de código y configuraciones de servicios,
siguiendo las secciones 7.1–7.5 del PDF `Modelo_mineria_datos.pdf`. El resultado de este
avance es un dataset trazable, análisis exploratorio, un pipeline de características,
dos algoritmos comparados y un modelo serializado evaluado con datos retenidos.
La integración CLI y su demostración sobre un proyecto desconocido quedan pendientes.

La clasificación es binaria y multietiqueta: un fragmento puede asociarse a ambos
estándares. El catálogo contiene las veinte categorías del PDF; diez tienen evidencia
experimental en este dataset y diez están declaradas como no evaluadas.

## Sample — §7.1

Se obtuvieron **{audit['records']} fragmentos únicos**, {audit['safe_targeted']} no vulnerables
a la debilidad objetivo y {audit['vulnerable']} vulnerables. Se supera el mínimo del PDF
de 500 registros y 100 ejemplos no vulnerables. Se eliminaron {audit['duplicates_removed']}
duplicados exactos tras la limpieza; se excluyeron {audit['conflicting_records_excluded']}
registros con conflicto de etiquetas. No se reutilizó el CSV original de los talleres.

{sources}

Se usan {audit['languages']['Java']} casos Java y {audit['languages']['Python']} Python.
Las fuentes, licencias y contratos están en `fuentes.md`; el diccionario y la tabla
CWE–OWASP son entregables separados. Las etiquetas de Benchmark son su resultado esperado,
no una auditoría propia. Los casos controlados necesitan revisión humana.

### Particiones

{table(partitions)}

Se mantienen **{audit['groups']} grupos** sin intersección entre particiones. Se agrupan
clones por estructura normalizada y componentes de similitud coseno de caracteres ≥0,90,
sin usar etiquetas para agrupar. Se usa una sola partición por grupos con semillas fijas;
el porcentaje efectivo varía porque no se rompen grupos para forzar 70/15/15.
Este control reduce filtraciones por duplicación; no garantiza independencia semántica.
Benchmark es un solo proyecto, de modo que el test Java mide generalización interna.

## Explore — §7.2

Los gráficos de `results/por_categoria.png`, `por_clase.png`, `por_lenguaje.png`,
`por_fuente.png`, `por_artefacto.png`, `longitudes.png` y `patrones.png` documentan la exploración.
Las tablas correspondientes permiten comprobar recuentos y longitudes. No se encontraron
faltantes en los campos obligatorios después de preparar el conjunto.

El equilibrio aproximado de la etiqueta binaria no implica equilibrio por categoría.
Las etiquetas API tienen siete positivos y siete negativos por escenario en todo el
dataset; solo **un positivo y un negativo de cada escenario** están en test. El dominio
Java y Benchmark domina la muestra. Las categorías agrupan distintas CWE y su frecuencia
no puede interpretarse como prevalencia de riesgos en software real.

Las longitudes son muy diferentes entre funciones Python pequeñas y métodos Java de
servlets. Los tokens frecuentes incluyen sintaxis y bibliotecas; no son por sí mismos
evidencia causal de una vulnerabilidad. Estas diferencias justifican informar resultados
por fuente y lenguaje, además del promedio global.

## Modify — §7.3

Se retiraron comentarios, identificadores de Benchmark y rutas de `doGet` que podían
revelar la etiqueta. Se conservaron literales de código relevantes y helpers de prueba
referidos. Se tokenizan identificadores, números, símbolos y operadores, generando TF-IDF
de unigramas y bigramas con `min_df=2`, `sublinear_tf=True` y máximo 18.000 características.
El vocabulario efectivo es **{modify['vocabulary_size']}**.

El vectorizador de clasificación se ajustó solo con train; validation y test se transforman
con ese vocabulario congelado. Este vectorizador es distinto al usado para agrupar clones.
Ninguna etiqueta, CWE, ruta de origen o nombre del escenario entra como característica.
Las matrices dispersas y los objetivos se guardan en `data/processed/`.

Se usa `class_weight=balanced` en los problemas binarios One-vs-Rest, sin sobremuestrear
los conjuntos retenidos. El texto permite capturar patrones de consultas, algoritmos,
autenticación y configuraciones, pero no sustituye análisis de flujo ni de dependencias.

## Model — §7.4

Se compararon Regresión Logística (`C=0.5` y `C=2`) y Random Forest (100 árboles sin
límite de profundidad y hoja mínima 2; 150 árboles con profundidad 20 y hoja mínima 1).
Ambos usan One-vs-Rest sobre el objetivo vulnerable y las diez categorías respaldadas.
Se probaron umbrales 0,30, 0,40, 0,50, 0,60 y 0,70 en validación.

Se eligió **{selection['candidate']}**, umbral **{selection['threshold']:.2f}**, por mayor
F1 macro de categorías en validación: **{selection['validation_category_f1_macro']:.4f}**.
F1 binario y tiempo resuelven empates. El modelo se congeló antes de examinar test;
no se reentrenó con validación. La selección no se modifica si otro algoritmo obtiene
una métrica de test mejor. `validation_search.csv` conserva todas las configuraciones.

`models/modelo_seleccionado.joblib` incluye TF-IDF, clasificadores, catálogo y umbral.
Los scores son salidas sin calibrar, no niveles de severidad. Un caso binario positivo
sin categoría suficiente o cercano al umbral queda pendiente de revisión; no se fuerza
una categoría. Las etiquetas emitidas se consideran potenciales y requieren verificación.

## Assess — §7.5

{metrics}

En test, el modelo seleccionado obtuvo F1 binario **{row.test_binary_f1:.4f}** y F1 macro
de categorías **{row.test_category_f1_macro:.4f}**. El promedio macro corresponde a las
diez categorías con datos, **no a todo el catálogo de veinte**. Las categorías no evaluadas
no se incorporan como ceros artificiales ni se presentan como cobertura conseguida.
También se exportan F1 micro, precision/recall macro, Hamming loss y exactitud de conjuntos.

La diferencia train–validación del F1 macro es
**{row.train_category_f1_macro - row.validation_category_f1_macro:.4f}**. Esta diferencia y
el resultado de test ayudan a examinar el sobreajuste, pero no permiten descartarlo en
otros proyectos. En cada etiqueta, la matriz 2×2 usa filas reales y columnas predichas:
`[[TN, FP], [FN, TP]]`. El gating y la abstención de categorías forman parte de la evaluación;
el objetivo binario conserva su decisión por umbral aun cuando el estado sea pendiente.

### Métricas por categoría

{table(category)}

### Resultados por fuente y lenguaje

{table(by_source[['grouping', 'group', 'n', 'binary_precision', 'binary_recall', 'binary_f1', 'f1_macro_supported_labels']])}

En este desglose, `f1_macro_supported_labels` promedia únicamente etiquetas con positivos
en el subconjunto; los CSV conservan también el macro sobre el conjunto fijo de etiquetas
para que ambos promedios sean auditables. No se deben comparar promedios con distinto
conjunto de etiquetas sin considerar ese detalle.

### Falsos positivos, falsos negativos y abstenciones

Se observaron **{len(fp)} falsos positivos binarios** y **{len(fn)} falsos negativos binarios**.
Hay **{len(errors)} registros con al menos un error binario o de categoría** y
**{pending} registros con estado pendiente de revisión**. Los CSV `*_errores.csv` incluyen
el fragmento completo, etiquetas, procedencia y la necesidad de revisión. Los CSV de
predicciones permiten reconstruir las métricas. No observar un falso negativo en una
muestra no demuestra que el detector no pueda omitir vulnerabilidades.

{chr(10).join(error_examples)}

## Limitaciones y mejoras

1. Los ejemplos API son pocos y controlados. Un caso adicional puede cambiar mucho el
   recall de una categoría. Ampliar fuentes, revisar etiquetas y evaluar proyectos externos
   antes de afirmar detección confiable de autorización o autenticación.
2. Benchmark y los casos controlados no reflejan la diversidad de microservicios reales.
   Separar por repositorios independientes y añadir contextos interprocedimentales es la
   siguiente evaluación necesaria; no se infiere generalización a partir de este test.
3. TF-IDF aprende correlaciones textuales. Puede confundir una llamada peligrosa con una
   vulnerabilidad o ignorar validaciones; agregar características sintácticas y de flujo como
   complemento, conservando la contribución del modelo entrenado.
4. Los scores no están calibrados y el umbral se ajustó con pocos casos API. Ampliar la
   validación, estudiar calibración y analizar compromisos precision–recall sin ajustar test.
5. Categorías no evaluadas: {unsupported}. Su ausencia de hallazgos nunca equivale a
   ausencia de vulnerabilidades.

## Entregables y pendiente de integración

El avance entrega dataset, diccionario, fuentes, correspondencias CWE–OWASP, cinco
notebooks ejecutables, matrices, entrenamiento reproducible, comparación experimental,
modelos serializados y evaluación con evidencia de errores. La actividad 7 de Assess
(pruebas funcionales sobre microservicios desconocidos) y la sección 8 (CLI, descubrimiento,
líneas y reportes JSON/HTML de seguridad) continúan pendientes. Los JSON de métricas de
este avance no se presentan como reportes de hallazgos de una CLI.

El resultado respalda una base experimental para integrar un detector de hallazgos
potenciales. La validación disponible no respalda desplegarlo como certificador de seguridad.
'''
    (ROOT / 'docs/informe_semma.md').write_text(text, encoding='utf-8')
    print('Report generated from actual saved results.')
    return text
