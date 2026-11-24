# Alcance y correspondencia con el PDF

Documento rector: `../Modelo_mineria_datos.pdf`, Laboratorio 1, 19 de noviembre de 2026.
Este avance desarrolla las secciones **7.1–7.5 (SEMMA)** y prepara el modelo para su
integración posterior. La sección 8 (herramienta CLI) queda fuera del alcance acordado.
La fecha de entrega indicada por el PDF es 26 de noviembre de 2026.

| Sección y páginas | Exigencia del PDF | Evidencia de este avance |
|---|---|---|
| 4, pp. 3–4 | Dos estándares y múltiples etiquetas; abstención sin evidencia | Catálogo de 20 categorías; One-vs-Rest multietiqueta; `src/mining.py` |
| 7.1, pp. 5–6 | ≥500 registros, ≥100 no vulnerables, procedencia, diccionario, CWE–OWASP | Dataset, manifiesto fijado por commit, `diccionario_datos.md`, `cwe_owasp.csv` |
| 7.1, pp. 5–6 | Entrenamiento/validación/prueba independientes, recomendación 70/15/15 | Particiones por grupos de clones, semilla fija; auditoría y proporciones reales |
| 7.2, pp. 6–7 | Distribuciones, faltantes, duplicados, gráficos interpretados | Notebook 02; tablas y PNG en `results/`; informe generado |
| 7.3, pp. 7–8 | Limpieza, etiquetas, tokenización, características, balance y matrices | `src/common.py`, `src/dataset.py`, `src/experiment.py:modify`; matrices NPZ y objetivos NPY |
| 7.4, pp. 8–9 | ≥2 algoritmos, hiperparámetros, comparación y serialización | Regresión Logística y Random Forest, búsqueda en validación, pipeline guardado |
| 7.5, pp. 9–10 | Precision, recall, F1, F1 macro, errores, matrices y evaluación por categoría | Notebook 05; comparación, predicciones, errores y resultados por fuente/lenguaje |
| 7.5, actividad 7, p. 9 | Pruebas funcionales en proyectos de microservicios no usados al entrenar | **Pendiente** hasta implementar la CLI; no se sustituye por evaluar fragmentos |
| 8, pp. 10–13 | Descubrimiento, ubicación, análisis de repositorios y reportes JSON/HTML de hallazgos | **Pendiente**, fuera de este avance |
| 9, p. 14 | Informe, notebooks, modelo y dataset | Entregables parciales en esta carpeta; informe enfocado en SEMMA |

## Límites de cumplimiento

El conjunto cubre experimentalmente cinco categorías Top 10:2025 y cinco API:2023.
Esto **no acredita la demostración funcional** de cinco y cuatro categorías exigida en
§6 y §10.1: esa aceptación requiere ejecutar la herramienta sobre un repositorio.
Las otras diez categorías figuran como `no_evaluada`, no como ausencia de riesgo.

Benchmark aporta Java; los casos controlados aportan Python y configuraciones de API.
No se ha implementado todavía soporte de análisis de repositorios en esos lenguajes.
Las etiquetas seguras se refieren a la debilidad objetivo, no certifican todo el programa.
Las etiquetas de API requieren revisión humana; su soporte de prueba es pequeño.

El agrupamiento evita dividir clones detectados por una heurística de similitud y
variantes estructurales exactas. No prueba ausencia de todo clon semántico. Los casos
Java proceden de un mismo proyecto Benchmark: el test retenido mide generalización
interna. La generalización a proyectos reales externos continúa sin demostrar.

El PDF sugiere separación por proyecto cuando corresponda. Se separan las familias de
implementación de casos controlados, y se agrupan clones de Benchmark dentro de su
único proyecto. No se presenta este procedimiento como evaluación entre proyectos.

El núcleo usa clasificadores supervisados entrenados; no llama a LLM ni asigna las
predicciones mediante reglas de búsqueda. La correspondencia CWE–OWASP se usa para
etiquetar el dataset, no como entrada del modelo ni como regla de inferencia.
