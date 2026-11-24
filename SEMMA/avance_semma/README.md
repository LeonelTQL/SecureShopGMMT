# Avance SEMMA — Modelo de minería de datos

Desarrollo de las fases **Sample, Explore, Modify, Model y Assess**, siguiendo
las secciones **7.1–7.5 de `Modelo_mineria_datos.pdf`**. Los talleres originales
permanecen intactos. La correspondencia detallada con el PDF está en
[docs/alcance_pdf.md](docs/alcance_pdf.md).

El avance entrega preparación de datos, análisis, entrenamiento y evaluación del modelo.
**Queda pendiente** la actividad de Assess que requiere ejecutar la futura CLI sobre
proyectos de microservicios desconocidos, junto con la integración de la sección 8.

## Contenido

| Entregable del PDF | Ubicación |
|---|---|
| Dataset etiquetado | [data/processed/dataset.csv](data/processed/dataset.csv) |
| Diccionario de datos | [docs/diccionario_datos.md](docs/diccionario_datos.md) |
| Fuentes, muestreo, licencias y supuestos | [docs/fuentes.md](docs/fuentes.md) |
| Correspondencias CWE–OWASP | [docs/cwe_owasp.csv](docs/cwe_owasp.csv) |
| Cinco notebooks por fase | [notebooks/](notebooks/) |
| Scripts de preparación y entrenamiento | [src/](src/) |
| Matrices y particiones | [data/processed/](data/processed/) |
| Modelo y preprocesamiento serializados | [models/](models/) |
| Comparación experimental | [results/model_comparison.csv](results/model_comparison.csv) |
| Tablas, gráficos y errores con evidencia | [results/](results/) |
| Informe técnico con resultados reales | [docs/informe_semma.md](docs/informe_semma.md) |
| Comprobaciones automáticas | [results/verification.json](results/verification.json) |

## Datos y cobertura

- 2.680 fragmentos únicos: 1.367 vulnerables y 1.313 no vulnerables al riesgo objetivo.
- Java: 2.610 pruebas de OWASP Benchmark Java 1.2, con etiquetas oficiales y commit fijado.
- Python: 70 casos controlados, incluidos fragmentos de configuración, pendientes de revisión humana.
- Partición por grupos de clones: 2.001 train, 338 validation y 341 test. La recomendación
  70/15/15 se aproxima sin romper grupos; las proporciones efectivas son 74,66/12,61/12,72 %.
- Catálogo completo de veinte categorías. Hay datos para A01, A02, A04, A05 y A07 de 2025;
  API1, API2, API3, API5 y API8 de 2023. Las demás se declaran no evaluadas.

El volumen y las etiquetas no demuestran cobertura funcional de repositorios. Las
categorías API tienen poco soporte y solo un positivo y un negativo por escenario en test.
Benchmark es una suite construida, no software representativo de producción. La evaluación
entre proyectos reales y la demostración CLI siguen pendientes.

## Reproducir

Entorno usado: Python 3.14.6 en Windows. Las versiones exactas están en
`requirements-lock.txt`; los artefactos guardados requieren un entorno compatible.
`requirements.txt` permite instalar y volver a entrenar en otros entornos compatibles.

Desde esta carpeta, el entorno `.venv` ya está preparado localmente. Para recrearlo,
usar un ejecutable Python instalado y ejecutar `python -m venv .venv`, luego:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-lock.txt
.\.venv\Scripts\python.exe fetch_data.py
.\.venv\Scripts\python.exe run.py
```

`fetch_data.py` descarga la versión fijada de Benchmark si falta el ZIP y verifica su
SHA-256. El ZIP ocupa unos 18 MB y queda excluido de Git; el dataset procesado, las
etiquetas oficiales, el manifiesto y la licencia se conservan como entregables.
`run.py` reconstruye las cinco fases y el informe; no analiza repositorios ni abre servicios.

Para reproducir y guardar además las salidas de los notebooks, ejecutar **en lugar de
`run.py`**:

```powershell
.\.venv\Scripts\python.exe build_notebooks.py
.\.venv\Scripts\python.exe execute_notebooks.py
.\.venv\Scripts\python.exe verify.py
```

La ejecución secuencial de los notebooks reproduce las cinco fases y el informe.
También pueden abrirse en VS Code/Jupyter con el intérprete de `.venv`, ejecutándolos
en orden. Se usan procesos locales de kernel; los fragmentos vulnerables del dataset
se procesan exclusivamente como texto.

## Usar el modelo sin entrenarlo otra vez

Desde `avance_semma`, con el mismo entorno:

```python
import joblib

model = joblib.load('models/modelo_seleccionado.joblib')
result = model.predict(["app = FastAPI(debug=True)"])
print(result)
```

La entrada es una lista de fragmentos, no una ruta de repositorio. La salida distingue
hallazgo potencial, pendiente de revisión y ausencia de evidencia del modelo; esta última
no certifica seguridad. Los scores no están calibrados y no equivalen a severidad.
El archivo contiene TF-IDF y clasificadores entrenados: la inferencia no ejecuta `fit`.
Los archivos `joblib` deben proceder de una fuente confiable.

## Criterio experimental

Se comparan Regresión Logística y Random Forest con dos configuraciones por algoritmo
y cinco umbrales. La selección usa F1 macro de categorías en validación, sin escoger con
test. El vectorizador de clasificación se ajusta solo con train. Un vectorizador separado
de caracteres agrupa clones antes de dividir el dataset; no se reutiliza en el modelo.
No hay llamadas a LLM ni reglas que determinen directamente las predicciones OWASP.

El informe explica los resultados, falsos positivos/negativos, diferencias por fuente,
posible sobreajuste y las limitaciones de generalización. Las métricas se recalculan desde
el modelo guardado mediante `verify.py`. La evaluación cuenta como errores las categorías
omitidas por abstención; la decisión binaria sigue usando su umbral.
