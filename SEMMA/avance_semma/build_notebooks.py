"""Create five self-contained phase notebooks. Execute with execute_notebooks.py."""
from pathlib import Path
import nbformat as nbf

ROOT = Path(__file__).resolve().parent
BOOT = '''from pathlib import Path
import sys, json
ROOT = Path.cwd()
if not (ROOT / 'src').exists():
    ROOT = ROOT.parent
assert (ROOT / 'src').is_dir(), 'Abrir desde avance_semma o su carpeta notebooks'
sys.path.insert(0, str(ROOT))
import pandas as pd
from IPython.display import display, Image, Markdown
'''


def write(name, cells):
    nb = nbf.v4.new_notebook()
    nb.metadata.kernelspec = {'name': 'python3', 'language': 'python', 'display_name': 'Python (avance SEMMA)'}
    nb.cells = [nbf.v4.new_markdown_cell(text) if kind == 'md' else nbf.v4.new_code_cell(text) for kind, text in cells]
    nbf.write(nb, ROOT / 'notebooks' / name)


if __name__ == '__main__':
    write('01_sample.ipynb', [
        ('md', '# 1. Sample — PDF §7.1, páginas 5–6\n\nSelección y muestreo con trazabilidad. Se usa OWASP Benchmark fijado por commit y casos controlados documentados. No se ejecutan los fragmentos.'),
        ('code', BOOT),
        ('md', '## Construcción y separación\n\nSe eliminan duplicados exactos y se excluyen conflictos. Los componentes de clones detectados permanecen en una sola partición. La división por grupos se aproxima a 70/15/15; no se rompen grupos para forzar los porcentajes.'),
        ('code', "from src.dataset import prepare\ndf = prepare()\ndisplay(df.drop(columns='code').head())"),
        ('code', "display(pd.crosstab(df.source, df.split))\ndisplay(pd.crosstab(df.language, df.vulnerable))\ndisplay(pd.read_csv(ROOT / 'docs/cwe_owasp.csv'))"),
        ('md', '## Calidad y alcance\n\nEl mínimo del PDF se contrasta con registros únicos y ejemplos no vulnerables al riesgo objetivo. La procedencia Java corresponde a un único benchmark: estas particiones no demuestran generalización entre proyectos reales. Los casos Python requieren revisión humana.'),
        ('code', "audit = json.loads((ROOT / 'results/sample_audit.json').read_text(encoding='utf-8'))\nassert audit['records'] >= 500 and audit['safe_targeted'] >= 100\nassert audit['group_overlap'] == audit['exact_code_overlap'] == 0\ndisplay(Markdown((ROOT / 'docs/fuentes.md').read_text(encoding='utf-8')))"),
    ])
    write('02_explore.ipynb', [
        ('md', '# 2. Explore — PDF §7.2, páginas 6–7\n\nDistribuciones, longitudes, patrones, datos faltantes y desequilibrios.'),
        ('code', BOOT),
        ('code', "from src.experiment import load, explore\ndf, y, labels = load()\nexplore(df)\ndisplay(df.isna().sum().to_frame('nulos'))\nprint('Códigos duplicados:', df.code_hash.duplicated().sum())\ndisplay(pd.crosstab(df.cwe, df.split))"),
        ('code', "for name in ['por_categoria', 'por_clase', 'por_lenguaje', 'por_fuente', 'por_artefacto', 'longitudes', 'patrones']:\n    display(Image(filename=str(ROOT / f'results/{name}.png')))"),
        ('md', '## Interpretación\n\nLa clase binaria es relativamente equilibrada, pero las etiquetas OWASP y los lenguajes están desbalanceados. Java domina y las etiquetas API dependen de pocos pares Python controlados. Las categorías amplias de inyección y criptografía agrupan varias CWE; su frecuencia no mide prevalencia real en microservicios. Los tokens frecuentes incluyen sintaxis y no prueban causalidad. Es necesario informar resultados por categoría y fuente, no solo accuracy global.'),
    ])
    write('03_modify.ipynb', [
        ('md', '# 3. Modify — PDF §7.3, páginas 7–8\n\nCódigo sin comentarios e identificadores que revelen etiquetas; TF-IDF de tokens y bigramas. El vocabulario se ajusta exclusivamente en train. Los metadatos sirven para auditoría y nunca son características.'),
        ('code', BOOT),
        ('code', "from src.common import clean_code, code_tokens\nfrom src.experiment import modify\nsample = \"cursor.execute('SELECT * FROM accounts WHERE id=?', (account_id,))\"\nprint(code_tokens(clean_code(sample)))\nmatrices, targets = modify()\nprint({name: value.shape for name, value in matrices.items()})\nprint('Objetivos:', targets)"),
        ('code', "display(pd.Series(json.loads((ROOT / 'results/modify_audit.json').read_text(encoding='utf-8'))))\ndisplay(pd.read_csv(ROOT / 'data/processed/feature_names.csv').head(30))"),
        ('md', '## Justificación\n\nTF-IDF es una base reproducible para minería de texto/código. Los símbolos y bigramas conservan parte de los patrones de llamadas, operadores y controles. `min_df=2` reduce términos aislados; el límite de 18.000 características controla el costo. Se usa ponderación de clases en cada clasificador binario, sin alterar los conjuntos retenidos. Las matrices se guardan dispersas. Esta representación no entiende flujo de datos, dependencias entre servicios ni lógica completa.'),
    ])
    write('04_model.ipynb', [
        ('md', '# 4. Model — PDF §7.4, páginas 8–9\n\nSe comparan Regresión Logística y Random Forest. Cada algoritmo aprende los objetivos binario y multietiqueta mediante One-vs-Rest. Las predicciones no se generan mediante expresiones regulares.'),
        ('code', BOOT),
        ('md', '## Entrenamiento y validación\n\nSe prueban dos configuraciones por algoritmo y umbrales 0,30–0,70. Se selecciona por F1 macro de las diez categorías con evidencia en validación; F1 binario y tiempo resuelven empates. No se consulta test para escoger. El pipeline se serializa antes de evaluar test.'),
        ('code', "from src.experiment import model_phase\ncomparison = model_phase()\ndisplay(pd.read_csv(ROOT / 'results/validation_search.csv'))\ndisplay(pd.DataFrame(comparison))"),
        ('code', "display(pd.Series(json.loads((ROOT / 'results/model_selection.json').read_text(encoding='utf-8'))))\nprint('Artefactos:', [p.name for p in (ROOT / 'models').glob('*.joblib')])"),
        ('md', '## Inferencia posterior\n\nEl artefacto seleccionado incluye vectorización, clasificadores, catálogo y umbral. Su entrada es código fuente, sin CWE ni categoría conocida. Un resultado incierto deja la categoría pendiente de revisión. Los scores no están calibrados y no representan severidad. Las categorías sin datos están declaradas como no evaluadas.'),
    ])
    write('05_assess.ipynb', [
        ('md', '# 5. Assess — PDF §7.5, páginas 9–10\n\nEvaluación de modelos congelados con datos retenidos. Métricas binarias y multietiqueta, matrices 2×2 por etiqueta, errores y comparación con un clasificador trivial.'),
        ('code', BOOT),
        ('code', "from src.experiment import assess\ncomparison = assess()\ndisplay(pd.DataFrame(comparison))\nselection = json.loads((ROOT / 'results/model_selection.json').read_text(encoding='utf-8'))\nfamily = selection['family']\ndisplay(pd.read_csv(ROOT / f'results/{family}_por_categoria.csv'))"),
        ('code', "display(Image(filename=str(ROOT / f'results/{family}_matrices.png')))\ndisplay(pd.read_csv(ROOT / f'results/{family}_por_fuente_lenguaje.csv'))\nerrors = pd.read_csv(ROOT / f'results/{family}_errores.csv')\ndisplay(errors.drop(columns='code').head(10))\nprint('Errores con evidencia completa en CSV:', len(errors))"),
        ('md', '## Análisis reproducible y conclusiones\n\nLa siguiente celda genera el informe a partir de los resultados y muestra ejemplos concretos de errores; no agrega métricas manualmente.'),
        ('code', "from src.report import build_report\nbuild_report()\ndisplay(Markdown((ROOT / 'docs/informe_semma.md').read_text(encoding='utf-8')))"),
        ('md', '## Actividad pendiente del PDF\n\nLa actividad 7 de Assess (pruebas funcionales en proyectos de microservicios desconocidos) se realizará al integrar la CLI. Evaluar fragmentos retenidos no la sustituye. Tampoco se ha probado generalización a repositorios reales externos ni confirmado vulnerabilidades mediante pruebas dinámicas.'),
    ])
    print('Five phase notebooks created.')
