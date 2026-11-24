import json
import platform
import time
from importlib.metadata import version

import joblib
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from scipy.sparse import save_npz
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (classification_report, confusion_matrix, f1_score,
                             multilabel_confusion_matrix, precision_score, recall_score,
                             hamming_loss, accuracy_score)
from sklearn.multiclass import OneVsRestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import MultiLabelBinarizer

from .common import ROOT, code_tokens, digest, save_json
from .mining import MiningModel

RESULTS = ROOT / 'results'


def load():
    df = pd.read_csv(ROOT / 'data/processed/dataset.csv', keep_default_na=False)
    labels = sorted({label for cell in df.labels for label in json.loads(cell)})
    encoder = MultiLabelBinarizer(classes=labels)
    categories = encoder.fit_transform(df.labels.map(json.loads))
    y = np.column_stack([df.vulnerable.to_numpy(), categories])
    return df, y, ['vulnerable'] + labels


def explore(df):
    tables = {
        'por_lenguaje': df.language.value_counts(),
        'por_clase': df.vulnerable.map({0: 'no vulnerable al riesgo etiquetado', 1: 'vulnerable'}).value_counts(),
        'por_categoria': pd.Series([label for cell in df.labels for label in json.loads(cell)]).value_counts(),
        'por_fuente': df.source.value_counts(),
        'por_artefacto': df.artifact_type.value_counts(),
    }
    for name, counts in tables.items():
        counts.rename_axis('grupo').reset_index(name='registros').to_csv(RESULTS / f'{name}.csv', index=False)
        fig, ax = plt.subplots(figsize=(9, max(3, .4 * len(counts))))
        counts.sort_values().plot.barh(ax=ax)
        ax.set_xlabel('Registros'); ax.set_title(name.replace('_', ' ').capitalize())
        fig.tight_layout(); fig.savefig(RESULTS / f'{name}.png', dpi=150); plt.close(fig)
    lengths = pd.DataFrame({'caracteres': df.code.str.len(), 'tokens': df.code.map(lambda s: len(code_tokens(s))),
                            'language': df.language, 'vulnerable': df.vulnerable})
    lengths.groupby(['language', 'vulnerable'])[['caracteres', 'tokens']].describe().to_csv(RESULTS / 'longitudes.csv')
    fig, ax = plt.subplots(figsize=(9, 4))
    sns.boxplot(data=lengths, x='language', y='tokens', hue='vulnerable', ax=ax)
    ax.set_title('Longitud por lenguaje y etiqueta'); fig.tight_layout()
    fig.savefig(RESULTS / 'longitudes.png', dpi=150); plt.close(fig)
    counts = pd.Series(code_tokens('\n'.join(df.code))).value_counts().head(25)
    counts.rename_axis('token').reset_index(name='frecuencia').to_csv(RESULTS / 'patrones.csv', index=False)
    fig, ax = plt.subplots(figsize=(9, 7)); counts.sort_values().plot.barh(ax=ax)
    ax.set_title('Tokens frecuentes (incluye sintaxis, sin inferir causalidad)')
    fig.tight_layout(); fig.savefig(RESULTS / 'patrones.png', dpi=150); plt.close(fig)
    pd.crosstab(df.split, df.language).to_csv(RESULTS / 'particiones_lenguaje.csv')


def score(y, pred):
    return {'binary_precision': float(precision_score(y[:, 0], pred[:, 0], zero_division=0)),
            'binary_recall': float(recall_score(y[:, 0], pred[:, 0], zero_division=0)),
            'binary_f1': float(f1_score(y[:, 0], pred[:, 0], zero_division=0)),
            'category_precision_macro': float(precision_score(y[:, 1:], pred[:, 1:], average='macro', zero_division=0)),
            'category_recall_macro': float(recall_score(y[:, 1:], pred[:, 1:], average='macro', zero_division=0)),
            'category_f1_macro': float(f1_score(y[:, 1:], pred[:, 1:], average='macro', zero_division=0)),
            'category_f1_micro': float(f1_score(y[:, 1:], pred[:, 1:], average='micro', zero_division=0)),
            'hamming_loss': float(hamming_loss(y[:, 1:], pred[:, 1:])),
            'subset_accuracy': float(accuracy_score(y[:, 1:], pred[:, 1:]))}


def evaluate(name, model, df, y, labels, indices):
    truth = y[indices]
    part = df.iloc[indices].reset_index(drop=True)
    probabilities = model.probabilities(part.code.tolist())
    pred = model.decisions(probabilities)
    metrics = score(truth, pred)
    save_json(RESULTS / f'{name}_test_metrics.json', metrics)
    report = classification_report(truth[:, 1:], pred[:, 1:], target_names=labels[1:], output_dict=True, zero_division=0)
    pd.DataFrame(report).T.to_csv(RESULTS / f'{name}_por_categoria.csv', index_label='categoria')
    matrices = multilabel_confusion_matrix(truth, pred)
    save_json(RESULTS / f'{name}_matrices.json', {label: matrix.tolist() for label, matrix in zip(labels, matrices)})
    fig, axes = plt.subplots(3, 4, figsize=(16, 11))
    for ax, label, matrix in zip(axes.flat, labels, matrices):
        sns.heatmap(matrix, annot=True, fmt='d', cbar=False, ax=ax, cmap='Blues')
        ax.set_title(label); ax.set_xlabel('Predicho'); ax.set_ylabel('Real')
    for ax in axes.flat[len(labels):]: ax.axis('off')
    fig.tight_layout(); fig.savefig(RESULTS / f'{name}_matrices.png', dpi=140); plt.close(fig)
    error_rows, prediction_rows = [], []
    output = model.predict(part.code.tolist())
    for i, row in part.iterrows():
        fp = [label for label, t, p in zip(labels, truth[i], pred[i]) if p and not t]
        fn = [label for label, t, p in zip(labels, truth[i], pred[i]) if t and not p]
        record = {'record_id': row.record_id, 'source': row.source, 'language': row.language,
                  'true_labels': row.labels, 'true_vulnerable': int(truth[i, 0]),
                  'predicted_labels': json.dumps([k for k, v in zip(labels[1:], pred[i, 1:]) if v]),
                  'predicted_vulnerable': int(pred[i, 0]), 'score_vulnerable': float(probabilities[i, 0]),
                  'status': output[i]['status'], 'public_categories': json.dumps(output[i]['categories']),
                  'false_positive_labels': json.dumps(fp), 'false_negative_labels': json.dumps(fn)}
        prediction_rows.append(record)
        if fp or fn:
            error_rows.append({**record, 'code': row.code, 'source_url': row.source_url,
                               'diagnosis': 'Revisar flujo de datos, guardas y contexto; hipótesis, no causa probada.'})
    pd.DataFrame(prediction_rows).to_csv(RESULTS / f'{name}_test_predictions.csv', index=False)
    pd.DataFrame(error_rows, columns=list(prediction_rows[0]) + ['code', 'source_url', 'diagnosis']).to_csv(RESULTS / f'{name}_errores.csv', index=False)
    groups = []
    for column in ['source', 'language']:
        for value in part[column].unique():
            mask = (part[column] == value).to_numpy()
            present = np.flatnonzero(truth[mask, 1:].sum(axis=0) > 0) + 1
            local_macro = f1_score(truth[mask][:, present], pred[mask][:, present], average='macro', zero_division=0)
            groups.append({'grouping': column, 'group': value, 'n': int(mask.sum()), **score(truth[mask], pred[mask]),
                           'f1_macro_supported_labels': float(local_macro), 'supported_labels': json.dumps([labels[j] for j in present])})
    pd.DataFrame(groups).to_csv(RESULTS / f'{name}_por_fuente_lenguaje.csv', index=False)
    return metrics


def modify():
    df, y, labels = load()
    indices = {split: np.flatnonzero(df.split.eq(split)) for split in ['train', 'validation', 'test']}
    # Source metadata, CWE, labels and filenames are never features.
    tfidf = TfidfVectorizer(tokenizer=code_tokens, token_pattern=None, lowercase=False,
                            ngram_range=(1, 2), min_df=2, max_features=18000, sublinear_tf=True)
    matrices = {'train': tfidf.fit_transform(df.iloc[indices['train']].code)}
    for split in ['validation', 'test']:
        matrices[split] = tfidf.transform(df.iloc[indices[split]].code)
    for split, matrix in matrices.items():
        save_npz(ROOT / f'data/processed/X_{split}.npz', matrix)
        np.save(ROOT / f'data/processed/y_{split}.npy', y[indices[split]])
    pd.Series(tfidf.get_feature_names_out(), name='feature').to_csv(ROOT / 'data/processed/feature_names.csv', index=False)
    save_json(RESULTS / 'modify_audit.json', {'fit_partition': 'train', 'metadata_used_as_features': False,
              'vocabulary_size': len(tfidf.vocabulary_), 'shapes': {k: list(v.shape) for k,v in matrices.items()},
              'class_balance_strategy': 'class_weight=balanced en cada clasificador binario; sin sobremuestrear validation/test',
              'targets': labels, 'input': 'code only, comments and benchmark IDs removed'})
    joblib.dump(tfidf, ROOT / 'models/preprocessor.joblib', compress=3)
    return matrices, labels


def model_phase():
    from scipy.sparse import load_npz
    df, y, labels = load()
    indices = {split: np.flatnonzero(df.split.eq(split)) for split in ['train', 'validation', 'test']}
    matrices = {split: load_npz(ROOT / f'data/processed/X_{split}.npz') for split in indices}
    tfidf = joblib.load(ROOT / 'models/preprocessor.joblib')
    catalog = json.loads((ROOT / 'data/processed/catalogo_owasp.json').read_text(encoding='utf-8'))
    candidates = [
        ('lr_C0.5', 'logistic_regression', LogisticRegression(C=.5, class_weight='balanced', max_iter=1500, random_state=42)),
        ('lr_C2', 'logistic_regression', LogisticRegression(C=2, class_weight='balanced', max_iter=1500, random_state=42)),
        ('rf_100', 'random_forest', RandomForestClassifier(n_estimators=100, max_depth=None, min_samples_leaf=2, class_weight='balanced', n_jobs=-1, random_state=42)),
        ('rf_150_depth20', 'random_forest', RandomForestClassifier(n_estimators=150, max_depth=20, min_samples_leaf=1, class_weight='balanced', n_jobs=-1, random_state=42)),
    ]
    trials, fitted = [], {}
    for name, family, estimator in candidates:
        started = time.perf_counter()
        clf = OneVsRestClassifier(estimator, n_jobs=1)
        clf.fit(matrices['train'], y[indices['train']])
        elapsed = time.perf_counter() - started
        model = MiningModel(Pipeline([('tfidf', tfidf), ('classifier', clf)]), labels, .5, catalog)
        val_probs = clf.predict_proba(matrices['validation'])
        for threshold in [.30, .40, .50, .60, .70]:
            model.threshold = threshold
            metrics = score(y[indices['validation']], model.decisions(val_probs))
            trials.append({'candidate': name, 'family': family, 'threshold': threshold, 'fit_seconds': elapsed,
                           'parameters': json.dumps(estimator.get_params(), default=str), **metrics})
        fitted[name] = model
        print(f'Trained {name} in {elapsed:.1f}s', flush=True)
    table = pd.DataFrame(trials)
    table = table.sort_values(['category_f1_macro', 'binary_f1', 'fit_seconds'], ascending=[False, False, True])
    table.to_csv(RESULTS / 'validation_search.csv', index=False)
    # Commit selection using validation only, before examining test outcomes.
    selected = table.iloc[0]
    family_best = table.groupby('family', sort=False).head(1)
    selection = {'candidate': selected.candidate, 'family': selected.family, 'threshold': float(selected.threshold),
                 'criterion': 'Maximum validation category F1 macro; binary F1 then fit time break ties.',
                 'validation_category_f1_macro': float(selected.category_f1_macro),
                 'test_used_for_selection': False, 'refit_on_validation': False,
                 'dataset_sha256': digest((ROOT / 'data/processed/dataset.csv').read_text(encoding='utf-8'))}
    save_json(RESULTS / 'model_selection.json', selection)
    comparisons = []
    for _, row in family_best.iterrows():
        model = fitted[row.candidate]; model.threshold = float(row.threshold)
        joblib.dump(model, ROOT / f'models/{row.family}.joblib', compress=3)
        train_metrics = score(y[indices['train']], model.decisions(model.probabilities(df.iloc[indices['train']].code.tolist())))
        comparisons.append({'family': row.family, 'candidate': row.candidate, 'threshold': row.threshold,
                            'train_category_f1_macro': train_metrics['category_f1_macro'],
                            'validation_category_f1_macro': row.category_f1_macro})
        if row.candidate == selected.candidate:
            joblib.dump(model, ROOT / 'models/modelo_seleccionado.joblib', compress=3)
    pd.DataFrame(comparisons).to_csv(RESULTS / 'train_validation_comparison.csv', index=False)
    save_json(ROOT / 'models/metadata.json', {**selection, 'python': platform.python_version(),
              'packages': {p: version(p) for p in ['scikit-learn', 'pandas', 'numpy', 'scipy', 'joblib']},
              'labels': labels, 'input_contract': 'UTF-8 code snippets, same granularity as training; no repository discovery',
              'score_calibration': 'not calibrated', 'safety': 'Load trusted joblib files only.'})
    return comparisons


def assess():
    from scipy.sparse import load_npz
    df, y, labels = load()
    indices = {split: np.flatnonzero(df.split.eq(split)) for split in ['train', 'validation', 'test']}
    matrices = {split: load_npz(ROOT / f'data/processed/X_{split}.npz') for split in indices}
    comparisons = []
    for row in pd.read_csv(RESULTS / 'train_validation_comparison.csv').to_dict('records'):
        model = joblib.load(ROOT / f'models/{row["family"]}.joblib')
        test_metrics = evaluate(row['family'], model, df, y, labels, indices['test'])
        comparisons.append({**row, **{'test_' + k: v for k, v in test_metrics.items()}})
    pd.DataFrame(comparisons).to_csv(RESULTS / 'model_comparison.csv', index=False)
    baseline = DummyClassifier(strategy='most_frequent').fit(matrices['train'], y[indices['train'], 0])
    binary = baseline.predict(matrices['test'])
    zeros = np.zeros_like(y[indices['test']]); zeros[:, 0] = binary
    save_json(RESULTS / 'dummy_baseline.json', score(y[indices['test']], zeros))
    reloaded = joblib.load(ROOT / 'models/modelo_seleccionado.joblib')
    example = reloaded.predict(df.iloc[indices['test'][:3]].code.tolist())
    save_json(RESULTS / 'inference_examples.json', example)
    print(pd.DataFrame(comparisons).to_string(index=False), flush=True)
    return comparisons


def run_experiment():
    df, _, _ = load()
    explore(df)
    modify()
    model_phase()
    return assess()
