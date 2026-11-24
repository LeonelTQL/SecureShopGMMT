"""Verify data isolation, saved pipeline behavior and reported test metrics."""
import json
from pathlib import Path
import sys

import joblib
import numpy as np
import pandas as pd
import nbformat
from sklearn.metrics import f1_score

from src.common import ROOT, digest, save_json
from src.experiment import load


def verify(require_executed=True):
    df, y, labels = load()
    assert len(df) >= 500 and (df.vulnerable == 0).sum() >= 100
    assert df.code_hash.nunique() == len(df)
    assert df.groupby('group').split.nunique().max() == 1
    assert df.groupby('code_hash').split.nunique().max() == 1
    for split in ['train', 'validation', 'test']:
        part = y[df.split.eq(split)]
        assert (part.sum(axis=0) > 0).all(), f'Missing positives in {split}'
        assert (part.sum(axis=0) < len(part)).all(), f'Missing negatives in {split}'
    model = joblib.load(ROOT / 'models/modelo_seleccionado.joblib')
    meta = json.loads((ROOT / 'models/metadata.json').read_text(encoding='utf-8'))
    assert meta['dataset_sha256'] == digest((ROOT / 'data/processed/dataset.csv').read_text(encoding='utf-8'))
    assert model.labels == labels and len(model.catalog) == 20
    test_mask = df.split.eq('test').to_numpy()
    truth = y[test_mask]
    predictions = model.decisions(model.probabilities(df.loc[test_mask, 'code'].tolist()))
    metrics = json.loads((ROOT / f'results/{meta["family"]}_test_metrics.json').read_text(encoding='utf-8'))
    assert np.isclose(f1_score(truth[:, 0], predictions[:, 0]), metrics['binary_f1'])
    assert np.isclose(f1_score(truth[:, 1:], predictions[:, 1:], average='macro', zero_division=0), metrics['category_f1_macro'])
    saved = pd.read_csv(ROOT / f'results/{meta["family"]}_test_predictions.csv')
    assert len(saved) == len(truth)
    assert np.array_equal(saved.predicted_vulnerable, predictions[:, 0])
    saved_categories = np.array([[int(label in json.loads(cell)) for label in labels[1:]] for cell in saved.predicted_labels])
    assert np.array_equal(saved_categories, predictions[:, 1:])
    # Reloading must preserve scores and must not fit or add tokens during inference.
    reloaded = joblib.load(ROOT / 'models/modelo_seleccionado.joblib')
    examples = df.loc[test_mask, 'code'].head(5).tolist()
    before = dict(reloaded.pipeline.named_steps['tfidf'].vocabulary_)
    np.testing.assert_allclose(model.probabilities(examples), reloaded.probabilities(examples))
    reloaded.predict(examples + ['def never_seen_sentinel_987():\n    return 123'])
    assert before == reloaded.pipeline.named_steps['tfidf'].vocabulary_
    for target in model.catalog:
        if target['estado'] == 'no_evaluada': assert target['id'] not in model.labels
    notebooks = []
    for path in sorted((ROOT / 'notebooks').glob('*.ipynb')):
        nb = nbformat.read(path, as_version=4)
        nbformat.validate(nb)
        cells = [cell for cell in nb.cells if cell.cell_type == 'code']
        executed = all(cell.execution_count is not None for cell in cells)
        assert not any(output.output_type == 'error' for cell in cells for output in cell.outputs)
        if require_executed: assert executed, f'Notebook not executed: {path.name}'
        notebooks.append({'name': path.name, 'executed': executed})
    assert len(notebooks) == 5
    audit = {'records': len(df), 'test_records': int(test_mask.sum()), 'unique_codes': True,
             'disjoint_clone_groups': True, 'all_labels_have_positive_and_negative_examples_in_each_split': True,
             'saved_model_matches_reported_metrics': True, 'serialization_roundtrip': True,
             'inference_does_not_fit_vectorizer': True, 'notebooks': notebooks,
             'pending': ['CLI integration', 'functional scan of unseen microservice project', 'external real-project generalization', 'human review of controlled labels']}
    save_json(ROOT / 'results/verification.json', audit)
    print(json.dumps(audit, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    verify('--allow-unexecuted' not in sys.argv)
