"""Saved text-only classifier and explicit abstention behavior."""
from dataclasses import dataclass

import numpy as np

from .common import clean_code


@dataclass
class MiningModel:
    pipeline: object
    labels: list
    threshold: float
    catalog: list

    def probabilities(self, snippets):
        return self.pipeline.predict_proba([clean_code(s) for s in snippets])

    def decisions(self, probabilities):
        predictions = (probabilities >= self.threshold).astype(int)
        predictions[predictions[:, 0] == 0, 1:] = 0
        predictions[np.abs(probabilities[:, 0] - self.threshold) < .05, 1:] = 0
        return predictions

    def predict(self, snippets):
        probabilities = self.probabilities(snippets)
        decisions = self.decisions(probabilities)
        results = []
        for scores, pred in zip(probabilities, decisions):
            categories = [label for label, yes in zip(self.labels[1:], pred[1:]) if yes]
            # A score is an uncalibrated model output, not a severity or confirmation.
            uncertain = abs(float(scores[0]) - self.threshold) < .05
            pending = uncertain or (bool(pred[0]) and not categories)
            results.append({
                'potential_vulnerability': bool(pred[0]),
                'categories': [] if pending else categories,
                'status': 'pendiente_revision' if pending else 'hallazgo_potencial' if pred[0] else 'sin_evidencia_modelo',
                'vulnerability_score': float(scores[0]),
                'category_scores': {key: float(value) for key, value in zip(self.labels[1:], scores[1:])},
                'unevaluated_categories': [c['id'] for c in self.catalog if c['estado'] == 'no_evaluada'],
                'note': 'Probabilidades sin calibración; no certifica seguridad ni confirma vulnerabilidades.'})
        return results
