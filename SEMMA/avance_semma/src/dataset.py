import csv
import io
import json
import re
import zipfile
from collections import Counter

import numpy as np
import pandas as pd
from scipy.sparse.csgraph import connected_components
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import GroupShuffleSplit

from .common import ROOT, clean_code, digest, save_json, structural_key
from .controlled import records
from .taxonomy import CWE_TOP, export_catalog


def benchmark_records():
    raw = ROOT / 'data/raw'
    revision = json.loads((raw / 'benchmark_commit.json').read_text(encoding='utf-8-sig'))['sha']
    archive = raw / 'benchmark_java.zip'
    rows = []
    with zipfile.ZipFile(archive) as z:
        names = z.namelist()
        prefix = names[0]
        expected = next(n for n in names if n.endswith('/expectedresults-1.2.csv'))
        truth = z.read(expected).decode('utf-8-sig')
        (raw / 'expectedresults-1.2.csv').write_text(truth, encoding='utf-8')
        license_path = next(n for n in names if n.endswith('/LICENSE'))
        (raw / 'LICENSE-BenchmarkJava.txt').write_bytes(z.read(license_path))
        paths = {n.rsplit('/', 1)[-1]: n for n in names if '/testcode/' in n and n.endswith('.java')}
        excluded = Counter()
        for item in csv.reader(io.StringIO(truth)):
            if not item or item[0].startswith('#'):
                continue
            test, scenario, flag, cwe = [v.strip() for v in item[:4]]
            if int(cwe) not in CWE_TOP:
                excluded[cwe] += 1
                continue
            path = paths[test + '.java']
            original = z.read(path).decode('utf-8')
            # doGet includes category in HTML paths. Keep complete doPost and auxiliary methods.
            start = original.index('public void doPost(')
            snippet = original[start:]
            # Some tests delegate to separate helper classes. Include their source as evidence.
            helpers = sorted(set(re.findall(r'\bBenchmarkTest\d+Helper\b', snippet)))
            for helper in helpers:
                if helper + '.java' not in paths:
                    raise ValueError(f'Missing helper {helper}')
                snippet += '\n' + z.read(paths[helper + '.java']).decode('utf-8')
            snippet = clean_code(snippet)
            vulnerable = int(flag == 'true')
            rows.append({'record_id': test, 'code': snippet, 'language': 'Java', 'artifact_type': 'source',
                         'source': 'OWASP Benchmark Java 1.2', 'project': 'BenchmarkJava',
                         'source_url': f'https://github.com/OWASP-Benchmark/BenchmarkJava/blob/{revision}/{path[len(prefix):]}',
                         'source_revision': revision, 'license': 'GPL-2.0-only', 'scenario': scenario,
                         'cwe': f'CWE-{cwe}', 'vulnerable': vulnerable,
                         'labels': [CWE_TOP[int(cwe)]] if vulnerable else [],
                         'group': 'benchmark-' + structural_key(snippet),
                         'split': '', 'label_basis': 'expectedresults-1.2.csv: targeted CWE only',
                         'review_status': 'etiqueta_fuente_no_auditada_manualmente'})
    save_json(raw / 'excluded_categories.json', dict(excluded))
    save_json(raw / 'source_manifest.json', {
        'repository': 'https://github.com/OWASP-Benchmark/BenchmarkJava', 'revision': revision,
        'archive_url': f'https://codeload.github.com/OWASP-Benchmark/BenchmarkJava/zip/{revision}',
        'archive_sha256': __import__('hashlib').sha256(archive.read_bytes()).hexdigest(),
        'expectedresults_sha256': digest(truth), 'license': 'GPL-2.0-only',
        'notes': 'No production repositories; benchmark is a deliberately constructed test suite.'})
    return rows


def assign_benchmark_splits(df):
    # Group near clones without labels, before selecting any model. This vectorizer
    # serves ONLY dataset decontamination and is never the model feature extractor.
    x = TfidfVectorizer(analyzer='char', ngram_range=(5, 5), min_df=2,
                        max_features=25000).fit_transform(df.code)
    similarities = (x @ x.T).tocsr()
    similarities.data[similarities.data < .90] = 0
    similarities.eliminate_zeros()
    # Also connect the literal/identifier-normalized exact structural groups.
    graph = similarities.tolil()
    for positions in df.reset_index(drop=True).groupby('group').indices.values():
        for position in positions[1:]:
            graph[positions[0], position] = 1
            graph[position, positions[0]] = 1
    _, components = connected_components(graph.tocsr(), directed=False)
    df['group'] = ['benchmark-clone-' + str(c) for c in components]
    # One fixed, reproducible grouped split, selected without model scores or test tuning.
    splitter = GroupShuffleSplit(n_splits=1, test_size=.30, random_state=42)
    train, rest = next(splitter.split(df, groups=df['group']))
    holdout = df.iloc[rest]
    val, test = next(GroupShuffleSplit(n_splits=1, test_size=.5, random_state=43).split(holdout, groups=holdout['group']))
    df.loc[df.index[train], 'split'] = 'train'
    df.loc[holdout.index[val], 'split'] = 'validation'
    df.loc[holdout.index[test], 'split'] = 'test'
    return df


def prepare():
    rows = benchmark_records() + records()
    df = pd.DataFrame(rows)
    df['code_hash'] = df.code.map(digest)
    # Conflicting duplicate labels are ambiguous and must not become train/test examples.
    conflicts = df.groupby('code_hash').vulnerable.nunique()
    conflict_hashes = set(conflicts[conflicts > 1].index)
    excluded = df[df.code_hash.isin(conflict_hashes)].copy()
    excluded.to_csv(ROOT / 'data/processed/excluded_conflicts.csv', index=False)
    df = df[~df.code_hash.isin(conflict_hashes)].copy()
    duplicates = int(df.code_hash.duplicated().sum())
    df = df.drop_duplicates('code_hash').reset_index(drop=True)
    mask = df.source != 'controlled'
    grouped = assign_benchmark_splits(df[mask].copy())
    df.loc[mask, ['split', 'group']] = grouped[['split', 'group']]
    # Prevent comments and identifiers from directly exposing source labels.
    assert not df.code.str.contains(r'BenchmarkTest\d+').any()
    assert df.groupby('group').split.nunique().max() == 1
    assert df.groupby('code_hash').split.nunique().max() == 1
    assert len(df) >= 500 and (df.vulnerable == 0).sum() >= 100
    assert not df[['code', 'language', 'cwe', 'source_url', 'split']].isna().any().any()
    df['labels'] = df.labels.map(lambda labels: json.dumps(labels, ensure_ascii=False))
    df.to_csv(ROOT / 'data/processed/dataset.csv', index=False)
    df[['record_id', 'group', 'code_hash', 'source', 'split']].to_csv(ROOT / 'data/processed/partitions.csv', index=False)
    evaluated = sorted({label for cell in df.labels for label in json.loads(cell)})
    export_catalog(evaluated)
    audit = {'records': len(df), 'safe_targeted': int((df.vulnerable == 0).sum()),
             'vulnerable': int(df.vulnerable.sum()), 'unique_code': int(df.code_hash.nunique()),
             'groups': int(df.group.nunique()), 'duplicates_removed': duplicates,
             'conflicting_records_excluded': len(excluded),
             'splits': df.split.value_counts().to_dict(), 'languages': df.language.value_counts().to_dict(),
             'sources': df.source.value_counts().to_dict(), 'evaluated_labels': evaluated,
             'group_overlap': 0, 'exact_code_overlap': 0,
             'clone_grouping': 'Connected components: character 5-gram TF-IDF cosine >= 0.90 OR equal structural hash. Grouping uses no labels.',
             'limitation': 'Clone grouping is heuristic. Semantic near clones can remain. Benchmark split is within one source project; external project evaluation remains pending.'}
    save_json(ROOT / 'results/sample_audit.json', audit)
    print(json.dumps(audit, ensure_ascii=False, indent=2))
    return df
