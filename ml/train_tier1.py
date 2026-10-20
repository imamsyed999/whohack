"""Train LightGBM + a local benign isolation forest and export portable ONNX.

Only train families are fitted; validation families choose the tree count. The
isolation forest uses benign training observations. Never executes fixture paths.
"""
import argparse
import json
import math
from pathlib import Path
from dataset import read_jsonl, validate, sha256


def average_path(n):
    if n <= 1: return 0.
    if n == 2: return 1.
    return 2 * (math.log(n - 1) + 0.5772156649015329) - 2 * (n - 1) / n


def isolation_tree(x, rng, depth=0, limit=8):
    if len(x) <= 1 or depth >= limit:
        return {"leaf_value": depth + average_path(len(x))}
    varying = [j for j in range(x.shape[1]) if x[:, j].min() < x[:, j].max()]
    if not varying:
        return {"leaf_value": depth + average_path(len(x))}
    feature = int(rng.choice(varying)); threshold = float(rng.uniform(x[:, feature].min(), x[:, feature].max()))
    left = x[:, feature] <= threshold
    return dict(split_feature=feature, threshold=threshold, decision_type="<=",
                left_child=isolation_tree(x[left], rng, depth + 1, limit),
                right_child=isolation_tree(x[~left], rng, depth + 1, limit))


def tree_predict(tree, x):
    if "leaf_value" in tree: return tree["leaf_value"]
    branch = "left_child" if x[tree["split_feature"]] <= tree["threshold"] else "right_child"
    return tree_predict(tree[branch], x)


def export_onnx(booster, forest, sample_size, output):
    import numpy as np
    import onnx
    from onnx import helper as h, TensorProto as T, numpy_helper
    nodes, values = [], []
    serial = 0
    def constant(value, dtype=np.float32):
        nonlocal serial
        name = f"c{serial}"; serial += 1
        values.append(numpy_helper.from_array(np.asarray(value, dtype=dtype), name))
        return name
    def node(kind, inputs, **attrs):
        nonlocal serial
        name = f"n{serial}"; serial += 1
        nodes.append(h.make_node(kind, inputs, [name], **attrs)); return name
    def tree(t):
        if 'leaf_value' in t: return constant([[t['leaf_value']]])
        if t.get('decision_type') != '<=' or t.get('missing_type', 'None') not in {'None', 'NaN'}:
            raise ValueError('unsupported categorical or zero-missing tree')
        column = node('Gather', ['features', constant([t['split_feature']], np.int64)], axis=1)
        # Inputs are finite float32. Round threshold downward so x<=threshold
        # retains LightGBM's float64 comparison semantics at float32 boundaries.
        threshold = np.float32(t['threshold'])
        if float(threshold) > t['threshold']: threshold = np.nextafter(threshold, np.float32(-np.inf))
        cond = node('LessOrEqual', [column, constant([[threshold]])])
        return node('Where', [cond, tree(t['left_child']), tree(t['right_child'])])
    def add(items):
        result = constant([[0.]])
        for item in items: result = node('Add', [result, item])
        return result
    trees = booster.dump_model()['tree_info']
    supervised = node('Sigmoid', [add([tree(t['tree_structure']) for t in trees])])
    depth = add([tree(t) for t in forest])
    exponent = node('Mul', [depth, constant([[-math.log(2) / (len(forest) * average_path(sample_size))]])])
    anomaly = node('Exp', [exponent])
    # A conservative ensemble score; it is a ranking score, not a calibrated
    # probability. The decision-model quality gate remains independent.
    score = node('Max', [supervised, anomaly])
    nodes.append(h.make_node('Identity', [score], ['score']))
    graph = h.make_graph(nodes, 'whohack-tier1-v1', [h.make_tensor_value_info('features', T.FLOAT, [1, 17])],
                         [h.make_tensor_value_info('score', T.FLOAT, [1, 1])], values)
    model = h.make_model(graph, opset_imports=[h.make_opsetid('', 13)], producer_name='whohack-train-tier1')
    model.ir_version = 8
    onnx.checker.check_model(model); onnx.save(model, str(output))
    return model


def train(rows, output):
    import numpy as np
    import lightgbm as lgb
    from onnx.reference import ReferenceEvaluator
    validate(rows)
    train_rows = [r for r in rows if r['split'] == 'train']
    val_rows = [r for r in rows if r['split'] == 'val']
    if len(train_rows) < 20 or not val_rows:
        raise ValueError('need at least 20 training cases and held-out validation families')
    x = np.asarray([r['feature_vector'] for r in train_rows], dtype=np.float32)
    y = np.asarray([r['labels']['verdict'] != 'benign' for r in train_rows], dtype=np.float32)
    if len(set(y)) != 2: raise ValueError('training data must contain benign and non-benign cases')
    xv = np.asarray([r['feature_vector'] for r in val_rows], dtype=np.float32)
    yv = np.asarray([r['labels']['verdict'] != 'benign' for r in val_rows], dtype=np.float32)
    params = dict(objective='binary', metric='binary_logloss', num_leaves=7, max_depth=3,
                  min_data_in_leaf=3, learning_rate=.1, num_threads=4, verbosity=-1,
                  deterministic=True, force_col_wise=True, seed=4528, use_missing=False)
    booster = lgb.train(params, lgb.Dataset(x, label=y), num_boost_round=64,
                        valid_sets=[lgb.Dataset(xv, label=yv)], callbacks=[lgb.early_stopping(8, verbose=False)])
    benign = x[y == 0]
    if len(benign) < 10: raise ValueError('isolation forest requires at least ten benign training cases')
    rng = np.random.default_rng(4528); size = min(128, len(benign))
    forest = [isolation_tree(benign[rng.choice(len(benign), size=size, replace=False)], rng, limit=math.ceil(math.log2(size))) for _ in range(16)]
    output = Path(output); output.parent.mkdir(parents=True, exist_ok=True)
    model = export_onnx(booster, forest, size, output)
    runtime = ReferenceEvaluator(model)
    # Verify the standard ONNX graph against the original model, including
    # validation cases never used for fitting tree thresholds.
    expected_supervised = booster.predict(xv)
    error = 0.
    for row, predicted in zip(xv, expected_supervised):
        expected = max(float(predicted), 2 ** (-sum(tree_predict(t, row) for t in forest) / (len(forest) * average_path(size))))
        actual = float(runtime.run(None, {'features': row.reshape(1, 17)})[0].item())
        error = max(error, abs(expected - actual))
    if error > 1e-5: raise ValueError(f'ONNX parity failed: max error {error}')
    output.with_suffix('.json').write_text(json.dumps(dict(schema_version=1, sha256=sha256(output),
        feature_names=rows[0]['feature_names'], input_shape=[1, 17], output_shape=[1, 1],
        synthetic=any(r['synthetic'] for r in rows), qualified=False, train_cases=len(train_rows), val_cases=len(val_rows),
        lightgbm_version=lgb.__version__, validation_max_error=error, trees=booster.num_trees(), isolation_trees=len(forest)), indent=2) + '\n', encoding='utf-8')
    return error


def main():
    p = argparse.ArgumentParser(description=__doc__); p.add_argument('dataset', type=Path)
    p.add_argument('--output', type=Path, required=True); a = p.parse_args()
    print('Exported ONNX; maximum validation parity error:', train(read_jsonl(a.dataset), a.output))


if __name__ == '__main__':
    main()
