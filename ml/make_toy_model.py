"""Generate a tiny synthetic ONNX fixture. This is NOT a trained detector."""
from pathlib import Path
import hashlib
import json
import numpy as np
import onnx
from onnx import TensorProto, helper, numpy_helper


def main():
    root = Path(__file__).resolve().parent / "fixtures"
    root.mkdir(exist_ok=True)
    weights = np.zeros((17, 1), dtype=np.float32)
    weights[10, 0], weights[11, 0], weights[12, 0] = 0.3, 0.7, 0.4
    graph = helper.make_graph([
        helper.make_node("MatMul", ["features", "weights"], ["linear"]),
        helper.make_node("Add", ["linear", "bias"], ["logit"]),
        helper.make_node("Sigmoid", ["logit"], ["score"]),
    ], "whohack_synthetic_fixture", [helper.make_tensor_value_info("features", TensorProto.FLOAT, [1, 17])],
        [helper.make_tensor_value_info("score", TensorProto.FLOAT, [1, 1])],
        [numpy_helper.from_array(weights, "weights"), numpy_helper.from_array(np.array([-2.0], dtype=np.float32), "bias")])
    model = helper.make_model(graph, producer_name="whohack synthetic test fixture", opset_imports=[helper.make_opsetid("", 13)], ir_version=8)
    onnx.checker.check_model(model)
    path = root / "toy-tier1.onnx"
    onnx.save(model, path)
    (root / "toy-tier1.json").write_text(json.dumps({"synthetic": True, "trained": False, "feature_schema": 1,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "purpose": "Loading/inference contract test only; no detection accuracy claim"}, indent=2) + "\n", encoding="utf-8")
    print(path)


if __name__ == "__main__":
    main()
