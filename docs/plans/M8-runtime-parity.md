# M8 follow-up — replay parity and qualification contracts

The release review found code gaps independent of the missing representative
dataset. Complete them after M10's local checks:

1. Let offline replay explicitly load configured Tier 1/rules/sensitive paths,
   using the same scorer and sanitized state as runtime. Pass that config through
   dataset building and record its identity. Fixtures still execute no OS response.
2. Verify model-specific local layouts (OpenDecider versus Laya), bounded file
   trees and qualification reports. Recheck minimum held-out sample/family counts,
   CPU measurements and the benign week when accepting a report at runtime.
3. Test score/state parity, invalid model layouts, missing/small/incorrect reports,
   and update the evaluation report/documentation. Keep synthetic models advisory.

Files: service replay/CLI, decide manifest/sidecar, Python dataset/evaluation/model
preparation tools, focused Rust/Python tests and training documentation.

Verified: configured ONNX replay/state equality, 80-case dataset export through the
configured model, typed contract comparison, threshold/sample/identity rejection,
Laya preparation and a real seven-event native ONNX + OpenDecider replay (six
complete decisions, one cold-load review, no OS response). Current synthetic
evaluation remains unqualified. Windows and Linux targeted tests pass.
