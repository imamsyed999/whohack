# M5: bounded behavior windows and local scoring

- Add a versioned 60-second feature vector in `vigil-detect`, keyed by PID and
  creation time. Track distinct destinations/ports, raw IPs, child launches,
  sensitive access, persistence, byte counters, interval variation, unexpected
  capability severity, taint, signature and path class. Expose saturation instead
  of quietly claiming complete observations after resource limits.
- Add `NetStats` to the event contract and Windows ETW send/receive normalization.
  Missing sensors produce explicit missing-data flags, never invented zero risk.
- Keep the documented hand-weighted fallback. Add a SHA-256-pinned, bounded local
  ONNX scorer using the current pure Rust tract API and an explicitly synthetic
  fixture to verify loading/inference. No network inference or trained-accuracy
  claims come from that fixture.
- Use windows in the service's detections and provide a feature export command for
  replay/training. Test expiration, reordered events, PID reuse, missing counters,
  known toy output, corrupt model rejection, and scoring latency.

Follow with M6 decision-state/fusion integration and M8 dataset/training tooling.
Elevated sensor validation and representative labeled telemetry remain explicit
release gates, separate from synthetic pipeline validation.
