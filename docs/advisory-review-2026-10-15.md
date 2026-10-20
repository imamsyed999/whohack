# Dependency advisory review, 2026-10-15

Fresh RustSec data adds three Wasmtime advisories to the previous audit. The
locked YARA-X 1.21.0 release still requires Wasmtime 45.0.3. Its published manifest
enables only `cranelift` and `runtime`, without default features; the resolved
graph contains neither async, GC nor component-model support. Vigil compiles
bounded, locally installed YARA source through `Compiler::add_source` and
`Compiler::build`; scanned files are byte data, never guest WASM. It does not
deserialize supplied compiled rule objects. YARA-X uses one global engine.

| Advisory | Affected operation | Review and decision |
|---|---|---|
| [RUSTSEC-2026-0359](https://rustsec.org/advisories/RUSTSEC-2026-0359.html) | Dropping a guest-controlled recursive type chain | No guest WASM loading or recursive GC types in Vigil's rule input path. Accept a scoped exception pending a supported upstream upgrade. |
| [RUSTSEC-2026-0362](https://rustsec.org/advisories/RUSTSEC-2026-0362.html) | Mixing async entry and synchronous re-entry | Async feature absent and scanner calls synchronous. Accept a scoped exception. |
| [RUSTSEC-2026-0363](https://rustsec.org/advisories/RUSTSEC-2026-0363.html) | Component-model resource handle growth | Component model absent. Accept a scoped exception. |

These reachability conclusions are an engineering assessment of this locked
application, not patches to Wasmtime. Patched branches include 48.0.6 and 49.0.3;
they cannot be selected by a compatible 45.x lockfile update. A private fork or
unreviewed major transitive substitution would need separate maintenance and
acceptance. Recheck upstream YARA-X releases and retire exceptions when supported.
The older exceptions remain documented in `deny.toml` and the backlog.

CI runs `tools/ci/check_wasmtime_surface.py` to fail if feature unification adds
async, GC or the component model. Review all exceptions whenever adding a raw
WASM loader, compiled-rule deserialization, custom YARA modules or another engine.
The GTK build-time unmaintained advisory and MPL approvals are covered in
[the dependency license review](license-review-2026-10-14.md).
