//! Local, pinned ONNX inference. External data files and remote model loading
//! are excluded: the model is parsed from the exact bounded bytes we hashed.
use super::window::{FEATURE_NAMES, Features};
use anyhow::{Result, ensure};
use sha2::{Digest, Sha256};
use std::path::Path;
use tract_onnx::prelude::*;

pub struct OnnxScorer {
    model: std::sync::Arc<TypedRunnableModel>,
}
struct NoExternalData;
impl tract_onnx::data_resolver::ModelDataResolver for NoExternalData {
    fn read_bytes_from_path(
        &self,
        _: &mut Vec<u8>,
        _: &Path,
        _: usize,
        _: Option<usize>,
    ) -> TractResult<()> {
        anyhow::bail!("external ONNX tensor data is not permitted; export a self-contained model")
    }
}
impl std::fmt::Debug for OnnxScorer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnnxScorer").finish_non_exhaustive()
    }
}
impl OnnxScorer {
    pub fn load(path: &Path, expected_sha256: &str) -> Result<Self> {
        let expected = whohack_core::hex::decode32(expected_sha256)?;
        let file = std::fs::File::open(path)?;
        ensure!(
            file.metadata()?.len() <= 8 * 1024 * 1024,
            "Tier 1 model exceeds 8 MiB"
        );
        use std::io::Read;
        let mut bytes = Vec::new();
        file.take(8 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 8 * 1024 * 1024, "Tier 1 model exceeds 8 MiB");
        ensure!(
            <[u8; 32]>::from(Sha256::digest(&bytes)) == expected,
            "Tier 1 model digest mismatch"
        );
        let mut parser = tract_onnx::onnx();
        parser.provider = std::sync::Arc::new(NoExternalData);
        let model = parser
            .model_for_read(&mut std::io::Cursor::new(bytes))?
            .with_input_fact(0, f32::fact([1, FEATURE_NAMES.len()]).into())?
            .into_optimized()?
            .into_runnable()?;
        let scorer = Self { model };
        scorer.score(&Features::default())?;
        Ok(scorer)
    }
    pub fn score(&self, features: &Features) -> Result<f32> {
        let vector = features.vector();
        ensure!(
            vector.iter().all(|x| x.is_finite()),
            "non-finite feature input"
        );
        let input = Tensor::from_shape(&[1, FEATURE_NAMES.len()], &vector)?;
        let output = self.model.run(tvec!(input.into()))?;
        ensure!(output.len() == 1, "Tier 1 model must have one score output");
        let tensor = output[0].try_as_plain_ram()?;
        let values = tensor.as_slice::<f32>()?;
        ensure!(
            values.len() == 1 && values[0].is_finite() && (0.0..=1.0).contains(&values[0]),
            "Tier 1 model must emit one finite score in [0,1]"
        );
        Ok(values[0])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pinned_synthetic_model_and_tamper_rejection() {
        let root = std::env::var_os("WHOHACK_TEST_ROOT")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."));
        let path = root.join("ml/fixtures/toy-tier1.onnx");
        let sha = whohack_core::hex::encode(&Sha256::digest(std::fs::read(&path).unwrap()));
        let scorer = OnnxScorer::load(&path, &sha).unwrap();
        let low = scorer.score(&Features::default()).unwrap();
        assert!((low - 0.11920292).abs() < 0.00001);
        let high = scorer
            .score(&Features {
                unexpected_severity: 6,
                tainted: true,
                unsigned: true,
                ..Default::default()
            })
            .unwrap();
        assert!(high > low);
        assert!(OnnxScorer::load(&path, &"00".repeat(32)).is_err());
    }
}
