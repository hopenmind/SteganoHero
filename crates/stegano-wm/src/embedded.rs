//! The embedded llama.cpp backend (feature `embedded-llama`, off by default).
//!
//! In-process GGUF inference, fully local and offline, following the A-typik
//! pattern (a model loaded once, a fresh context per call). This is the only
//! part of the crate that pulls a C++ build, so it lives behind a feature: the
//! default build stays pure Rust. Being local, it is exempt from the disclaimer
//! gate; content never leaves the machine.

// This module mirrors A-typik's proven path against llama-cpp-2 0.1, which uses
// the `Special` token-to-string API the crate has since deprecated. The
// deprecated path still works and is what builds on this machine; allow it here
// rather than diverge from the reference until the crate is upgraded.
#![allow(deprecated)]

use std::num::NonZeroU32;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

use llama_cpp_2::{
    context::params::LlamaContextParams,
    llama_backend::LlamaBackend,
    llama_batch::LlamaBatch,
    model::{params::LlamaModelParams, AddBos, LlamaChatMessage, LlamaModel, Special},
    sampling::LlamaSampler,
};

use crate::backend::{BackendError, InferenceBackend, Locality};
use crate::logprob::{token_logprob, LogprobProvider};

/// The most new tokens a single rewrite will generate.
const MAX_NEW: i32 = 512;

fn unavailable(e: impl std::fmt::Display) -> BackendError {
    BackendError::Unavailable(e.to_string())
}

/// The llama.cpp backend is a process-wide singleton: `LlamaBackend::init` may
/// run only once per process, so every model shares this one. Wrapping it lets
/// it live in a `static`; access is a shared `&` used to create read-only
/// inference contexts.
struct SharedBackend(LlamaBackend);
// SAFETY: the backend holds llama.cpp's global init state, read-only after
// setup; contexts borrow it by shared reference. Mirrors the reference tool.
unsafe impl Send for SharedBackend {}
unsafe impl Sync for SharedBackend {}

static BACKEND: OnceLock<SharedBackend> = OnceLock::new();
static INIT_LOCK: Mutex<()> = Mutex::new(());

/// The one process-wide backend, initialized on first use. Sharing it is what
/// lets two models (a Binoculars pair) load in the same process. The init is
/// serialized with a mutex and double-checked, so `LlamaBackend::init` runs
/// exactly once even when several models load concurrently (parallel tests).
fn shared_backend() -> Result<&'static LlamaBackend, BackendError> {
    if let Some(handle) = BACKEND.get() {
        return Ok(&handle.0);
    }
    let _guard = INIT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // Re-check under the lock: another thread may have initialized it while we
    // waited.
    if let Some(handle) = BACKEND.get() {
        return Ok(&handle.0);
    }
    let backend = LlamaBackend::init().map_err(unavailable)?;
    let _ = BACKEND.set(SharedBackend(backend));
    Ok(&BACKEND.get().expect("backend set under the init lock").0)
}

/// An in-process GGUF model that rewrites text locally.
pub struct EmbeddedLlamaBackend {
    // The model is leaked to `'static` so a per-call context can borrow it.
    model: &'static LlamaModel,
    system_prompt: String,
    n_threads: i32,
}

impl EmbeddedLlamaBackend {
    /// Load a GGUF model from `model_path`. Errors by name when the file is
    /// missing or the model cannot be loaded, never a silent failure.
    pub fn load(
        model_path: impl AsRef<Path>,
        system_prompt: impl Into<String>,
    ) -> Result<Self, BackendError> {
        let path = model_path.as_ref();
        if !path.exists() {
            return Err(BackendError::Unavailable(format!(
                "model file not found: {}",
                path.display()
            )));
        }
        let backend = shared_backend()?;
        let model = LlamaModel::load_from_file(backend, path, &LlamaModelParams::default())
            .map_err(unavailable)?;
        let model: &'static LlamaModel = Box::leak(Box::new(model));
        let n_threads = std::thread::available_parallelism()
            .map(|n| n.get() as i32)
            .unwrap_or(4)
            .max(1);
        Ok(Self {
            model,
            system_prompt: system_prompt.into(),
            n_threads,
        })
    }
}

impl InferenceBackend for EmbeddedLlamaBackend {
    fn rewrite(&self, text: &str) -> Result<String, BackendError> {
        let template = self.model.chat_template(None).map_err(unavailable)?;
        let system =
            LlamaChatMessage::new("system".to_string(), self.system_prompt.clone()).map_err(unavailable)?;
        let user = LlamaChatMessage::new("user".to_string(), text.to_string()).map_err(unavailable)?;
        let prompt = self
            .model
            .apply_chat_template(&template, &[system, user], true)
            .map_err(unavailable)?;
        let tokens = self.model.str_to_token(&prompt, AddBos::Always).map_err(unavailable)?;
        if tokens.is_empty() {
            return Err(BackendError::Empty);
        }

        let ctx_params = LlamaContextParams::default()
            .with_n_ctx(Some(NonZeroU32::new(2048).unwrap()))
            .with_n_threads(self.n_threads);
        let mut ctx = self
            .model
            .new_context(shared_backend()?, ctx_params)
            .map_err(unavailable)?;

        let n = tokens.len();
        let mut batch = LlamaBatch::new(n, 1);
        for (i, token) in tokens.iter().enumerate() {
            batch.add(*token, i as i32, &[0], i == n - 1).map_err(unavailable)?;
        }
        ctx.decode(&mut batch).map_err(unavailable)?;

        let mut sampler =
            LlamaSampler::chain_simple([LlamaSampler::temp(0.2), LlamaSampler::greedy()]);
        let mut output = String::new();
        let mut position = n as i32;
        let mut last = n as i32 - 1;
        let mut produced = 0;

        loop {
            let token = sampler.sample(&ctx, last);
            if self.model.is_eog_token(token) || produced >= MAX_NEW {
                break;
            }
            #[allow(deprecated)]
            if let Ok(piece) = self.model.token_to_str(token, Special::Tokenize) {
                output.push_str(&piece);
            }
            sampler.accept(token);

            let mut step = LlamaBatch::new(1, 1);
            step.add(token, position, &[0], true).map_err(unavailable)?;
            ctx.decode(&mut step).map_err(unavailable)?;
            last = position;
            position += 1;
            produced += 1;
        }

        let output = output.trim().to_string();
        if output.is_empty() {
            return Err(BackendError::Empty);
        }
        Ok(output)
    }

    fn locality(&self) -> Locality {
        Locality::Local
    }
}

impl LogprobProvider for EmbeddedLlamaBackend {
    fn sequence_logprobs(&self, text: &str) -> Result<Vec<f64>, BackendError> {
        let tokens = self.model.str_to_token(text, AddBos::Always).map_err(unavailable)?;
        if tokens.len() < 2 {
            return Ok(Vec::new());
        }
        let n = tokens.len();
        let n_ctx = (n as u32 + 8).max(512);
        let ctx_params = LlamaContextParams::default()
            .with_n_ctx(Some(NonZeroU32::new(n_ctx).unwrap()))
            .with_n_threads(self.n_threads);
        let mut ctx = self
            .model
            .new_context(shared_backend()?, ctx_params)
            .map_err(unavailable)?;

        // Enable logits at every position so each one predicts the next token.
        let mut batch = LlamaBatch::new(n, 1);
        for (i, token) in tokens.iter().enumerate() {
            batch.add(*token, i as i32, &[0], true).map_err(unavailable)?;
        }
        ctx.decode(&mut batch).map_err(unavailable)?;

        // Position i predicts token i+1; score each actual next token.
        let mut out = Vec::with_capacity(n - 1);
        for i in 0..n - 1 {
            let logits = ctx.get_logits_ith(i as i32);
            let next = tokens[i + 1].0 as usize;
            out.push(token_logprob(logits, next));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_model_file_is_reported_by_name() {
        // Returns before touching the llama backend, so this needs no model and
        // runs no inference; it only proves the load path errors honestly.
        let result = EmbeddedLlamaBackend::load("this-model-does-not-exist.gguf", "Rewrite.");
        assert!(matches!(result, Err(BackendError::Unavailable(_))));
    }

    /// Live check against a real model. Ignored by default: set
    /// STEGANO_WM_TEST_MODEL to a GGUF path and run with `--ignored`.
    #[test]
    #[ignore = "needs a real GGUF; set STEGANO_WM_TEST_MODEL and run with --ignored"]
    fn live_logprobs_over_a_real_model_are_sane() {
        use crate::logprob::perplexity;
        let path = std::env::var("STEGANO_WM_TEST_MODEL")
            .expect("set STEGANO_WM_TEST_MODEL to a GGUF path");
        let backend = EmbeddedLlamaBackend::load(&path, "You rewrite text.")
            .expect("the model loads");
        let logprobs = backend
            .sequence_logprobs("The quick brown fox jumps over the lazy dog.")
            .expect("the model scores the text");
        assert!(!logprobs.is_empty(), "a scored sequence is not empty");
        assert!(
            logprobs.iter().all(|lp| lp.is_finite() && *lp <= 1e-6),
            "each log-probability is finite and non-positive"
        );
        let ppl = perplexity(&logprobs).unwrap();
        assert!(ppl.is_finite() && ppl > 1.0, "perplexity {ppl} is finite and > 1");
    }
}
