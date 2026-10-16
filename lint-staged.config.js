// lint-staged config — runs only on staged files for fast pre-commit feedback.
//
// Rust files trigger workspace-wide cargo fmt --check and cargo clippy
// (per-file fmt/clippy doesn't compose with workspace state). Frontend
// files run through prettier + eslint.

export default {
  "*.{ts,tsx,js,jsx}": ["prettier --write", "eslint --fix"],
  "*.{json,yaml,yml,html,css}": ["prettier --write"],
  "src-tauri/**/*.rs": () => [
    "cargo fmt --manifest-path src-tauri/Cargo.toml --all -- --check",
    "cargo clippy --manifest-path src-tauri/Cargo.toml --workspace --all-targets -- -D warnings",
  ],
};
