/**
 * v6.3.0 — suggested filename for a saved chat code block, derived from
 * the markdown fence language. Purely a nicer DEFAULT in the native save
 * dialog: the backend sanitizes whatever the webview suggests
 * (chat_snippet.rs), so this map carries no security weight.
 */
const EXT_BY_LANGUAGE: Record<string, string> = {
  bash: "sh",
  sh: "sh",
  shell: "sh",
  zsh: "sh",
  python: "py",
  py: "py",
  javascript: "js",
  js: "js",
  typescript: "ts",
  ts: "ts",
  tsx: "tsx",
  jsx: "jsx",
  rust: "rs",
  rs: "rs",
  go: "go",
  ruby: "rb",
  rb: "rb",
  powershell: "ps1",
  ps1: "ps1",
  yaml: "yaml",
  yml: "yaml",
  json: "json",
  toml: "toml",
  xml: "xml",
  html: "html",
  css: "css",
  sql: "sql",
  diff: "diff",
  ini: "ini",
  conf: "conf",
  c: "c",
  cpp: "cpp",
  java: "java",
  kotlin: "kt",
  swift: "swift",
  perl: "pl",
  lua: "lua",
  dockerfile: "dockerfile",
};

export function suggestedSnippetName(language: string): string {
  const ext = EXT_BY_LANGUAGE[language.toLowerCase()] ?? "txt";
  return `snippet.${ext}`;
}
