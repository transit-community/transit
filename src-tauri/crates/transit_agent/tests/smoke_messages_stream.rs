//! Manual smoke test against the real providers — streams a short
//! message through `DirectAnthropic` / `DirectOpenAI` end-to-end.
//!
//! `#[ignore]`d by default — run with:
//!
//! ```bash
//! ANTHROPIC_API_KEY=sk-ant-... cargo test -p transit_agent --test smoke_messages_stream -- --ignored anthropic
//! OPENAI_API_KEY=sk-...        cargo test -p transit_agent --test smoke_messages_stream -- --ignored openai
//! ```
//!
//! Expected pass: prints the streamed assistant response to stderr and a
//! final `TokenUsage` line. The env var is read by the TEST only — the
//! application never reads provider keys from the environment.

use futures::StreamExt;
use secrecy::SecretString;
use transit_agent::{
    DirectAnthropic, DirectOpenAI, LlmClient, LlmMessage, LlmRequest, LlmStreamEvent, OpenAiAuth,
};

fn request(model: String) -> LlmRequest {
    LlmRequest {
        model,
        system: Some(
            "You are a smoke test. Reply with exactly the words \"hello smoke test\" and nothing else."
                .into(),
        ),
        messages: vec![LlmMessage::User("respond now".into())],
        max_tokens: Some(64),
        tools: None,
    }
}

async fn drive(client: &dyn LlmClient, req: LlmRequest, label: &str) {
    let mut stream = client
        .messages(req)
        .await
        .expect("messages call must succeed against the provider");

    let mut text = String::new();
    let mut final_usage = None;
    while let Some(event) = stream.next().await {
        match event.expect("stream event must not error") {
            LlmStreamEvent::TextDelta(t) => text.push_str(&t),
            LlmStreamEvent::Completed(u) => final_usage = Some(u),
            LlmStreamEvent::ToolUseComplete { .. } => {
                panic!("smoke test sent tools: None; tool_use is a regression")
            }
        }
    }

    eprintln!("=== {label} response ===");
    eprintln!("text: {text}");
    eprintln!("usage: {final_usage:?}");
    assert!(!text.is_empty(), "expected at least one text delta");
    let u = final_usage.expect("Completed event before stream close");
    assert!(u.input_total() > 0, "expected non-zero input tokens");
    assert!(u.output > 0, "expected non-zero output tokens");
}

#[tokio::test]
#[ignore = "requires a real ANTHROPIC_API_KEY; run with `--ignored`"]
async fn smoke_anthropic_messages_stream() {
    let key = std::env::var("ANTHROPIC_API_KEY").expect("ANTHROPIC_API_KEY must be set");
    let client = DirectAnthropic::new(SecretString::new(key.into()), false);
    let model = std::env::var("SMOKE_MODEL").unwrap_or_else(|_| "claude-sonnet-4-6".into());
    drive(&client, request(model), "anthropic /v1/messages").await;
}

#[tokio::test]
#[ignore = "requires a real OPENAI_API_KEY; run with `--ignored`"]
async fn smoke_openai_responses_stream() {
    let key = std::env::var("OPENAI_API_KEY").expect("OPENAI_API_KEY must be set");
    let client = DirectOpenAI::new(OpenAiAuth::ApiKey(SecretString::new(key.into())), false);
    let model = std::env::var("SMOKE_MODEL").unwrap_or_else(|_| "gpt-5.6-sol".into());
    drive(&client, request(model), "openai /v1/responses").await;
}
