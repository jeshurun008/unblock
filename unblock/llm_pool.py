"""
Multi-provider LLM pool for unblock's LLM-based scanners.

Each entry below is a candidate model. At runtime, only models whose
required env var is actually set get added to the active pool — so
the pool grows automatically as the user adds more provider keys,
with zero code changes needed.

If a call to one model fails (rate limit, error, timeout), the pool
automatically falls back to the next active model. If the pool is
empty (no keys set at all), LLM scanning is skipped gracefully —
the AST scanners keep working regardless.
"""

import os
import time

# litellm is an optional dependency: the LLM scanners degrade gracefully when it's
# missing, so import it lazily (inside the function that calls it) rather than at
# module import time — otherwise its absence would break the whole CLI, including
# the deterministic AST scanners that never need it.
LITELLM_IMPORT_ERROR: ImportError | None = None
try:
    import litellm
    litellm.suppress_debug_info = True
except ImportError as e:  # pragma: no cover - depends on env
    litellm = None
    LITELLM_IMPORT_ERROR = e

# (model string for litellm, required env var)
CANDIDATE_MODELS = [
    ("groq/openai/gpt-oss-120b", "GROQ_API_KEY"),
    ("groq/openai/gpt-oss-20b", "GROQ_API_KEY"),
    ("groq/qwen/qwen3.6-27b", "GROQ_API_KEY"),
    ("gemini/gemini-2.0-flash", "GEMINI_API_KEY"),
    ("mistral/mistral-large-latest", "MISTRAL_API_KEY"),
    ("openrouter/meta-llama/llama-3.1-70b-instruct", "OPENROUTER_API_KEY"),
    ("cohere/command-r-plus", "COHERE_API_KEY"),
    ("openai/gpt-4o-mini", "OPENAI_API_KEY"),
    ("anthropic/claude-3-5-haiku-20241022", "ANTHROPIC_API_KEY"),
    ("together_ai/meta-llama/Llama-3-70b-chat-hf", "TOGETHER_API_KEY"),
]


def active_pool() -> list[str]:
    """Returns the list of model strings whose required key is actually set."""
    if litellm is None:
        return []  # litellm not installed -> force graceful skip of LLM scanners
    return [model for model, env_var in CANDIDATE_MODELS if os.environ.get(env_var)]


def pool_status() -> dict:
    """For CLI display — which providers are active vs missing a key."""
    active = []
    missing = []
    if litellm is None:
        return {"active": active, "missing": [(m, v, "litellm not installed") for m, v in CANDIDATE_MODELS]}
    for model, env_var in CANDIDATE_MODELS:
        if os.environ.get(env_var):
            active.append(model)
        else:
            missing.append((model, env_var))
    return {"active": active, "missing": missing}


def call_with_fallback(system_prompt: str, user_content: str, max_retries_per_model: int = 1):
    """
    Tries each active model in order. Returns (response_text, model_used) on
    success, or (None, None) if every active model fails.
    """
    pool = active_pool()
    if not pool:
        return None, None

    for model in pool:
        for attempt in range(max_retries_per_model + 1):
            try:
                response = litellm.completion(
                    model=model,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_content},
                    ],
                    temperature=0,
                    timeout=30,
                )
                text = response.choices[0].message.content
                return text, model
            except litellm.RateLimitError:
                break  # move to next model in pool immediately
            except Exception:
                if attempt < max_retries_per_model:
                    time.sleep(1)
                    continue
                break  # give up on this model, try next

    return None, None
