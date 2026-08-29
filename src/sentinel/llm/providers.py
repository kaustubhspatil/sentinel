"""Concrete LLM providers.

Four backends, chosen so the project can run its high-volume work at zero marginal cost
while still making a genuine production call against two managed services:

  gemini  - Google AI Studio free tier. Carries the evaluation traffic, which is
            thousands of calls and would otherwise dominate the budget.
  vertex  - Vertex AI on the project's own GCP account.
  azure   - Azure OpenAI.
  ollama  - a local model on the workstation GPU. The offline fallback, and the only
            option that keeps working with no network at all.

Each provider reports token usage where the API supplies it, and estimates it otherwise -
flagged as an estimate rather than quietly presented as measured.
"""
from __future__ import annotations

import json
import time

import httpx

from sentinel.config import settings
from sentinel.llm.base import LLMResponse, Message, Timer, render_prompt

TIMEOUT = httpx.Timeout(90.0, connect=15.0)


def _approx_tokens(text: str) -> int:
    """Rough token estimate for providers that do not report usage: ~4 chars/token."""
    return max(1, len(text) // 4)


class GeminiProvider:
    name = "gemini"
    BASE = "https://generativelanguage.googleapis.com/v1beta"

    def available(self) -> bool:
        return bool(settings.gemini_api_key)

    def list_models(self) -> list[str]:
        with httpx.Client(timeout=TIMEOUT) as c:
            r = c.get(f"{self.BASE}/models", params={"key": settings.gemini_api_key})
            r.raise_for_status()
            return [
                m["name"].removeprefix("models/")
                for m in r.json().get("models", [])
                if "generateContent" in (m.get("supportedGenerationMethods") or [])
            ]

    def complete(self, messages: list[Message], model: str, **kwargs) -> LLMResponse:
        system, rest = render_prompt(messages)
        body: dict = {
            "contents": [
                {"role": "user" if m.role == "user" else "model",
                 "parts": [{"text": m.content}]}
                for m in rest
            ],
            "generationConfig": {
                "temperature": kwargs.get("temperature", 0.0),
                "maxOutputTokens": kwargs.get("max_tokens", 1024),
            },
        }
        if system:
            body["systemInstruction"] = {"parts": [{"text": system}]}

        t = Timer()
        try:
            with httpx.Client(timeout=TIMEOUT) as c:
                r = c.post(
                    f"{self.BASE}/models/{model}:generateContent",
                    params={"key": settings.gemini_api_key},
                    json=body,
                )
                r.raise_for_status()
                data = r.json()
        except Exception as exc:  # noqa: BLE001
            return LLMResponse("", self.name, model, latency_ms=t.ms,
                               error=f"{type(exc).__name__}: {exc}")

        cand = (data.get("candidates") or [{}])[0]
        parts = (cand.get("content") or {}).get("parts") or []
        text = "".join(p.get("text", "") for p in parts)
        usage = data.get("usageMetadata") or {}
        return LLMResponse(
            text=text,
            provider=self.name,
            model=model,
            input_tokens=usage.get("promptTokenCount", 0),
            output_tokens=usage.get("candidatesTokenCount", 0),
            latency_ms=t.ms,
            finish_reason=cand.get("finishReason", ""),
        )


class VertexProvider:
    name = "vertex"

    def available(self) -> bool:
        """Configured if any Application Default Credential resolves.

        Deliberately not "is GOOGLE_APPLICATION_CREDENTIALS set": the project's GCP org
        policy blocks service-account key creation (disableServiceAccountKeyCreation),
        which is the right default - long-lived key files are the most commonly leaked
        cloud credential. ADC covers both real cases here: a developer's gcloud login
        locally, and the VM's own metadata identity on the backbone. No key ever exists
        on disk.
        """
        if not settings.gcp_project_id:
            return False
        try:
            from google.auth import default

            creds, _ = default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
            return creds is not None
        except Exception:  # noqa: BLE001
            return False

    def _token(self) -> str:
        from google.auth import default
        from google.auth.transport.requests import Request

        creds, _ = default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
        creds.refresh(Request())
        return creds.token

    def complete(self, messages: list[Message], model: str, **kwargs) -> LLMResponse:
        system, rest = render_prompt(messages)
        region = settings.gcp_region
        url = (
            f"https://{region}-aiplatform.googleapis.com/v1/projects/"
            f"{settings.gcp_project_id}/locations/{region}/publishers/google/"
            f"models/{model}:generateContent"
        )
        body: dict = {
            "contents": [
                {"role": "user" if m.role == "user" else "model",
                 "parts": [{"text": m.content}]}
                for m in rest
            ],
            "generationConfig": {
                "temperature": kwargs.get("temperature", 0.0),
                "maxOutputTokens": kwargs.get("max_tokens", 1024),
            },
        }
        if system:
            body["systemInstruction"] = {"parts": [{"text": system}]}

        t = Timer()
        try:
            token = self._token()
            with httpx.Client(timeout=TIMEOUT) as c:
                r = c.post(url, json=body, headers={"Authorization": f"Bearer {token}"})
                r.raise_for_status()
                data = r.json()
        except Exception as exc:  # noqa: BLE001
            return LLMResponse("", self.name, model, latency_ms=t.ms,
                               error=f"{type(exc).__name__}: {exc}")

        cand = (data.get("candidates") or [{}])[0]
        parts = (cand.get("content") or {}).get("parts") or []
        usage = data.get("usageMetadata") or {}
        return LLMResponse(
            text="".join(p.get("text", "") for p in parts),
            provider=self.name,
            model=model,
            input_tokens=usage.get("promptTokenCount", 0),
            output_tokens=usage.get("candidatesTokenCount", 0),
            latency_ms=t.ms,
            finish_reason=cand.get("finishReason", ""),
        )


class AzureOpenAIProvider:
    name = "azure"
    API_VERSION = "2024-10-21"

    def available(self) -> bool:
        return bool(settings.azure_openai_endpoint and settings.azure_openai_api_key)

    def complete(self, messages: list[Message], model: str, **kwargs) -> LLMResponse:
        endpoint = (settings.azure_openai_endpoint or "").rstrip("/")
        deployment = model or settings.azure_openai_deployment
        url = f"{endpoint}/openai/deployments/{deployment}/chat/completions"

        payload = {
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "temperature": kwargs.get("temperature", 0.0),
            "max_tokens": kwargs.get("max_tokens", 1024),
        }

        # Retry the same deployment before giving up. A GlobalStandard deployment is
        # served from several regions and returns intermittent 404s while a capacity
        # change propagates - the identical request succeeds on the next attempt. Falling
        # straight through to another provider on a transient status wastes the one
        # provider that works and, worse, reports the *fallback's* error as the failure.
        t = Timer()
        last_exc: Exception | None = None
        for attempt in range(3):
            try:
                with httpx.Client(timeout=TIMEOUT) as c:
                    r = c.post(
                        url,
                        params={"api-version": self.API_VERSION},
                        headers={"api-key": settings.azure_openai_api_key},
                        json=payload,
                    )
                    if r.status_code in (404, 408, 429, 500, 502, 503, 504) and attempt < 2:
                        time.sleep(0.75 * (attempt + 1))
                        continue
                    r.raise_for_status()
                    data = r.json()
                    break
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                if attempt == 2:
                    return LLMResponse("", self.name, deployment, latency_ms=t.ms,
                                       error=f"{type(exc).__name__}: {exc}")
                time.sleep(0.75 * (attempt + 1))
        else:
            return LLMResponse("", self.name, deployment, latency_ms=t.ms,
                               error=f"exhausted retries: {last_exc}")

        choice = (data.get("choices") or [{}])[0]
        usage = data.get("usage") or {}
        text = (choice.get("message") or {}).get("content") or ""
        finish = choice.get("finish_reason", "")

        # A 200 response with empty content and non-zero completion tokens is the
        # signature of a reasoning model spending the whole budget on hidden reasoning
        # tokens. It is a failure, but it does not look like one: nothing raises, usage
        # is reported, and only the text is missing. Naming it here stops the router
        # from silently falling through to another provider and reporting that provider's
        # error instead of this one.
        err = ""
        if not text.strip():
            err = (
                f"empty completion (finish_reason={finish!r}, "
                f"completion_tokens={usage.get('completion_tokens', 0)}) - "
                "raise max_tokens if the deployment routes to a reasoning model"
            )

        return LLMResponse(
            text=text,
            provider=self.name,
            model=deployment,
            input_tokens=usage.get("prompt_tokens", 0),
            output_tokens=usage.get("completion_tokens", 0),
            latency_ms=t.ms,
            finish_reason=finish,
            error=err,
        )


class OllamaProvider:
    name = "ollama"

    def available(self) -> bool:
        try:
            with httpx.Client(timeout=httpx.Timeout(3.0)) as c:
                return c.get(f"{settings.ollama_host}/api/tags").status_code == 200
        except Exception:  # noqa: BLE001
            return False

    def complete(self, messages: list[Message], model: str, **kwargs) -> LLMResponse:
        t = Timer()
        try:
            with httpx.Client(timeout=TIMEOUT) as c:
                r = c.post(
                    f"{settings.ollama_host}/api/chat",
                    json={
                        "model": model,
                        "messages": [{"role": m.role, "content": m.content} for m in messages],
                        "stream": False,
                        "options": {"temperature": kwargs.get("temperature", 0.0)},
                    },
                )
                r.raise_for_status()
                data = r.json()
        except Exception as exc:  # noqa: BLE001
            return LLMResponse("", self.name, model, latency_ms=t.ms,
                               error=f"{type(exc).__name__}: {exc}")

        text = (data.get("message") or {}).get("content", "")
        return LLMResponse(
            text=text,
            provider=self.name,
            model=model,
            input_tokens=data.get("prompt_eval_count") or _approx_tokens(
                json.dumps([m.content for m in messages])
            ),
            output_tokens=data.get("eval_count") or _approx_tokens(text),
            latency_ms=t.ms,
            finish_reason=data.get("done_reason", ""),
        )


PROVIDERS = {
    p.name: p
    for p in (GeminiProvider(), VertexProvider(), AzureOpenAIProvider(), OllamaProvider())
}
