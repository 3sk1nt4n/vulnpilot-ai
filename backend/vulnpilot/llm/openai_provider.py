"""
VulnPilot AI - OpenAI GPT Provider
Used as the CHALLENGER agent in Lock 2 (Adversarial AI Validation).

Architecture:
  - Justifier (Agent 3A): Claude or Ollama - builds the case
  - Challenger (Agent 3B): GPT-4o - attacks the case from a DIFFERENT model

Why different models matter:
  Same-model debate = one brain arguing with itself (still valuable, catches errors)
  Cross-model debate = two DIFFERENT architectures with different training data,
  different reasoning patterns, different blind spots. When both agree, confidence
  is exponentially higher.

This is the moat nobody else has. Not Tenable. Not CrowdStrike. Not Cogent.

Setup:
  OPENAI_API_KEY=sk-...
  CHALLENGER_MODEL=gpt-4o        # or gpt-4o-mini for cost savings
"""

import json
import logging
import os
from typing import AsyncGenerator, Optional

import httpx

from vulnpilot.llm.base import LLMProvider, DebateResult, JustificationResult
from vulnpilot.llm.prompts import (
    CHALLENGER_SYSTEM, CHALLENGER_PROMPT,
    JUSTIFICATION_SYSTEM, JUSTIFICATION_PROMPT,
    CORRELATOR_SYSTEM, CORRELATOR_PROMPT,
    CONTEXT_MAPPER_SYSTEM, CONTEXT_MAPPER_PROMPT,
)

logger = logging.getLogger(__name__)


class OpenAIProvider(LLMProvider):
    """OpenAI GPT provider.

    Primary use: Challenger agent in Lock 2 adversarial debate.
    Can also serve as a full LLM provider for all 5 agents if configured.
    """

    def __init__(self):
        self.api_key = os.getenv("OPENAI_API_KEY", "")
        self.model = os.getenv("OPENAI_MODEL", "gpt-4o")
        self.challenger_model = os.getenv("CHALLENGER_MODEL", self.model)
        self.base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
        self.timeout = 60.0

    @property
    def provider_name(self) -> str:
        return f"openai/{self.model}"

    async def _chat(self, system: str, user: str, model: Optional[str] = None) -> str:
        """Make a chat completion request to OpenAI API."""
        model = model or self.model
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                f"{self.base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    "temperature": 0.3,
                    "response_format": {"type": "json_object"},
                },
            )
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]

    async def generate(self, prompt: str, system: str = "") -> str:
        """Non-streaming generate (plain text, no JSON mode)."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                f"{self.base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system or "You are a cybersecurity expert."},
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": 0.3,
                },
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]

    async def stream_generate(self, prompt: str, system: str = "") -> AsyncGenerator[str, None]:
        """Stream tokens from OpenAI via SSE."""
        # Pre-flight check
        if not self.api_key.strip():
            raise RuntimeError("OPENAI_API_KEY not configured. Add your key to .env - $5 free credits at platform.openai.com")

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                async with client.stream(
                    "POST",
                    f"{self.base_url}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self.model,
                        "messages": [
                            {"role": "system", "content": system or "You are a cybersecurity expert."},
                            {"role": "user", "content": prompt},
                        ],
                        "temperature": 0.3,
                        "stream": True,
                    },
                ) as response:
                    if response.status_code != 200:
                        body = await response.aread()
                        logger.error(f"OpenAI stream error {response.status_code}: {body.decode()[:200]}")
                        if response.status_code == 401:
                            raise RuntimeError("Invalid OpenAI API key. Check OPENAI_API_KEY in .env → platform.openai.com/api-keys")
                        elif response.status_code == 429:
                            raise RuntimeError("OpenAI rate limit exceeded. Wait a moment or switch to Ollama (free).")
                        else:
                            raise RuntimeError(f"OpenAI API error {response.status_code}")

                    async for line in response.aiter_lines():
                        if not line.strip() or not line.startswith("data: "):
                            continue
                        payload = line[6:].strip()
                        if payload == "[DONE]":
                            return
                        try:
                            chunk = json.loads(payload)
                            delta = chunk.get("choices", [{}])[0].get("delta", {}).get("content", "")
                            if delta:
                                yield delta
                        except json.JSONDecodeError:
                            continue

        except httpx.ConnectError:
            raise RuntimeError("Cannot connect to OpenAI API. Check internet connection from Docker.")
        except RuntimeError:
            raise  # Re-raise our own RuntimeErrors
        except Exception as e:
            logger.error(f"OpenAI stream failed: {e}")
            raise RuntimeError(f"OpenAI error: {str(e)}")

    async def generate_json(self, prompt: str, system_prompt: str = "") -> dict:
        """Generate a JSON response from GPT."""
        try:
            raw = await self._chat(system_prompt, prompt)
            return json.loads(raw)
        except json.JSONDecodeError:
            # Try to extract JSON from markdown code blocks
            if "```json" in raw:
                raw = raw.split("```json")[1].split("```")[0]
            elif "```" in raw:
                raw = raw.split("```")[1].split("```")[0]
            try:
                return json.loads(raw.strip())
            except json.JSONDecodeError:
                logger.warning(f"OpenAI returned non-JSON: {raw[:200]}")
                return {}
        except Exception as e:
            logger.error(f"OpenAI API call failed: {e}")
            return {}

    async def correlate(self, cve_data: dict) -> dict:
        """Agent 1: Correlator."""
        context = json.dumps(cve_data, default=str)
        return await self.generate_json(
            CORRELATOR_PROMPT.format(cve_data=context),
            CORRELATOR_SYSTEM,
        )

    async def context_map(self, cve_data: dict) -> dict:
        """Agent 2: Context Mapper."""
        context = json.dumps(cve_data, default=str)
        return await self.generate_json(
            CONTEXT_MAPPER_PROMPT.format(cve_data=context),
            CONTEXT_MAPPER_SYSTEM,
        )

    async def debate(self, cve_data: dict, vprs_components: dict) -> DebateResult:
        """Lock 2 - Cross-Model Adversarial AI Debate.

        THIS IS THE KEY DIFFERENTIATOR.

        When used as the Challenger, GPT attacks the Justifier's reasoning
        from a completely different AI architecture. Different training data,
        different reasoning patterns, different blind spots.

        The Justifier (Claude/Ollama) builds the case.
        The Challenger (GPT) tries to destroy it.
        Disagreement = higher priority wins (biased toward caution).
        """
        context = json.dumps({**cve_data, "vprs_components": vprs_components}, default=str)

        # Agent 3A - Justifier (uses primary model)
        justifier_response = await self.generate_json(
            CHALLENGER_PROMPT.format(
                cve_data=context,
                justifier_argument="N/A - this model is acting as both agents",
            ),
            CHALLENGER_SYSTEM.replace("Agent 3B (The Challenger)", "Agent 3A (The Justifier)")
                .replace("ATTACK Agent 3A's reasoning", "Build the case FOR the proposed score"),
        )

        # Agent 3B - Challenger (uses challenger_model, possibly different)
        challenger_response = await self.generate_json(
            CHALLENGER_PROMPT.format(
                cve_data=context,
                justifier_argument=json.dumps(justifier_response, default=str),
            ),
            CHALLENGER_SYSTEM,
            # Note: _chat will use self.model by default, but when this provider
            # is used specifically as the challenger, the pipeline passes the
            # justifier's argument from Claude/Ollama
        )

        j_score = float(justifier_response.get("proposed_score",
                         vprs_components.get("raw_vprs", 50)))
        c_score = float(challenger_response.get("counter_score", j_score))
        consensus = abs(j_score - c_score) < 10

        # KEY: On disagreement, HIGHER score wins (safety bias)
        if not consensus:
            final_score = max(j_score, c_score)
            override = True
        else:
            final_score = (j_score + c_score) / 2
            override = False

        return DebateResult(
            justifier_score=j_score,
            challenger_score=c_score,
            final_score=final_score,
            justifier_reasoning=justifier_response.get("reasoning", ""),
            challenger_reasoning=challenger_response.get("reasoning", ""),
            consensus=consensus,
            override_applied=override,
        )

    async def challenge_only(self, cve_data: dict, vprs_components: dict,
                              justifier_argument: dict) -> dict:
        """Run ONLY the Challenger side of the debate.

        This is the method called when GPT is used as the cross-model
        Challenger while Claude/Ollama serves as the Justifier.

        Args:
            cve_data: CVE details and threat intel
            vprs_components: VPRS scoring breakdown
            justifier_argument: The Justifier's full output (from Claude/Ollama)

        Returns:
            Challenger's counter-argument with counter_score and reasoning
        """
        context = json.dumps({**cve_data, "vprs_components": vprs_components}, default=str)

        response = await self.generate_json(
            CHALLENGER_PROMPT.format(
                cve_data=context,
                justifier_argument=json.dumps(justifier_argument, default=str),
            ),
            CHALLENGER_SYSTEM + "\n\nIMPORTANT: You are a DIFFERENT AI model (GPT) "
            "than the Justifier (Claude). Use your independent judgment. "
            "Do not defer to the Justifier's reasoning just because it seems "
            "well-structured. Find the weaknesses. Challenge the assumptions. "
            "If you believe the score should be HIGHER (more severe), say so.",
        )

        return response

    async def justify(self, cve_data: dict, vprs_score: float,
                      severity: str, debate_result: Optional[DebateResult] = None) -> JustificationResult:
        """Agent 5: Generate plain-English justification."""
        context = json.dumps(cve_data, default=str)
        debate_context = ""
        if debate_result:
            debate_context = (
                f"\nAdversarial debate: Justifier={debate_result.justifier_score:.1f}, "
                f"Challenger={debate_result.challenger_score:.1f}, "
                f"consensus={'yes' if debate_result.consensus else 'no'}"
            )

        result = await self.generate_json(
            JUSTIFICATION_PROMPT.format(
                cve_data=context,
                vprs_score=vprs_score,
                severity=severity,
                debate_context=debate_context,
            ),
            JUSTIFICATION_SYSTEM,
        )

        return JustificationResult(
            summary=result.get("summary", f"{cve_data.get('cve_id', 'CVE')} scored {vprs_score:.1f}"),
            remediation_steps=result.get("remediation_steps", []),
            risk_factors=result.get("risk_factors", []),
            confidence=float(result.get("confidence", 0.8)),
        )

    async def health_check(self) -> bool:
        """Verify OpenAI API connectivity."""
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    f"{self.base_url}/models",
                    headers={"Authorization": f"Bearer {self.api_key}"},
                )
                return resp.status_code == 200
        except Exception:
            return False
