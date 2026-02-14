"""
VulnPilot AI - Anthropic Claude LLM Provider
Production-grade LLM inference via Claude API.
Best-in-class justification quality. Board-ready prose.
"""

import json
import logging
import os
from typing import AsyncGenerator, Optional

import anthropic

from vulnpilot.llm.base import LLMProvider, DebateResult, JustificationResult
from vulnpilot.llm.prompts import (
    CORRELATOR_SYSTEM, CORRELATOR_PROMPT,
    CONTEXT_MAPPER_SYSTEM, CONTEXT_MAPPER_PROMPT,
    JUSTIFIER_SYSTEM, JUSTIFIER_PROMPT,
    CHALLENGER_SYSTEM, CHALLENGER_PROMPT,
)

logger = logging.getLogger(__name__)


class AnthropicProvider(LLMProvider):
    """Cloud LLM provider using Anthropic Claude API."""

    def __init__(self):
        self.client = anthropic.AsyncAnthropic(
            api_key=os.getenv("ANTHROPIC_API_KEY", "")
        )
        self.model = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-20250514")

    async def generate(self, prompt: str, system: str = "") -> str:
        try:
            resp = await self.client.messages.create(
                model=self.model,
                max_tokens=2048,
                system=system or "You are a cybersecurity expert.",
                messages=[{"role": "user", "content": prompt}],
            )
            return resp.content[0].text
        except anthropic.APIError as e:
            logger.error(f"Anthropic API error: {e}")
            raise

    async def stream_generate(self, prompt: str, system: str = "") -> AsyncGenerator[str, None]:
        """Stream tokens from Claude using Anthropic SDK native streaming."""
        # Pre-flight check: fail fast if no API key
        api_key = os.getenv("ANTHROPIC_API_KEY", "").strip()
        if not api_key:
            raise RuntimeError("ANTHROPIC_API_KEY not configured. Add your key to .env - $5 free credits at console.anthropic.com")

        try:
            async with self.client.messages.stream(
                model=self.model,
                max_tokens=2048,
                system=system or "You are a cybersecurity expert.",
                messages=[{"role": "user", "content": prompt}],
            ) as stream:
                async for text in stream.text_stream:
                    yield text
        except anthropic.AuthenticationError as e:
            logger.error(f"Anthropic auth error: {e}")
            raise RuntimeError("Invalid Anthropic API key. Check ANTHROPIC_API_KEY in .env → console.anthropic.com/settings/keys")
        except anthropic.APIStatusError as e:
            logger.error(f"Anthropic streaming error: {e}")
            if e.status_code == 401:
                raise RuntimeError("Invalid Anthropic API key. Check ANTHROPIC_API_KEY in .env")
            elif e.status_code == 429:
                raise RuntimeError("Anthropic rate limit exceeded. Wait a moment or switch to Ollama (free).")
            else:
                raise RuntimeError(f"Anthropic API error {e.status_code}: {e.message}")
        except anthropic.APIConnectionError as e:
            logger.error(f"Anthropic connection error: {e}")
            raise RuntimeError("Cannot reach Anthropic API. Check internet connection from Docker.")
        except Exception as e:
            logger.error(f"Anthropic stream failed: {e}")
            raise RuntimeError(f"Anthropic error: {str(e)}")

    async def generate_json(self, prompt: str, system: str = "") -> dict:
        system_with_json = (
            f"{system}\n\nRespond with valid JSON only. "
            "No markdown code fences. No text outside the JSON object."
        )
        raw = await self.generate(prompt, system_with_json)

        cleaned = raw.strip()
        if cleaned.startswith("```json"):
            cleaned = cleaned[7:]
        if cleaned.startswith("```"):
            cleaned = cleaned[3:]
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]
        cleaned = cleaned.strip()

        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            logger.warning(f"Failed to parse JSON from Claude, raw: {raw[:200]}")
            return {"error": "json_parse_failed", "raw": raw[:500]}

    async def debate(self, cve_data: dict, vprs_components: dict) -> DebateResult:
        """Lock 2 - Adversarial AI Debate with Claude.
        Same logic as Ollama but with superior reasoning quality.
        """
        context = json.dumps({**cve_data, "vprs_components": vprs_components}, default=str)

        # Agent 3A - The Justifier
        justifier_response = await self.generate_json(
            JUSTIFIER_PROMPT.format(cve_data=context),
            JUSTIFIER_SYSTEM,
        )

        # Agent 3B - The Challenger (sees Justifier's argument)
        challenger_response = await self.generate_json(
            CHALLENGER_PROMPT.format(
                cve_data=context,
                justifier_argument=json.dumps(justifier_response, default=str),
            ),
            CHALLENGER_SYSTEM,
        )

        j_score = float(justifier_response.get("proposed_score", vprs_components.get("raw_vprs", 50)))
        c_score = float(challenger_response.get("counter_score", j_score))
        consensus = abs(j_score - c_score) < 10

        # Higher score wins on disagreement - biased toward caution
        if not consensus:
            final_score = max(j_score, c_score)
            override = True
        else:
            final_score = (j_score + c_score) / 2
            override = False

        return DebateResult(
            justifier_score=j_score,
            challenger_score=c_score,
            final_score=round(final_score, 1),
            justifier_reasoning=justifier_response.get("reasoning", ""),
            challenger_reasoning=challenger_response.get("reasoning", ""),
            consensus=consensus,
            override_applied=override,
        )

    async def justify(
        self, cve_data: dict, vprs_score: float, vprs_components: dict
    ) -> JustificationResult:
        context = json.dumps(
            {**cve_data, "vprs_score": vprs_score, "vprs_components": vprs_components},
            default=str,
        )
        result = await self.generate_json(
            f"Generate a plain-English justification for this vulnerability's VPRS score.\n\n{context}",
            "You are a senior cybersecurity analyst at a Fortune 500 company writing "
            "vulnerability justifications for technical teams and executive leadership. "
            "Respond with JSON: summary, detailed, board_ready, remediation_steps. "
            "The board_ready version must be understandable by a non-technical CEO.",
        )

        return JustificationResult(
            summary=result.get("summary", f"VPRS {vprs_score}: {cve_data.get('cve_id', 'Unknown')}"),
            detailed=result.get("detailed", ""),
            board_ready=result.get("board_ready", ""),
            remediation_steps=result.get("remediation_steps", ""),
        )

    async def correlate(self, cve_data: dict, threat_intel: dict) -> dict:
        context = json.dumps({**cve_data, "threat_intel": threat_intel}, default=str)
        return await self.generate_json(
            CORRELATOR_PROMPT.format(cve_data=context),
            CORRELATOR_SYSTEM,
        )

    async def map_context(self, cve_data: dict, asset_data: dict) -> dict:
        context = json.dumps({**cve_data, "asset": asset_data}, default=str)
        return await self.generate_json(
            CONTEXT_MAPPER_PROMPT.format(cve_data=context),
            CONTEXT_MAPPER_SYSTEM,
        )

    async def health_check(self) -> bool:
        try:
            resp = await self.client.messages.create(
                model=self.model,
                max_tokens=10,
                messages=[{"role": "user", "content": "ping"}],
            )
            return True
        except Exception:
            return False

    @property
    def provider_name(self) -> str:
        return "anthropic"
