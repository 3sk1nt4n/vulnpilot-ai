"""
VulnPilot AI - LLM Provider Interface (Layer 1)
The most critical abstraction. Switch between Ollama (free, local),
Anthropic Claude (production, cloud), and OpenAI GPT with a single env var.

LLM_PROVIDER=ollama     → Free local dev with qwen2.5:7b
LLM_PROVIDER=anthropic  → Production SaaS with Claude
LLM_PROVIDER=openai     → GPT-4o (also used as cross-model Challenger)

VPRS scores are IDENTICAL in all modes.
Only justification text quality and streaming speed differ.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import AsyncGenerator, Optional


@dataclass
class DebateResult:
    """Output from adversarial AI debate (Lock 2)."""
    justifier_score: float       # Agent 3A's proposed VPRS score
    challenger_score: float      # Agent 3B's counter-score
    final_score: float           # Resolved score (higher wins on disagreement)
    justifier_reasoning: str     # Agent 3A's argument
    challenger_reasoning: str    # Agent 3B's counter-argument
    consensus: bool              # Did agents agree?
    override_applied: bool       # Was the score changed by debate?


@dataclass
class JustificationResult:
    """Plain-English justification for a VPRS score."""
    summary: str                 # 1-2 sentence executive summary
    detailed: str                # Full justification with factor breakdown
    board_ready: str             # Non-technical version for executives
    remediation_steps: str       # Specific fix instructions


class LLMProvider(ABC):
    """
    Abstract base class for LLM providers.
    Implementations: OllamaProvider, AnthropicProvider, OpenAIProvider
    """

    @abstractmethod
    async def generate(self, prompt: str, system: str = "") -> str:
        """Generate a text completion.

        Args:
            prompt: User prompt
            system: System prompt for role/context

        Returns:
            Generated text response
        """
        ...

    async def stream_generate(self, prompt: str, system: str = "") -> AsyncGenerator[str, None]:
        """Stream a text completion token-by-token via SSE.

        This is the CyberSentinel-proven pattern: the frontend receives
        tokens as they're generated, enabling real-time typewriter display.

        Default implementation: falls back to generate() and yields the
        full response as a single chunk. Providers should override with
        native streaming for best UX.

        Args:
            prompt: User prompt
            system: System prompt for role/context

        Yields:
            Individual text tokens as they're generated
        """
        # Default fallback: generate full response, yield as one chunk
        response = await self.generate(prompt, system)
        yield response

    @abstractmethod
    async def generate_json(self, prompt: str, system: str = "") -> dict:
        """Generate a structured JSON response.

        Args:
            prompt: User prompt requesting JSON output
            system: System prompt

        Returns:
            Parsed JSON dict
        """
        ...

    @abstractmethod
    async def debate(self, cve_data: dict, vprs_components: dict) -> DebateResult:
        """Run adversarial AI debate (Lock 2).

        Two agents argue each CVE's priority:
        - Agent 3A (Justifier): Builds the case for the proposed score
        - Agent 3B (Challenger): Attacks the reasoning, finds holes

        On disagreement, higher priority (higher score) wins.
        This is VulnPilot's #1 differentiator - NOBODY else ships this.

        Args:
            cve_data: Normalized vulnerability data
            vprs_components: The 6 VPRS factor scores

        Returns:
            DebateResult with both agents' positions and final score
        """
        ...

    @abstractmethod
    async def justify(
        self, cve_data: dict, vprs_score: float, vprs_components: dict
    ) -> JustificationResult:
        """Generate plain-English justification for a VPRS score.

        Args:
            cve_data: Normalized vulnerability data
            vprs_score: Calculated VPRS score (0-100)
            vprs_components: The 6 factor breakdown

        Returns:
            JustificationResult with multiple detail levels
        """
        ...

    @abstractmethod
    async def correlate(self, cve_data: dict, threat_intel: dict) -> dict:
        """Agent 1 - The Correlator.
        Cross-reference CVSS + EPSS + KEV + dark web signals.

        Returns:
            Dict with correlation analysis and noise assessment
        """
        ...

    @abstractmethod
    async def map_context(self, cve_data: dict, asset_data: dict) -> dict:
        """Agent 2 - The Context Mapper.
        Reason through the specific environment - reachability,
        stack relevance, compensating controls.

        Returns:
            Dict with environmental context assessment
        """
        ...

    @abstractmethod
    async def health_check(self) -> bool:
        """Check if the LLM provider is available and responding."""
        ...

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Return the provider name (e.g., 'ollama', 'anthropic', 'openai')."""
        ...
