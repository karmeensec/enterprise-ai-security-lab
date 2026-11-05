
"""
Experiment 53 — Inspect raw Qwen tool-call output.

Diagnostic only. Does not execute tools or
modify project files.
"""

from backend.llm_service import get_llm_service
from backend.qwen_security_agent import (
    _build_agent_prompt,
)


QUESTION = (
    "Search the company security policies "
    "for remote access VPN requirements."
)


def main():
    print("=" * 60)
    print("QWEN AGENT OUTPUT DIAGNOSTIC")
    print("=" * 60)

    llm = get_llm_service()

    prompt = _build_agent_prompt(QUESTION)

    result = llm.generate(
        message=prompt
    )

    print("\nMODEL STATUS:")
    print(result["status"])

    print("\nRAW GENERATED RESPONSE:")
    print("-" * 60)
    print(repr(result["response"]))
    print("-" * 60)

    print("\nGENERATED TOKENS:")
    print(result["generated_tokens"])

    print("\nTRUNCATED:")
    print(result["truncated"])


if __name__ == "__main__":
    main()
