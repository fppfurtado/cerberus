"""The refusal: a named rule, never a row value."""

from __future__ import annotations


class Refusal(Exception):
    """cerberus declined to proceed. ``rule`` names why; ``detail`` says what and how to proceed."""

    def __init__(self, rule: str, detail: str) -> None:
        super().__init__(f"{rule}: {detail}")
        self.rule = rule
        self.detail = detail

    def as_dict(self) -> dict[str, object]:
        return {"refused": True, "rule": self.rule, "detail": self.detail}
