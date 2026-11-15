"""The refusal: a named rule, never a row value."""

from __future__ import annotations


class Refusal(Exception):
    """cerberus declined to proceed. ``rule`` names why; ``detail`` says what and how to proceed.

    ``guarantee`` is the write guarantee established on the connection when the refusal came after it
    was established; ``None`` when the refusal came before (the detail then says why).
    """

    def __init__(self, rule: str, detail: str, guarantee: dict[str, str] | None = None) -> None:
        super().__init__(f"{rule}: {detail}")
        self.rule = rule
        self.detail = detail
        self.guarantee = guarantee

    def as_dict(self) -> dict[str, object]:
        return {"refused": True, "rule": self.rule, "detail": self.detail, "guarantee": self.guarantee}
