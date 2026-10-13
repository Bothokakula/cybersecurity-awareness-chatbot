"""Loading and validating the chatbot's knowledge base and quiz data."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path


@dataclass(frozen=True)
class Intent:
    """A single topic the chatbot can answer questions about."""

    id: str
    title: str
    patterns: tuple[str, ...]
    answer: str
    tips: tuple[str, ...] = ()
    related: tuple[str, ...] = ()
    small_talk: bool = False


@dataclass(frozen=True)
class QuizQuestion:
    question: str
    options: tuple[str, ...]
    answer: int
    explanation: str


@dataclass(frozen=True)
class KnowledgeBase:
    intents: tuple[Intent, ...]
    _by_id: dict[str, Intent] = field(default_factory=dict, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "_by_id", {i.id: i for i in self.intents})

    def get(self, intent_id: str) -> Intent | None:
        return self._by_id.get(intent_id)

    @property
    def topics(self) -> list[Intent]:
        """Intents that are real security topics (not greetings and small talk)."""
        return [i for i in self.intents if not i.small_talk]


def _read_data_file(name: str) -> str:
    return resources.files("cyberaware.data").joinpath(name).read_text(encoding="utf-8")


def load_knowledge_base(path: str | Path | None = None) -> KnowledgeBase:
    """Load intents from JSON and check that the data is consistent."""
    raw = Path(path).read_text(encoding="utf-8") if path else _read_data_file("knowledge_base.json")
    data = json.loads(raw)

    intents = tuple(
        Intent(
            id=item["id"],
            title=item["title"],
            patterns=tuple(item["patterns"]),
            answer=item["answer"],
            tips=tuple(item.get("tips", ())),
            related=tuple(item.get("related", ())),
            small_talk=item.get("small_talk", False),
        )
        for item in data["intents"]
    )

    ids = [i.id for i in intents]
    duplicates = {i for i in ids if ids.count(i) > 1}
    if duplicates:
        raise ValueError(f"Duplicate intent ids: {sorted(duplicates)}")

    known = set(ids)
    for intent in intents:
        if not intent.patterns:
            raise ValueError(f"Intent '{intent.id}' has no patterns")
        missing = [r for r in intent.related if r not in known]
        if missing:
            raise ValueError(f"Intent '{intent.id}' links to unknown intents: {missing}")

    return KnowledgeBase(intents)


def load_quiz() -> list[QuizQuestion]:
    data = json.loads(_read_data_file("quiz.json"))
    questions = []
    for item in data:
        q = QuizQuestion(
            question=item["question"],
            options=tuple(item["options"]),
            answer=item["answer"],
            explanation=item["explanation"],
        )
        if not 0 <= q.answer < len(q.options):
            raise ValueError(f"Quiz answer index out of range: {q.question!r}")
        questions.append(q)
    return questions


def load_common_passwords() -> frozenset[str]:
    lines = _read_data_file("common_passwords.txt").splitlines()
    return frozenset(line.strip().lower() for line in lines if line.strip() and not line.startswith("#"))
