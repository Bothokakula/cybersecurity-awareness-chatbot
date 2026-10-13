"""Multiple-choice quiz logic, shared by the CLI and the web app."""

from __future__ import annotations

import random
from dataclasses import dataclass

from cyberaware.knowledge import QuizQuestion, load_quiz


@dataclass
class QuizResult:
    correct: int
    total: int

    @property
    def percentage(self) -> int:
        return round(100 * self.correct / self.total) if self.total else 0

    @property
    def message(self) -> str:
        if self.percentage == 100:
            return "Perfect score! You're a cyber pro. 🛡️"
        if self.percentage >= 70:
            return "Great job: you know how to spot most scams."
        if self.percentage >= 40:
            return "Not bad. Review the explanations to sharpen your instincts."
        return "Keep learning: ask me about any topic you weren't sure of."


def draw_questions(n: int = 5, seed: int | None = None) -> list[QuizQuestion]:
    questions = load_quiz()
    rng = random.Random(seed)
    return rng.sample(questions, k=min(n, len(questions)))


def grade(questions: list[QuizQuestion], answers: list[int | None]) -> QuizResult:
    if len(answers) != len(questions):
        raise ValueError("Number of answers must match number of questions")
    correct = sum(1 for q, a in zip(questions, answers, strict=True) if a == q.answer)
    return QuizResult(correct=correct, total=len(questions))
