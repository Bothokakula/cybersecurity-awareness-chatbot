"""Command-line interface: `cyberaware` (or `python -m cyberaware`)."""

from __future__ import annotations

import getpass
import re
import sys
import textwrap

from cyberaware.engine import ChatEngine
from cyberaware.passwords import check_password
from cyberaware.phishing import analyse_message, format_report
from cyberaware.quiz import draw_questions, grade

HELP = """
Commands:
  /topics     list the topics I can explain
  /check      analyse a suspicious message for phishing red flags
  /password   check a password's strength (input is hidden and never stored)
  /quiz       take a 5-question quiz
  /help       show this help
  /quit       exit
Or just ask a question, e.g. "What is a SIM swap?"
"""


def plain(markdown: str) -> str:
    """Strip light markdown for terminal output."""
    text = re.sub(r"^#+\s*", "", markdown, flags=re.MULTILINE)
    text = text.replace("**", "").replace("`", "")
    text = re.sub(r"(?<!\w)_(.+?)_(?!\w)", r"\1", text)
    return re.sub(r"(?<!\*)\*(?!\*)(.+?)\*", r"\1", text)


def run_check() -> None:
    print("Paste the message, then press Enter on an empty line:")
    lines = []
    while True:
        line = input()
        if not line:
            break
        lines.append(line)
    print()
    print(plain(format_report(analyse_message("\n".join(lines)))))


def run_password() -> None:
    report = check_password(getpass.getpass("Password (hidden): "))
    print(f"\nStrength: {report.label} ({report.score}/4), about {report.entropy_bits} bits")
    print(f"Estimated offline crack time: {report.crack_time}")
    for w in report.warnings:
        print(f"  ! {w}")
    for s in report.suggestions:
        print(f"  - {s}")


def run_quiz() -> None:
    questions = draw_questions(5)
    answers: list[int | None] = []
    for number, q in enumerate(questions, start=1):
        print(f"\nQ{number}. {q.question}")
        for i, option in enumerate(q.options):
            print(f"   {chr(65 + i)}) {option}")
        choice = input("Your answer (A-D): ").strip().upper()
        index = ord(choice) - 65 if len(choice) == 1 and choice.isalpha() else None
        answers.append(index)
        verdict = "✅ Correct!" if index == q.answer else f"❌ Answer: {chr(65 + q.answer)}"
        print(f"{verdict} {q.explanation}")
    result = grade(questions, answers)
    print(f"\nScore: {result.correct}/{result.total}. {result.message}")


def main() -> int:
    engine = ChatEngine()
    print("🔐 CyberAware: cybersecurity awareness assistant")
    print("Type /help for commands, or ask a question.\n")

    commands = {"/check": run_check, "/password": run_password, "/quiz": run_quiz}

    while True:
        try:
            message = input("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye!")
            return 0

        if not message:
            continue
        command = message.lower()
        if command in {"/quit", "/exit"}:
            print("Goodbye! Never share your OTP. 👋")
            return 0
        if command == "/help":
            print(HELP)
            continue
        if command == "/topics":
            for topic in engine.kb.topics:
                print(f"  • {topic.title}")
            continue
        if command in commands:
            commands[command]()
            print()
            continue

        reply = engine.reply(message)
        body = plain(reply.text)
        print("\nBot: " + textwrap.indent(body, "     ").lstrip())
        if reply.suggestions:
            label = "Related" if reply.kind == "answer" else "Try"
            print(f"     {label}: " + " | ".join(reply.suggestions))
        print()


if __name__ == "__main__":
    sys.exit(main())
