"""Retrieval-based chat engine.

Each intent in the knowledge base has example questions ("patterns"). The
engine turns every pattern into a TF-IDF vector that combines word n-grams
(for meaning) with character n-grams (so typos like "phisihng" still match).
An incoming message is vectorised the same way, and the intent with the most
similar pattern wins, provided the similarity clears a confidence threshold.
Otherwise the bot says it isn't sure and suggests topics.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.pipeline import FeatureUnion

from cyberaware.knowledge import Intent, KnowledgeBase, load_knowledge_base
from cyberaware.phishing import analyse_message, contains_url, format_report

# Expand abbreviations and local terms so they match the knowledge base wording.
SYNONYMS: dict[str, str] = {
    r"\b2fa\b": "two factor authentication 2fa",
    r"\bmfa\b": "multi factor authentication mfa",
    r"\botp\b": "otp one time pin",
    r"\bwi-?fi\b": "wifi",
    r"\bsms\b": "sms text message",
    r"\bpw\b|\bpwd\b|\bpasswd\b": "password",
    r"\bhacked\b": "hacked compromised",
    r"\bwa\b|\bwhatsap\b": "whatsapp",
    r"\bpop\b": "proof of payment",
    r"\bscamed\b|\bscammd\b": "scammed",
}

# Filler words that carry no topic meaning; removing them stops questions like
# "what is the weather today" matching "what is phishing" on wording alone.
STOP_WORDS = {
    "a",
    "an",
    "the",
    "is",
    "are",
    "was",
    "be",
    "do",
    "does",
    "did",
    "i",
    "i'm",
    "im",
    "me",
    "my",
    "it",
    "its",
    "it's",
    "this",
    "that",
    "to",
    "of",
    "on",
    "in",
    "at",
    "for",
    "and",
    "or",
    "so",
    "what",
    "what's",
    "whats",
    "how",
    "should",
    "can",
    "could",
    "would",
    "about",
    "please",
    "tell",
    "today",
    "got",
    "get",
    "just",
    "some",
    "any",
    "there",
}

POPULAR_TOPICS = ("phishing", "otp_scams", "passwords")

CHECK_PREFIX = re.compile(r"^\s*(check|scan|analy[sz]e)\s*[:\-]\s*", re.IGNORECASE)


def normalise(text: str) -> str:
    text = text.lower().strip()
    for pattern, replacement in SYNONYMS.items():
        text = re.sub(pattern, replacement, text)
    text = re.sub(r"[^\w\s'-]", " ", text)
    words = text.split()
    kept = [w for w in words if w not in STOP_WORDS]
    # Keep the original words if everything was filler (e.g. "what can you do").
    return " ".join(kept or words)


@dataclass
class BotReply:
    text: str
    kind: str  # "answer", "small_talk", "fallback" or "phishing_check"
    intent_id: str | None = None
    confidence: float = 0.0
    suggestions: list[str] = field(default_factory=list)


class ChatEngine:
    def __init__(self, kb: KnowledgeBase | None = None, threshold: float = 0.35) -> None:
        self.kb = kb or load_knowledge_base()
        self.threshold = threshold

        self._pattern_intents: list[Intent] = []
        corpus: list[str] = []
        for intent in self.kb.intents:
            for pattern in intent.patterns:
                corpus.append(normalise(pattern))
                self._pattern_intents.append(intent)

        self._vectoriser = FeatureUnion(
            [
                ("words", TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True)),
                ("chars", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), sublinear_tf=True)),
            ]
        )
        self._matrix = self._vectoriser.fit_transform(corpus)

    def rank(self, message: str, top_n: int = 3) -> list[tuple[Intent, float]]:
        """Return the best-matching intents with their similarity scores."""
        vector = self._vectoriser.transform([normalise(message)])
        scores = cosine_similarity(vector, self._matrix)[0]

        best: dict[str, tuple[Intent, float]] = {}
        for intent, score in zip(self._pattern_intents, scores, strict=True):
            if intent.id not in best or score > best[intent.id][1]:
                best[intent.id] = (intent, float(score))
        return sorted(best.values(), key=lambda pair: pair[1], reverse=True)[:top_n]

    def reply(self, message: str) -> BotReply:
        if not message or not message.strip():
            return BotReply("Type a question, or paste a suspicious message to check it.", "fallback")

        # Pasted messages with links, or an explicit "check: ..." request, go to the phishing checker.
        explicit = CHECK_PREFIX.match(message)
        if explicit or contains_url(message):
            text = message[explicit.end() :] if explicit else message
            report = analyse_message(text)
            return BotReply(format_report(report), "phishing_check", confidence=1.0)

        # Clicking a suggested topic sends its exact title, so match that directly.
        by_title = {i.title.lower(): i for i in self.kb.intents}
        if message.strip().lower() in by_title:
            ranked = [(by_title[message.strip().lower()], 1.0)]
        else:
            ranked = self.rank(message)
        intent, score = ranked[0]

        if score < self.threshold:
            if score >= 0.2:
                options = [i.title for i, _ in ranked if not i.small_talk]
                text = "I'm not sure I understood that. Did you mean one of these topics?"
            else:
                options = []
            if not options:
                options = [self.kb.get(i).title for i in POPULAR_TOPICS if self.kb.get(i)]
                text = (
                    "Sorry, I can only help with cybersecurity topics. "
                    'Here are some popular ones, or ask me "what can you do?"'
                )
            return BotReply(
                text,
                "fallback",
                confidence=score,
                suggestions=options,
            )

        if intent.small_talk:
            return BotReply(intent.answer, "small_talk", intent.id, score)

        parts = [f"### {intent.title}", intent.answer]
        if intent.tips:
            parts.append("**Tips:**\n" + "\n".join(f"- {tip}" for tip in intent.tips))
        related = [self.kb.get(r).title for r in intent.related if self.kb.get(r)]
        return BotReply("\n\n".join(parts), "answer", intent.id, score, suggestions=related)
