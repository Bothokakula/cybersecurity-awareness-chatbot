import pytest

from cyberaware.engine import ChatEngine, normalise


@pytest.fixture(scope="module")
def engine() -> ChatEngine:
    return ChatEngine()


@pytest.mark.parametrize(
    ("question", "expected"),
    [
        ("How do I know if an email is phishing?", "phishing"),
        ("Someone called asking for my OTP", "otp_scams"),
        ("what is a sim swap", "sim_swap"),
        ("My phone suddenly has no signal", "sim_swap"),
        ("Is 2FA worth turning on?", "mfa"),
        ("Can I do banking on the free mall wifi?", "public_wifi"),
        ("What's POPIA?", "popia"),
        ("My Instagram got hacked", "account_hacked"),
        ("I got scammed, what now?", "scammed"),
        ("Supplier changed their bank details on the invoice", "bec"),
        ("A job offer wants me to pay for training", "job_scams"),
        ("Is this online shop legit?", "online_shopping"),
        ("How do I back up my files?", "backups"),
    ],
)
def test_matches_expected_topic(engine, question, expected):
    reply = engine.reply(question)
    assert reply.kind == "answer"
    assert reply.intent_id == expected


def test_tolerates_typos(engine):
    assert engine.reply("how to make a strong pasword").intent_id == "passwords"
    assert engine.reply("phisihng").intent_id == "phishing"


def test_small_talk(engine):
    assert engine.reply("hello").kind == "small_talk"
    assert engine.reply("thanks!").intent_id == "thanks"
    assert engine.reply("what can you do").intent_id == "capabilities"


@pytest.mark.parametrize("question", ["what's the weather today", "tell me a joke", "what is a firewall"])
def test_unknown_questions_fall_back_with_suggestions(engine, question):
    reply = engine.reply(question)
    assert reply.kind == "fallback"
    assert reply.suggestions


def test_empty_message(engine):
    assert engine.reply("   ").kind == "fallback"


def test_answers_include_related_topics(engine):
    reply = engine.reply("what is phishing")
    assert "SMS and phone scams (smishing and vishing)" in reply.suggestions


def test_clicking_a_suggestion_title_opens_that_topic(engine):
    assert engine.reply("SIM swap fraud").intent_id == "sim_swap"


def test_messages_with_links_are_routed_to_phishing_checker(engine):
    reply = engine.reply("Your account is suspended, verify now at http://fnb-login.xyz")
    assert reply.kind == "phishing_check"
    assert "High risk" in reply.text


def test_explicit_check_prefix(engine):
    reply = engine.reply("check: Dear customer, reply with your PIN urgently")
    assert reply.kind == "phishing_check"


def test_normalise_expands_abbreviations_and_drops_filler():
    assert "two factor authentication" in normalise("What is 2FA?")
    assert normalise("what is the") == "what is the"  # all filler: keep original words
    assert "the" not in normalise("what is the otp").split()
