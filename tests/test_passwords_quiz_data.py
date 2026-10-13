import pytest

from cyberaware.knowledge import load_common_passwords, load_knowledge_base, load_quiz
from cyberaware.passwords import check_password
from cyberaware.quiz import draw_questions, grade


@pytest.mark.parametrize("password", ["password", "P@ssw0rd2026!", "qwerty123456", "Summer2026", "kaizerchiefs1"])
def test_common_and_predictable_passwords_are_very_weak(password):
    report = check_password(password)
    assert report.score == 0
    assert report.warnings


@pytest.mark.parametrize("password", ["river-quantum-lamp-tuesday", "x7#Kq!9vLm2$"])
def test_long_random_passwords_are_very_strong(password):
    assert check_password(password).score == 4


def test_leetspeak_warning_only_when_symbols_were_swapped():
    assert any("Swapping letters" in w for w in check_password("p@ssword").warnings)
    assert not any("Swapping letters" in w for w in check_password("Summer2026").warnings)


def test_detects_sequences_and_repeats():
    assert any("sequence" in w for w in check_password("abcd-Lion-Tree").warnings)
    assert any("repeated" in w for w in check_password("Zebraaaa!Moon").warnings)


def test_empty_password():
    assert check_password("").score == 0


def test_strength_never_decreases_when_adding_random_length():
    short = check_password("Kp4!xz")
    longer = check_password("Kp4!xz-mountain-velvet")
    assert longer.score >= short.score


def test_knowledge_base_is_consistent():
    kb = load_knowledge_base()
    assert len(kb.topics) >= 20
    for intent in kb.intents:
        assert intent.answer.strip()
        for related in intent.related:
            assert kb.get(related) is not None


def test_quiz_data_and_grading():
    questions = load_quiz()
    assert len(questions) >= 10
    drawn = draw_questions(5, seed=42)
    assert len(drawn) == 5
    assert draw_questions(5, seed=42) == drawn  # reproducible with a seed

    perfect = grade(drawn, [q.answer for q in drawn])
    assert perfect.correct == 5 and perfect.percentage == 100

    unanswered = grade(drawn, [None] * 5)
    assert unanswered.correct == 0

    with pytest.raises(ValueError):
        grade(drawn, [0])


def test_common_password_list_loads_without_comments():
    common = load_common_passwords()
    assert "password" in common
    assert not any(p.startswith("#") for p in common)
