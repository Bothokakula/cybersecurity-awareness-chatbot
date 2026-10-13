"""Streamlit web interface for CyberAware. Run with: streamlit run app.py"""

from __future__ import annotations

import random
import sys
from pathlib import Path

import streamlit as st

# Allow `streamlit run app.py` without installing the package first.
sys.path.insert(0, str(Path(__file__).parent / "src"))

from cyberaware.engine import ChatEngine  # noqa: E402
from cyberaware.passwords import check_password  # noqa: E402
from cyberaware.phishing import analyse_message, format_report  # noqa: E402
from cyberaware.quiz import draw_questions, grade  # noqa: E402

st.set_page_config(page_title="CyberAware", page_icon="🔐", layout="centered")

EXAMPLE_MESSAGES = {
    "Choose an example…": "",
    "Fake bank SMS": (
        "FNB: Dear customer, your account has been suspended due to suspicious activity. "
        "Verify your details within 24 hours to avoid permanent closure: http://fnb-secure-verify.xyz/login"
    ),
    "Parcel delivery scam": (
        "Your parcel is on hold. A delivery fee of R25.50 is outstanding. Pay now: bit.ly/parcel-za"
    ),
    "Prize scam": (
        "Congratulations! You have been selected as the winner of a R10,000 Takealot voucher. "
        "Claim your prize here: https://takealot-rewards.click/claim?id=8812"
    ),
    "Normal message": "Hi Thabo, are we still meeting at the library at 2pm tomorrow to work on the project?",
}

RISK_COLOURS = {"Low": "#1e8e3e", "Medium": "#e8710a", "High": "#d93025"}
STRENGTH_COLOURS = ["#d93025", "#e8710a", "#f9ab00", "#1e8e3e", "#137333"]


@st.cache_resource
def get_engine() -> ChatEngine:
    return ChatEngine()


def send(message: str) -> None:
    st.session_state.history.append({"role": "user", "content": message})
    reply = get_engine().reply(message)
    st.session_state.history.append({"role": "assistant", "content": reply.text, "suggestions": reply.suggestions})


st.title("🔐 CyberAware")
st.caption("A cybersecurity awareness assistant for everyday South Africans.")

chat_tab, phishing_tab, password_tab, quiz_tab = st.tabs(
    ["💬 Chat", "🎣 Phishing checker", "🔑 Password checker", "🧠 Quiz"]
)

# --- Chat -------------------------------------------------------------------
with chat_tab:
    if "history" not in st.session_state:
        st.session_state.history = [
            {
                "role": "assistant",
                "content": "Hi! Ask me anything about staying safe online, such as phishing, OTP scams, "
                "SIM swaps, passwords or POPIA. You can also paste a suspicious message with a link "
                "and I'll check it.",
                "suggestions": ["Phishing emails", "OTP scams", "SIM swap fraud"],
            }
        ]

    for index, entry in enumerate(st.session_state.history):
        with st.chat_message(entry["role"], avatar="🛡️" if entry["role"] == "assistant" else None):
            st.markdown(entry["content"])
            suggestions = entry.get("suggestions") or []
            is_last = index == len(st.session_state.history) - 1
            if suggestions and is_last:
                columns = st.columns(len(suggestions))
                for col, suggestion in zip(columns, suggestions, strict=True):
                    if col.button(suggestion, key=f"suggest-{index}-{suggestion}", use_container_width=True):
                        send(suggestion)
                        st.rerun()

    if prompt := st.chat_input("Ask a question or paste a suspicious message…"):
        send(prompt)
        st.rerun()

# --- Phishing checker ---------------------------------------------------------
with phishing_tab:
    st.subheader("Is this message a scam?")
    st.write("Paste an SMS, email or WhatsApp message. Everything is checked locally and nothing is saved.")
    example = st.selectbox("Or try an example", list(EXAMPLE_MESSAGES))
    message = st.text_area("Message", value=EXAMPLE_MESSAGES[example], height=140)
    if st.button("Check message", type="primary", disabled=not message.strip()):
        report = analyse_message(message)
        colour = RISK_COLOURS[report.level]
        st.markdown(
            f"<div style='height:10px;border-radius:5px;background:linear-gradient(90deg,{colour} "
            f"{max(report.score, 3)}%, rgba(128,128,128,.2) 0)'></div>",
            unsafe_allow_html=True,
        )
        st.markdown(format_report(report))

# --- Password checker ---------------------------------------------------------
with password_tab:
    st.subheader("How strong is your password?")
    st.write(
        "The check runs entirely in this app: your password is never stored, logged or sent anywhere. "
        "Still, it's best to test a *similar* password rather than your real one."
    )
    password = st.text_input("Password", type="password")
    if password:
        report = check_password(password)
        colour = STRENGTH_COLOURS[report.score]
        st.markdown(
            f"<div style='height:10px;border-radius:5px;background:linear-gradient(90deg,{colour} "
            f"{(report.score + 1) * 20}%, rgba(128,128,128,.2) 0)'></div>",
            unsafe_allow_html=True,
        )
        left, right = st.columns(2)
        left.metric("Strength", f"{report.label}")
        right.metric("Estimated crack time", report.crack_time)
        for warning in report.warnings:
            st.warning(warning)
        for suggestion in report.suggestions:
            st.info(suggestion)

# --- Quiz ----------------------------------------------------------------------
with quiz_tab:
    st.subheader("Test your cyber instincts")
    if "quiz_seed" not in st.session_state:
        st.session_state.quiz_seed = random.randint(0, 10_000)
    questions = draw_questions(5, seed=st.session_state.quiz_seed)

    with st.form("quiz"):
        answers: list[int | None] = []
        for number, q in enumerate(questions, start=1):
            choice = st.radio(
                f"**{number}. {q.question}**",
                options=range(len(q.options)),
                format_func=lambda i, q=q: q.options[i],
                index=None,
                key=f"q-{st.session_state.quiz_seed}-{number}",
            )
            answers.append(choice)
        submitted = st.form_submit_button("Submit answers", type="primary")

    if submitted:
        result = grade(questions, answers)
        st.markdown(f"### Score: {result.correct}/{result.total}")
        st.write(result.message)
        for number, (q, a) in enumerate(zip(questions, answers, strict=True), start=1):
            icon = "✅" if a == q.answer else "❌"
            st.markdown(f"{icon} **{number}.** {q.options[q.answer]}: {q.explanation}")

    if st.button("New quiz"):
        st.session_state.quiz_seed = random.randint(0, 10_000)
        st.rerun()

st.divider()
st.caption(
    "CyberAware gives general awareness guidance, not professional security or legal advice. "
    "If you've lost money, contact your bank immediately."
)
