import pytest

from cyberaware.phishing import analyse_message, extract_urls, format_report

FAKE_BANK = (
    "FNB: Dear customer, your account has been suspended. Verify your details within 24 hours: "
    "http://fnb-secure-verify.xyz/login"
)


def flag_names(text: str) -> set[str]:
    return {f.name for f in analyse_message(text).flags}


def test_fake_bank_sms_is_high_risk():
    report = analyse_message(FAKE_BANK)
    assert report.level == "High"
    assert report.score == 100
    assert {"Imitates a known brand", "Generic greeting", "Creates urgency"} <= flag_names(FAKE_BANK)


def test_normal_message_is_low_risk():
    report = analyse_message("Hi Thabo, are we still meeting at the library at 2pm tomorrow?")
    assert report.level == "Low"
    assert report.flags == []


def test_official_domain_is_not_flagged():
    text = "Your FNB statement is ready. Log in at https://www.fnb.co.za to view it."
    assert analyse_message(text).score == 0


def test_parcel_scam_with_short_link():
    names = flag_names("Your parcel is on hold. Delivery fee outstanding. Pay now: bit.ly/parcel-za")
    assert {"Shortened link", "Requests payment", "Pushes you to a link"} <= names


def test_ip_address_link():
    assert "Link uses an IP address" in flag_names("Confirm your account: http://192.168.4.20/login")


def test_punycode_and_at_sign():
    assert "Look-alike characters" in flag_names("Login at https://xn--pypal-4ve.com")
    assert "Hidden destination" in flag_names("Visit https://www.sars.gov.za@evil.example/refund")


def test_brand_mentioned_but_link_elsewhere():
    names = flag_names("Capitec: confirm your banking details at https://secure-update.example.com")
    assert "Link doesn't match sender" in names


def test_otp_request_without_link():
    report = analyse_message("Please send me the OTP you just received")
    assert "Asks for sensitive details" in {f.name for f in report.flags}


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("go to https://example.com/path.", ["https://example.com/path"]),
        ("see www.example.co.za now", ["www.example.co.za"]),
        ("tap bit.ly/abc123", ["bit.ly/abc123"]),
        ("no links here, e.g. just text", []),
    ],
)
def test_extract_urls(text, expected):
    assert extract_urls(text) == expected


def test_score_is_capped_and_report_formats():
    report = analyse_message(FAKE_BANK + " Congratulations, you won a prize! Pay the fee with gift cards.")
    assert report.score == 100
    text = format_report(report)
    assert "High risk (100/100)" in text
    assert "heuristic" in text
