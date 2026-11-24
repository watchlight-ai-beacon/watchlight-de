"""``redacted_input_summary`` describes tool arguments without values."""

from watchlight_core import INPUT_SUMMARY_MAX_CHARS, redacted_input_summary


def test_mapping_renders_names_and_types_only():
    out = redacted_input_summary({"token": "sk-live-SECRET", "n": 3})
    assert out == "2 args: token(str), n(int)"
    assert "sk-live-SECRET" not in out


def test_non_mapping_renders_only_its_type():
    assert redacted_input_summary("sk-live-SECRET") == "1 arg: (str)"
    assert redacted_input_summary(None) is None
    assert redacted_input_summary({}) == "0 args"


def test_summary_is_bounded():
    out = redacted_input_summary({f"k{i}": i for i in range(200)})
    assert len(out) <= INPUT_SUMMARY_MAX_CHARS


def test_error_summary_is_the_class_only():
    from watchlight_core import redacted_error_summary

    assert redacted_error_summary(ValueError("token sk-live-SECRET")) == "ValueError"
    assert redacted_error_summary("Rate limit for sk-live-SECRET") == "error_detail_withheld"
    assert redacted_error_summary(None) == "unknown_error"
    assert redacted_error_summary(KeyError) == "KeyError"
