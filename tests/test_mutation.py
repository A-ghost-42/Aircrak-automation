import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from main import mutate_seeds, _leet, _cap_variants, _parse_seeds


def test_leet_basic():
    assert _leet("hello") == "h3ll0"
    assert _leet("world") == "w0rld"


def test_leet_case_insensitive():
    assert _leet("Hello") == "H3ll0"
    assert _leet("SECRET") == "53CR37"


def test_leet_no_change():
    assert _leet("") == ""
    assert _leet("abc") == "48c"


def test_cap_variants():
    result = _cap_variants("hello")
    assert "hello" in result
    assert "Hello" in result
    assert "HELLO" in result
    assert len(result) <= 4


def test_cap_variants_empty():
    assert _cap_variants("") == [""]


def test_mutate_seeds_empty():
    assert mutate_seeds([]) == []
    assert mutate_seeds([""]) == []


def test_mutate_seeds_basic():
    result = mutate_seeds(["hello"])
    assert "hello" in result
    assert "h3ll0" in result


def test_mutate_seeds_with_suffixes():
    result = mutate_seeds(["admin"])
    suffixes = ["!", "@", "#", "123", "123!"]
    found = any("admin" + s in result for s in suffixes)
    assert found, "Expected at least one suffixed variant"


def test_mutate_seeds_multiple():
    result = mutate_seeds(["foo", "bar"])
    assert "foo" in result
    assert "bar" in result


def test_parse_seeds_empty():
    assert _parse_seeds("") == []


def test_parse_seeds_comma():
    assert _parse_seeds("foo, bar, baz") == ["foo", "bar", "baz"]


def test_parse_seeds_space():
    assert _parse_seeds("foo bar baz") == ["foo", "bar", "baz"]


def test_parse_seeds_semicolon():
    assert _parse_seeds("foo;bar;baz") == ["foo", "bar", "baz"]
