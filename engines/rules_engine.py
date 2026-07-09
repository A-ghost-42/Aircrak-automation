import itertools
import string


HASHCAT_RULES = [
    ":",       # no change
    "l",       # lowercase
    "u",       # uppercase
    "c",       # capitalize
    "t",       # toggle case
    "d",       # duplicate
    "p",       # reverse
    "r",       # reverse
]

COMPOUND_RULES = [
    ("$1", "$!"),
    ("$2", "$@"),
    ("$3", "$#"),
    ("$1", "$2", "$3"),
    ("$!", "$@", "$#"),
]

YEAR_SUFFIX_RULES = [
    ("$2", "$0", "$2", "$4"),
    ("$2", "$0", "$2", "$5"),
    ("$2", "$0", "$2", "$6"),
    ("$2", "$0", "$2", "$3"),
    ("$2", "$0", "$2", "$0"),
]

SPECIAL_APPEND = list("!@#$%&*?")
DIGIT_APPEND = [str(i) for i in range(10)]
DOUBLE_DIGIT = [str(i).zfill(2) for i in range(100)]


class RulesEngine:
    def __init__(self):
        self.compiled_rules = self._build_rule_set()

    def _build_rule_set(self):
        rules = []

        for rule in HASHCAT_RULES:
            rules.append(rule)

        for d in DIGIT_APPEND:
            rules.append(f"${d}")
        for dd in DOUBLE_DIGIT:
            rules.append(f"${dd[0]}${dd[1]}")
        for s in SPECIAL_APPEND:
            rules.append(f"${s}")
        for d in DIGIT_APPEND:
            for s in SPECIAL_APPEND:
                rules.append(f"${d}${s}")
        for s in SPECIAL_APPEND:
            for d in DIGIT_APPEND:
                rules.append(f"${s}${d}")

        for yr in YEAR_SUFFIX_RULES:
            rules.append("".join(yr))
        for yr in YEAR_SUFFIX_RULES:
            rules.append(f"c{"".join(yr)}")

        for d in DIGIT_APPEND:
            for s in SPECIAL_APPEND:
                rules.append(f"c${d}${s}")
                rules.append(f"u${d}${s}")

        rules.append("cu")
        rules.append("uc")
        rules.append("c$!$!$!")
        rules.append("u$!$!$!")

        return rules

    def apply(self, word):
        results = set()
        results.add(word)
        results.add(word.lower())
        results.add(word.upper())
        results.add(word.capitalize())
        results.add(word.swapcase())
        results.add(word[::-1])
        results.add(word + word)

        for rule in self.compiled_rules:
            try:
                transformed = self._apply_single_rule(word, rule)
                if transformed and len(transformed) >= 8:
                    results.add(transformed)
            except Exception:
                continue

        return [r for r in results if len(r) >= 8]

    def apply_bulk(self, words, max_results=50000):
        results = set()
        for word in words:
            if len(results) >= max_results:
                break
            for pw in self.apply(word):
                results.add(pw)
                if len(results) >= max_results:
                    break
        return list(results)

    def _apply_single_rule(self, word, rule):
        if rule == ":":
            return word
        if rule == "l":
            return word.lower()
        if rule == "u":
            return word.upper()
        if rule == "c":
            return word.capitalize()
        if rule == "t":
            return word.swapcase()
        if rule == "d":
            return word + word
        if rule == "p" or rule == "r":
            return word[::-1]
        if rule.startswith("$"):
            return word + rule[1:]
        if rule.startswith("^"):
            return rule[1:] + word
        if rule.startswith("c$"):
            rest = rule[1:]
            pw = word.capitalize()
            for ch in rest:
                if ch.startswith("$"):
                    pw += ch[1:]
            return pw
        if rule.startswith("u$"):
            rest = rule[1:]
            pw = word.upper()
            for ch in rest:
                if ch.startswith("$"):
                    pw += ch[1:]
            return pw
        if rule == "cu":
            return word.capitalize().swapcase()
        if rule == "uc":
            return word.upper().capitalize()

        return None

    def generate_mutations(self, word):
        return self.apply(word)
