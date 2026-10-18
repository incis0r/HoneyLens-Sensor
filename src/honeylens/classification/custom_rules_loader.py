"""Backward compatibility: loading AI rules from the ``ai_custom_rules`` table.

In 0.9 this module was dead: it did ``import attack_classifier`` without the package
(which never existed on ``sys.path``), so ``load_custom_rules()`` always ended with a
warning and zero, and even if the import had succeeded, it injected rules into
``attack_classifier._RULES`` while the registry lives in ``text_rules``. The real database
loading was and is done by ``text_rules._load_custom_rules_from_db``. This module remains as
a thin layer over it, because ``routes/ai/rules.py`` and ``analysis/rule_validator.py``
import it by name.
"""

from typing import Any

from honeylens.classification import text_rules
from honeylens.classification.text_rules import CUSTOM_RULE_FLAGS as CUSTOM_RULE_FLAGS


def load_custom_rules(force: bool = False) -> int:
    """Load the enabled rules from the database into the registry; idempotent unless ``force``."""
    if force:
        return text_rules.reload_custom_rules()
    return text_rules._load_custom_rules_from_db()


def reload_custom_rules() -> int:
    """Hot reload: removes the injected rules and reads the database anew."""
    return text_rules.reload_custom_rules()


def get_custom_rule_names() -> set[str]:
    return set(text_rules.get_custom_rule_names())


def get_custom_rules_info() -> list[dict[str, Any]]:
    """Custom rules present in the registry, for diagnostics."""
    names = text_rules.get_custom_rule_names()
    return [
        {
            "attack_type": atype,
            "rule_name": rname,
            "pattern": regex.pattern[:80],
            "is_custom": True,
        }
        for atype, rname, regex in text_rules._RULES
        if rname in names
    ]
