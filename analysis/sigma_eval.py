from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import yaml


@dataclass(frozen=True)
class SigmaRule:
    title: str
    rule_id: Optional[str]
    status: Optional[str]
    level: Optional[str]
    tags: List[str]
    logsource: Dict[str, Any]
    detection: Dict[str, Any]
    raw: Dict[str, Any]


def load_sigma_rules(path: str | Path) -> List[SigmaRule]:
    p = Path(path)
    if p.is_dir():
        docs: List[Dict[str, Any]] = []
        for f in sorted(p.rglob("*.yml")) + sorted(p.rglob("*.yaml")):
            docs.extend(_read_yaml_docs(f))
    else:
        docs = _read_yaml_docs(p)

    rules: List[SigmaRule] = []
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        detection = doc.get("detection")
        title = doc.get("title")
        if not title or not isinstance(detection, dict):
            continue
        rules.append(
            SigmaRule(
                title=str(title),
                rule_id=doc.get("id"),
                status=doc.get("status"),
                level=doc.get("level"),
                tags=[str(t) for t in (doc.get("tags") or [])],
                logsource=dict(doc.get("logsource") or {}),
                detection=detection,
                raw=doc,
            )
        )
    return rules


def evaluate_sigma_rules(
    events: Iterable[Dict[str, Any]], rules: Iterable[SigmaRule]
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    rule_list = list(rules)
    for event in events:
        enriched = dict(event)
        matches = []
        for rule in rule_list:
            if _match_rule(event, rule):
                matches.append(
                    {
                        "title": rule.title,
                        "id": rule.rule_id,
                        "level": rule.level,
                        "status": rule.status,
                        "tags": rule.tags,
                    }
                )
        if matches:
            enriched["sigma_matches"] = matches
            enriched["flagged"] = True
        out.append(enriched)
    return out


def _read_yaml_docs(path: Path) -> List[Dict[str, Any]]:
    with path.open("r", encoding="utf-8") as fh:
        data = list(yaml.safe_load_all(fh))
    return [d for d in data if d is not None]


def _match_rule(event: Dict[str, Any], rule: SigmaRule) -> bool:
    detection = rule.detection
    condition = str(detection.get("condition", "")).strip()
    if not condition:
        return False

    selections = {
        k: v
        for k, v in detection.items()
        if k != "condition" and isinstance(v, (dict, list))
    }

    # Minimal Sigma condition support: "sel", "sel1 and sel2", "sel1 or sel2", "1 of sel*", "all of sel*"
    tokens = condition.split()
    if len(tokens) == 1:
        return _eval_selector(tokens[0], selections, event)

    if len(tokens) == 4 and tokens[1] == "of":
        quant = tokens[0].lower()
        pattern = tokens[2]
        if tokens[3] != "":
            pass
        names = [n for n in selections if _matches_pattern(n, pattern)]
        if not names:
            return False
        results = [_eval_selector(n, selections, event) for n in names]
        if quant == "1":
            return any(results)
        if quant == "all":
            return all(results)

    # Basic left-to-right boolean chain
    result: Optional[bool] = None
    op: Optional[str] = None
    for tok in tokens:
        low = tok.lower()
        if low in {"and", "or"}:
            op = low
            continue
        cur = _eval_selector(tok, selections, event)
        if result is None:
            result = cur
        elif op == "and":
            result = result and cur
        elif op == "or":
            result = result or cur
    return bool(result)


def _matches_pattern(name: str, pattern: str) -> bool:
    if pattern.endswith("*"):
        return name.startswith(pattern[:-1])
    return name == pattern


def _eval_selector(name: str, selections: Dict[str, Any], event: Dict[str, Any]) -> bool:
    sel = selections.get(name)
    if sel is None:
        return False

    if isinstance(sel, list):
        # list means OR across maps
        return any(_match_map(item, event) for item in sel if isinstance(item, dict))
    if isinstance(sel, dict):
        return _match_map(sel, event)
    return False


def _match_map(selector: Dict[str, Any], event: Dict[str, Any]) -> bool:
    for key, expected in selector.items():
        actual = event.get(key)
        if isinstance(expected, list):
            if actual not in expected:
                return False
        elif isinstance(expected, str):
            if str(actual) != expected:
                return False
        else:
            if actual != expected:
                return False
    return True
