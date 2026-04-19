from analysis.sigma_eval import evaluate_sigma_rules, load_sigma_rules


def test_sigma_load_and_evaluate(tmp_path):
    rule_file = tmp_path / "rules.yml"
    rule_file.write_text(
        """
---
title: Suspicious PowerShell
author: unit
id: 11111111-1111-1111-1111-111111111111
level: high
status: test
tags: [attack.execution]
logsource:
  product: windows
detection:
  sel1:
    event_id: 4104
    process_name: powershell.exe
  condition: sel1
""".strip(),
        encoding="utf-8",
    )

    rules = load_sigma_rules(rule_file)
    assert len(rules) == 1

    events = [
        {"timestamp": "2025-01-01T00:00:00Z", "event_id": 4104, "process_name": "powershell.exe"},
        {"timestamp": "2025-01-01T00:01:00Z", "event_id": 4624, "process_name": "winlogon.exe"},
    ]

    result = evaluate_sigma_rules(events, rules)
    assert result[0]["flagged"] is True
    assert result[0]["sigma_matches"][0]["title"] == "Suspicious PowerShell"
    assert "sigma_matches" not in result[1]


def test_sigma_condition_and_or(tmp_path):
    rule_file = tmp_path / "rules2.yml"
    rule_file.write_text(
        """
title: Multi selector
id: 22222222-2222-2222-2222-222222222222
detection:
  a:
    category: process
  b:
    severity: high
  condition: a and b
""".strip(),
        encoding="utf-8",
    )

    rules = load_sigma_rules(rule_file)
    events = [
        {"category": "process", "severity": "high"},
        {"category": "process", "severity": "low"},
    ]
    result = evaluate_sigma_rules(events, rules)
    assert result[0]["flagged"] is True
    assert "sigma_matches" not in result[1]
