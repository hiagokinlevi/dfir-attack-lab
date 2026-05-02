from __future__ import annotations

import json

from dfir_attack_lab_cli.main import main


def test_analyze_process_tree_default_no_threshold(monkeypatch, tmp_path, capsys):
    in_file = tmp_path / "tree.json"
    in_file.write_text("{}", encoding="utf-8")

    sample_findings = [
        {"rule": "low", "score": 20},
        {"rule": "high", "score": 90},
    ]

    monkeypatch.setattr(
        "dfir_attack_lab_cli.main.analyze_process_tree",
        lambda _p: sample_findings,
    )

    rc = main(["analyze-process-tree", "--input", str(in_file)])
    assert rc == 0

    out = capsys.readouterr().out
    data = json.loads(out)
    assert data == sample_findings


def test_analyze_process_tree_min_score_filters(monkeypatch, tmp_path, capsys):
    in_file = tmp_path / "tree.json"
    in_file.write_text("{}", encoding="utf-8")

    sample_findings = [
        {"rule": "low", "score": 19.9},
        {"rule": "edge", "score": 20},
        {"rule": "high", "score": 87},
    ]

    monkeypatch.setattr(
        "dfir_attack_lab_cli.main.analyze_process_tree",
        lambda _p: sample_findings,
    )

    rc = main([
        "analyze-process-tree",
        "--input",
        str(in_file),
        "--min-score",
        "20",
    ])
    assert rc == 0

    out = capsys.readouterr().out
    data = json.loads(out)
    assert data == [
        {"rule": "edge", "score": 20},
        {"rule": "high", "score": 87},
    ]
