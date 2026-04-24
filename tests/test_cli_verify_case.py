import json

from dfir_attack_lab_cli import main


def test_verify_case_pass_human_output(monkeypatch, capsys):
    monkeypatch.setattr("dfir_attack_lab_cli.verify_case", lambda path: True)

    rc = main(["verify-case", "cases/demo"])

    out = capsys.readouterr().out.strip()
    assert rc == 0
    assert out.startswith("verify-case: PASS")
    assert "cases/demo" in out


def test_verify_case_fail_human_output(monkeypatch, capsys):
    monkeypatch.setattr("dfir_attack_lab_cli.verify_case", lambda path: False)

    rc = main(["verify-case", "cases/demo"])

    out = capsys.readouterr().out.strip()
    assert rc == 1
    assert out.startswith("verify-case: FAIL")


def test_verify_case_json_output_structure(monkeypatch, capsys):
    monkeypatch.setattr(
        "dfir_attack_lab_cli.verify_case",
        lambda path: {"ok": False, "mismatches": ["artifact.txt"]},
    )

    rc = main(["verify-case", "cases/demo", "--json"])

    out = capsys.readouterr().out.strip()
    payload = json.loads(out)
    assert rc == 1
    assert payload["case_dir"].endswith("cases/demo")
    assert payload["ok"] is False
    assert payload["mismatches"] == ["artifact.txt"]
