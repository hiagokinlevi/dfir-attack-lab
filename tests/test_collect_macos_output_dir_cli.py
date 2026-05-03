from pathlib import Path

from dfir_attack_lab_cli.main import main


def test_collect_macos_output_dir_is_parsed_created_and_passed(monkeypatch, tmp_path):
    called = {}

    def fake_collect_macos_triage(*, target_root, output_dir=None):
        called["target_root"] = target_root
        called["output_dir"] = output_dir

    monkeypatch.setattr("dfir_attack_lab_cli.main.collect_macos_triage", fake_collect_macos_triage)

    requested = tmp_path / "custom" / "triage-out"
    rc = main(["collect-macos", "--target", "/", "--output-dir", str(requested)])

    assert rc == 0
    assert requested.exists()
    assert requested.is_dir()
    assert called["target_root"] == "/"
    assert called["output_dir"] == str(Path(requested).resolve())
