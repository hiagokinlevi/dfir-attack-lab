from cli.main import main


def test_collect_linux_defaults_output_dir_none(monkeypatch):
    captured = {}

    def fake_collect_linux_triage(*, output_dir=None):
        captured["output_dir"] = output_dir
        return {"ok": True}

    monkeypatch.setattr("cli.main.collect_linux_triage", fake_collect_linux_triage)

    result = main(["collect-linux"])

    assert result == {"ok": True}
    assert captured["output_dir"] is None


def test_collect_linux_passes_output_dir(monkeypatch, tmp_path):
    captured = {}

    def fake_collect_linux_triage(*, output_dir=None):
        captured["output_dir"] = output_dir
        return {"ok": True}

    monkeypatch.setattr("cli.main.collect_linux_triage", fake_collect_linux_triage)

    out_dir = str(tmp_path / "case-001")
    result = main(["collect-linux", "--output-dir", out_dir])

    assert result == {"ok": True}
    assert captured["output_dir"] == out_dir
