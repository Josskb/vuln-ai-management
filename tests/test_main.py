from pathlib import Path

from vuln_ai.main import load_config, main


def test_load_config(tmp_path: Path):
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("llm:\n  provider: ollama\n", encoding="utf-8")
    data = load_config(cfg)
    assert data["llm"]["provider"] == "ollama"


def test_main_demo_run(tmp_path: Path, monkeypatch):
    arch_path = tmp_path / "arch.txt"
    arch_path.write_text("MediConnect Corp", encoding="utf-8")
    cfg_path = tmp_path / "cfg.yaml"
    out_dir = (tmp_path / "out").as_posix()
    cfg_path.write_text(
        "output:\n  directory: '%s'\n  formats: ['json', 'html']\n" % out_dir,
        encoding="utf-8",
    )
    monkeypatch.setattr("sys.argv", [
        "prog",
        "--arch",
        str(arch_path),
        "--config",
        str(cfg_path),
        "--demo",
        "--skip-cve",
        "--skip-scenarios",
    ])
    main()
