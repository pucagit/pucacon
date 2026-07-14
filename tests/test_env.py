import os
from pucacon.config import load_env

def test_load_env_sets_and_returns_keys(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("# comment\nPUCACON_TESTKEY=abc123\nQUOTED=\"v a l\"\n\n")
    # ensure clean slate for the vars we assert on
    monkeypatch.delenv("PUCACON_TESTKEY", raising=False)
    monkeypatch.delenv("QUOTED", raising=False)
    keys = load_env(env)
    assert set(keys) == {"PUCACON_TESTKEY", "QUOTED"}
    assert os.environ["PUCACON_TESTKEY"] == "abc123"
    assert os.environ["QUOTED"] == "v a l"

def test_load_env_does_not_overwrite_existing(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("PUCACON_TESTKEY=fromfile\n")
    monkeypatch.setenv("PUCACON_TESTKEY", "fromenv")
    load_env(env)
    assert os.environ["PUCACON_TESTKEY"] == "fromenv"  # real env wins

def test_load_env_missing_file_returns_empty(tmp_path):
    assert load_env(tmp_path / "nope.env") == []
