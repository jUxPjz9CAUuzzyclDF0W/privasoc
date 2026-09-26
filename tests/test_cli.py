from typer.testing import CliRunner

from privasoc.cli import app


def test_init_generates_secrets_and_merges_new_settings(tmp_path):
    example = tmp_path / ".env.example"
    example.write_text("PRIVASOC_API_TOKEN=\nPRIVASOC_VECTOR_BIN=vector\n")
    env = tmp_path / ".env"
    env.write_text("PRIVASOC_API_TOKEN=\n")  # an .env created by an older version
    r = CliRunner().invoke(app, ["init", "--env-file", str(env), "--example", str(example)])
    assert r.exit_code == 0, r.output
    text = env.read_text()
    assert "PRIVASOC_VECTOR_BIN=vector" in text
    token = [ln for ln in text.splitlines() if ln.startswith("PRIVASOC_API_TOKEN=")][0]
    assert len(token) > len("PRIVASOC_API_TOKEN=") + 20
    assert token.split("=", 1)[1] not in r.output  # secrets are never printed
