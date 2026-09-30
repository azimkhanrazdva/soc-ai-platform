from soc_ai.cli import main


def test_cli_version(capsys):
    assert main(["version"]) == 0
    assert "version" in capsys.readouterr().out
