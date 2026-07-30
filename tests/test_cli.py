import io
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from gitleaks_lite_cli.cli import collect_files, main


class TestCollectFiles(unittest.TestCase):
    def test_single_file_returns_itself(self) -> None:
        with TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "a.txt")
            Path(path).write_text("hello")
            self.assertEqual(collect_files(path), [path])

    def test_directory_walks_recursively(self) -> None:
        with TemporaryDirectory() as tmp:
            (Path(tmp) / "sub").mkdir()
            (Path(tmp) / "a.txt").write_text("x")
            (Path(tmp) / "sub" / "b.txt").write_text("y")
            files = collect_files(tmp)
            self.assertEqual(len(files), 2)

    def test_skips_dot_git_directory(self) -> None:
        with TemporaryDirectory() as tmp:
            (Path(tmp) / ".git").mkdir()
            (Path(tmp) / ".git" / "config").write_text("secretstuff")
            (Path(tmp) / "app.py").write_text("x = 1")
            files = collect_files(tmp)
            self.assertEqual(files, [str(Path(tmp) / "app.py")])

    def test_nonexistent_path_returns_empty(self) -> None:
        self.assertEqual(collect_files("/no/such/path"), [])


class TestMain(unittest.TestCase):
    def test_clean_file_exits_zero(self) -> None:
        with TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "clean.py")
            Path(path).write_text("def add(a, b):\n    return a + b\n")
            out = io.StringIO()
            code = main([path], out=out)
            self.assertEqual(code, 0)
            self.assertIn("no potential secrets found", out.getvalue())

    def test_file_with_secret_exits_one_and_masks_value(self) -> None:
        with TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "config.py")
            Path(path).write_text('aws_key = "AKIAABCDEFGHIJKLMNOP"\n')
            out = io.StringIO()
            code = main([path], out=out)
            self.assertEqual(code, 1)
            output = out.getvalue()
            self.assertIn("AWS Access Key", output)
            self.assertIn("config.py:1", output)
            self.assertNotIn("AKIAABCDEFGHIJKLMNOP", output)
            self.assertIn("AKIA", output)  # masked prefix still visible

    def test_scans_directory_recursively(self) -> None:
        with TemporaryDirectory() as tmp:
            (Path(tmp) / "sub").mkdir()
            (Path(tmp) / "sub" / "secrets.env").write_text('API_KEY="sk_live_abcdefgh12345678"\n')
            out = io.StringIO()
            code = main([tmp], out=out)
            self.assertEqual(code, 1)
            self.assertIn("Generic API Key", out.getvalue())

    def test_missing_path_warns_but_continues(self) -> None:
        with TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "clean.py")
            Path(path).write_text("x = 1\n")
            out = io.StringIO()
            err = io.StringIO()
            code = main(["/no/such/path", path], out=out, err=err)
            self.assertEqual(code, 0)
            self.assertIn("no such file or directory", err.getvalue())

    def test_multiple_secrets_counted(self) -> None:
        with TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "config.py")
            Path(path).write_text(
                'aws_key = "AKIAABCDEFGHIJKLMNOP"\n-----BEGIN RSA PRIVATE KEY-----\n'
            )
            out = io.StringIO()
            code = main([path], out=out)
            self.assertEqual(code, 1)
            self.assertIn("found 2 potential secret(s)", out.getvalue())


if __name__ == "__main__":
    unittest.main()
