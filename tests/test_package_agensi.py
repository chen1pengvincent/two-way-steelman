import importlib.util
import io
import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
import warnings
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("package_agensi", ROOT / "tools/package_agensi.py")
package = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(package)


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.files = package.load_payload(ROOT)

    def test_round_trip_is_deterministic_and_preserves_all_bytes(self):
        for layout in package.LAYOUTS:
            with self.subTest(layout=layout):
                data = package.build_archive(self.files, layout)
                self.assertEqual(data, package.build_archive(dict(reversed(list(self.files.items()))), layout))
                report = package.verify_archive(data, self.files, layout)
                self.assertEqual(report["local_checks"], "passed")
                paths = package.archive_paths(layout)
                with zipfile.ZipFile(io.BytesIO(data)) as archive:
                    self.assertEqual(archive.namelist(), list(paths.values()))
                    for name, content in self.files.items():
                        self.assertEqual(archive.read(paths[name]), content)

    def test_layouts_cannot_be_confused_and_unknown_layout_is_rejected(self):
        for layout, other in [("folder", "zip-root"), ("zip-root", "folder")]:
            with self.assertRaises(package.ValidationError):
                package.verify_archive(package.build_archive(self.files, layout), self.files, other)
        with self.assertRaises(package.ValidationError):
            package.build_archive(self.files, "unknown")

    def test_missing_license_and_extra_files_are_rejected(self):
        for files in [{k: v for k, v in self.files.items() if k != "LICENSE"},
                      {**self.files, ".env": b"not-for-distribution"}]:
            with self.assertRaises(package.ValidationError):
                package.validate_payload(files)

    def test_invalid_duplicate_empty_and_oversized_frontmatter_are_rejected(self):
        skill = self.files["SKILL.md"].decode()
        variants = [skill.replace("name: two-way-steelman", "name: Bad_Name"),
                    skill.replace("name: two-way-steelman", "name: two-way-steelman\nname: duplicate"),
                    skill.replace("description: ", "description: [", 1),
                    "---\nname: two-way-steelman\ndescription: ''\n---\nbody",
                    "---\nname: two-way-steelman\ndescription: " + "x" * 1025 + "\n---\nbody"]
        for variant in variants:
            with self.subTest(frontmatter=variant[:70]), self.assertRaises(package.ValidationError):
                package.validate_payload({**self.files, "SKILL.md": variant.encode()})

    def test_body_drift_and_missing_references_are_rejected(self):
        for name, content in [("SKILL.md", self.files["SKILL.md"] + b"\nchanged"),
                              ("README.md", self.files["README.md"] + b"\n[extra](references/missing.md)")]:
            with self.assertRaises(package.ValidationError):
                package.validate_payload({**self.files, name: content})

    def test_binary_and_secret_patterns_are_rejected_without_echoing_secrets(self):
        secret = b"ghp_" + b"A" * 36
        for content in [b"\x00binary", b"\xff", self.files["README.md"] + b"\n" + secret]:
            with self.assertRaises(package.ValidationError) as caught:
                package.validate_payload({**self.files, "README.md": content})
            self.assertNotIn(secret.decode(), str(caught.exception))

    def test_archive_path_duplicate_and_symlink_are_rejected(self):
        for kind in ["path", "duplicate", "symlink"]:
            output = io.BytesIO()
            with warnings.catch_warnings(), zipfile.ZipFile(output, "w") as archive:
                warnings.simplefilter("ignore", UserWarning)
                for name, data in self.files.items():
                    path = package.archive_paths("folder")[name]
                    info = zipfile.ZipInfo("../SKILL.md" if kind == "path" and name == "SKILL.md" else path)
                    info.create_system = 3
                    mode = stat.S_IFLNK if kind == "symlink" and name == "SKILL.md" else stat.S_IFREG
                    info.external_attr = (mode | 0o644) << 16
                    archive.writestr(info, data)
                if kind == "duplicate":
                    archive.writestr("two-way-steelman/SKILL.md", self.files["SKILL.md"])
            with self.subTest(kind=kind), self.assertRaises(package.ValidationError):
                package.verify_archive(output.getvalue())

    def test_source_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, content in self.files.items():
                (root / name).parent.mkdir(parents=True, exist_ok=True)
                (root / name).write_bytes(content)
            (root / "LICENSE").unlink()
            (root / "LICENSE").symlink_to(ROOT / "LICENSE")
            with self.assertRaises(package.ValidationError):
                package.load_payload(root)

    def test_corrupt_archive_and_source_mismatch_are_rejected(self):
        data = package.build_archive(self.files)
        corrupted = bytearray(data)
        corrupted[data.index(self.files["SKILL.md"])] ^= 1
        for candidate, expected in [(bytes(corrupted), self.files),
                                    (data, {**self.files, "README.md": b"different"})]:
            with self.assertRaises(package.ValidationError):
                package.verify_archive(candidate, expected)

    def test_cli_build_verify_and_refuse_overwrite(self):
        command = [sys.executable, str(ROOT / "tools/package_agensi.py")]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "submission.zip"
            built = subprocess.run(command + ["--output", str(path)], capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stderr)
            verified = subprocess.run(command + ["--verify", str(path)], capture_output=True, text=True)
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertEqual(json.loads(built.stdout)["zip_sha256"], json.loads(verified.stdout)["zip_sha256"])
            path.write_bytes(b"existing-user-content")
            refused = subprocess.run(command + ["--output", str(path)], capture_output=True, text=True)
            self.assertNotEqual(refused.returncode, 0)
            self.assertEqual(path.read_bytes(), b"existing-user-content")


if __name__ == "__main__":
    unittest.main()
