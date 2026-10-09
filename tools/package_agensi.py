#!/usr/bin/env python3
"""Build and verify this repository's Agensi ZIP; never upload or publish it."""

import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import stat
import sys
from urllib.parse import urlsplit
import zipfile

try:
    import yaml
except ImportError:
    sys.exit("Install build dependencies: python3 -m pip install -r tools/requirements.txt")


ROOT = Path(__file__).resolve().parents[1]
# This skill is self-contained. Keep repository tooling out of the installation ZIP.
BUNDLE_FILES = ("SKILL.md", "README.md", "LICENSE", "examples/decision-dialogue.md")
SKILL_NAME = "two-way-steelman"
LAYOUTS = ("folder", "zip-root")


def archive_paths(layout):
    if layout not in LAYOUTS:
        raise ValidationError("Unknown ZIP layout")
    prefix = f"{SKILL_NAME}/" if layout == "folder" else ""
    return {name: prefix + name for name in BUNDLE_FILES}


class ValidationError(ValueError):
    pass


class UniqueKeyLoader(yaml.SafeLoader):
    """Reject ambiguous duplicate keys instead of silently taking the last value."""


def unique_mapping(loader, node, deep=False):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str) or key in mapping:
            raise ValidationError("Frontmatter keys must be unique strings")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping
)


# Transparent, limited heuristics, not Agensi's private scanner or a security score.
PATTERNS = {
    "dangerous_commands": r"\b(?:sudo\s+|rm\s+(?:-[\w]+\s+)*|mkfs\b|dd\s+if=)|(?:curl|wget)[^\n]*\|\s*(?:sh|bash)\b",
    "secrets": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16}|sk-[A-Za-z0-9_-]{20,})\b|https?://[^\s/]+:[^\s/@]+@",
    "environment_reads": r"\b(?:printenv|os\.environ|process\.env)\b|\$\{?[A-Z_][A-Z0-9_]*",
    "obfuscation": r"\b(?:eval\s*\(|exec\s*\(|base64\.(?:b64decode|decodebytes))|[A-Za-z0-9+/]{200,}={0,2}",
    "prompt_injection": r"ignore (?:all |any )?(?:previous|prior|system) (?:instructions|rules)|hide (?:this|these|your) (?:actions|instructions) from (?:the )?user|忽略(?:所有)?(?:之前|系统)的?(?:指令|规则)|(?:窃取|外传)(?:密钥|令牌|凭据)",
}


def validate_payload(files):
    if set(files) != set(BUNDLE_FILES):
        raise ValidationError("Bundle must contain exactly the four declared skill and documentation files")
    texts = {}
    for name, data in files.items():
        try:
            texts[name] = data.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValidationError(f"{name} is not UTF-8 text") from error
        if not data or any(ord(c) < 32 and c not in "\t\n\r" for c in texts[name]):
            raise ValidationError(f"{name} is empty or contains binary control characters")

    match = re.match(r"\A---\n(.*?)\n---\n(.*)\Z", texts["SKILL.md"], re.S)
    if not match:
        raise ValidationError("SKILL.md needs YAML frontmatter between --- lines")
    try:
        frontmatter = yaml.load(match[1], Loader=UniqueKeyLoader)
    except yaml.YAMLError as error:
        raise ValidationError("Invalid YAML frontmatter") from error
    if not isinstance(frontmatter, dict):
        raise ValidationError("Frontmatter must be a mapping")
    name = frontmatter.get("name")
    if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name) or len(name) > 64:
        raise ValidationError("Invalid skill name")
    if name != SKILL_NAME:
        raise ValidationError(f"Skill name must remain {SKILL_NAME}")
    description = frontmatter.get("description")
    if not isinstance(description, str) or not description.strip() or len(description) > 1024:
        raise ValidationError("Description must be a non-empty string of at most 1024 characters")
    body = match[2].strip("\n")
    original = re.search(r"## 原文全文\n\n```text\n(.*?)\n```", texts["README.md"], re.S)
    if not body or original is None or body != original[1]:
        raise ValidationError("Skill body must match the original prompt documented in README.md")
    if not texts["LICENSE"].startswith("MIT License\n"):
        raise ValidationError("The existing MIT license must be bundled")

    # Check relative Markdown references without fetching any external resources.
    for filename, text in texts.items():
        for target in re.findall(r"\]\(([^\s)]+)\)", text):
            url = urlsplit(target)
            if not url.scheme and not target.startswith("#") and url.path not in files:
                raise ValidationError(f"Unbundled local reference in {filename}: {url.path}")

    findings = []
    for filename, text in texts.items():
        for category, pattern in PATTERNS.items():
            for hit in re.finditer(pattern, text, re.I):
                findings.append({"file": filename, "category": category,
                                 "line": text[:hit.start()].count("\n") + 1})
    if findings:
        # Never print potential secret values.
        raise ValidationError("Local heuristic findings require review: " + json.dumps(findings))
    urls = sorted({url.rstrip(".,;") for text in texts.values()
                   for url in re.findall(r"https?://[^\s)<>`\"]+", text)})
    return {
        "name": name,
        "description_characters": len(description),
        "files": {name: {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                  for name, data in sorted(files.items())},
        "local_checks": "passed",
        "heuristic_findings": findings,
        "outbound_urls_in_text": urls,
        "network_note": "URLs are documentation/install references; packaging makes no network calls.",
        "platform_security_scan": "not run; private rules cannot be reproduced locally",
        "platform_manual_review": "not submitted",
    }


def load_payload(root=ROOT):
    files = {}
    for name in BUNDLE_FILES:
        path = root / name
        if path.is_symlink() or not path.is_file():
            raise ValidationError(f"{name} must be a regular file, not a symlink")
        files[name] = path.read_bytes()
    validate_payload(files)
    return files


def build_archive(files, layout="folder"):
    validate_payload(files)
    paths = archive_paths(layout)
    output = io.BytesIO()
    # Fixed metadata + ZIP_STORED make bytes independent of mtimes and zlib versions.
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for name in BUNDLE_FILES:
            info = zipfile.ZipInfo(paths[name], date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, files[name])
    return output.getvalue()


def verify_archive(data, expected=None, layout="folder"):
    paths = archive_paths(layout)
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            if len(infos) != len(BUNDLE_FILES) or {i.filename for i in infos} != set(paths.values()):
                raise ValidationError("Unexpected, duplicate, nested or unsafe ZIP paths")
            for info in infos:
                if info.is_dir() or info.flag_bits & 1 or (info.create_system == 3 and
                        not stat.S_ISREG(info.external_attr >> 16)):
                    raise ValidationError("ZIP members must be unencrypted regular files")
            files = {name: archive.read(path) for name, path in paths.items()}
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError) as error:
        raise ValidationError("Invalid or corrupted ZIP") from error
    report = validate_payload(files)
    if expected is not None and files != expected:
        raise ValidationError("ZIP content differs from the current source files")
    report["zip_sha256"] = hashlib.sha256(data).hexdigest()
    report["zip_bytes"] = len(data)
    report["zip_layout"] = layout
    report["zip_member_paths"] = list(paths.values())
    report["submission_layout_status"] = "unconfirmed: public docs require folder; delegated email asks for ZIP root"
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--layout", choices=LAYOUTS, default="folder",
                        help="folder: public docs candidate (default); zip-root: delegated email candidate")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="Validate source without writing a ZIP")
    mode.add_argument("--verify", type=Path, help="Validate a ZIP and compare it with source")
    mode.add_argument("--output", type=Path, help="Build ZIP at this path; refuse to replace different content")
    args = parser.parse_args()
    try:
        files = load_payload()
        if ROOT.name != SKILL_NAME:
            raise ValidationError(f"Repository/install directory must be named {SKILL_NAME}")
        if args.check:
            report = validate_payload(files)
        elif args.verify:
            report = verify_archive(args.verify.read_bytes(), files, args.layout)
            report["zip_path"] = str(args.verify.resolve())
        else:
            path = args.output or ROOT / "dist" / f"{SKILL_NAME}-agensi-{args.layout}.zip"
            if path.suffix != ".zip":
                raise ValidationError("Output path must end in .zip")
            data = build_archive(files, args.layout)
            report = verify_archive(data, files, args.layout)
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists():
                if path.is_symlink() or not path.is_file() or path.read_bytes() != data:
                    raise ValidationError("Refusing to overwrite an existing, different output")
            else:
                with path.open("xb") as output:
                    output.write(data)
            report["zip_path"] = str(path.resolve())
        print(json.dumps(report, ensure_ascii=False, indent=2))
    except (ValidationError, OSError) as error:
        parser.exit(1, f"Validation failed: {error}\n")


if __name__ == "__main__":
    main()
