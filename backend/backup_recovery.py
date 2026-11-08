
"""
Experiment 61 — SOC Backup and Recovery.

Commands:
    backup  — Create a ZIP archive with SHA-256 manifest.
    verify  — Validate archive structure, contents, and hashes.
    restore — Restore only into a new, nonexistent directory.

Backups should be created while the application is stopped
to obtain a consistent snapshot of its JSONL stores.

SHA-256 detects accidental modification but does not
authenticate the backup against a malicious replacement.
"""

import argparse
import hashlib
import json
import os
import shutil
import tempfile
import zipfile

from datetime import datetime, timezone
from pathlib import Path


BACKUP_VERSION = 1

DATA_FILES = (
    "security_audit.jsonl",
    "investigation_cases.jsonl",
    "response_plans.jsonl",
    "response_simulations.jsonl",
)

MANIFEST_NAME = "manifest.json"

MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024


class BackupError(ValueError):
    """Backup format, integrity, or recovery error."""


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _validate_jsonl(data: bytes, name: str) -> None:
    try:
        content = data.decode("utf-8")

        for line_number, line in enumerate(
            content.splitlines(),
            start=1,
        ):
            if not line.strip():
                raise BackupError(
                    f"Blank JSONL record: {name}, line {line_number}"
                )

            record = json.loads(line)

            if not isinstance(record, dict):
                raise BackupError(
                    f"Invalid JSONL object: {name}, line {line_number}"
                )

    except (UnicodeError, json.JSONDecodeError) as exc:
        raise BackupError(
            f"Invalid JSONL data in {name}"
        ) from exc


def _read_source_files(source: Path) -> dict[str, bytes]:
    if not source.is_dir():
        raise BackupError("Source directory does not exist")

    if source.is_symlink():
        raise BackupError("Source cannot be a symbolic link")

    selected = {}
    total_bytes = 0

    for name in DATA_FILES:
        path = source / name

        if path.is_symlink():
            raise BackupError(
                f"Symbolic links are not supported: {name}"
            )

        if not path.exists():
            continue

        if not path.is_file():
            raise BackupError(
                f"Expected a regular file: {name}"
            )

        if path.stat().st_size > MAX_FILE_BYTES:
            raise BackupError(
                f"File exceeds backup limit: {name}"
            )

        with path.open("rb") as stream:
            data = stream.read(MAX_FILE_BYTES + 1)

        if len(data) > MAX_FILE_BYTES:
            raise BackupError(
                f"File exceeds backup limit: {name}"
            )

        _validate_jsonl(data, name)

        total_bytes += len(data)

        if total_bytes > MAX_TOTAL_BYTES:
            raise BackupError("Backup exceeds size limit")

        selected[name] = data

    if not selected:
        raise BackupError(
            "No recognized SOC records found to back up"
        )

    return selected


def create_backup(
    source: Path,
    output: Path,
) -> dict:
    source = Path(source)
    output = Path(output)

    if output.exists():
        raise BackupError(
            "Backup destination already exists"
        )

    if not output.parent.is_dir():
        raise BackupError(
            "Backup destination directory does not exist"
        )

    files = _read_source_files(source)

    manifest = {
        "format_version": BACKUP_VERSION,
        "created_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "files": {
            name: {
                "sha256": _digest(data),
                "size": len(data),
            }
            for name, data in sorted(files.items())
        },
    }

    temporary_path = None

    try:
        with tempfile.NamedTemporaryFile(
            prefix=".soc-backup-",
            suffix=".zip",
            dir=output.parent,
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)

        with zipfile.ZipFile(
            temporary_path,
            mode="w",
            compression=zipfile.ZIP_DEFLATED,
        ) as archive:
            archive.writestr(
                MANIFEST_NAME,
                json.dumps(
                    manifest,
                    indent=2,
                    sort_keys=True,
                ),
            )

            for name, data in sorted(files.items()):
                archive.writestr(name, data)

        # Create output exclusively: never replace a backup.
        with output.open("xb") as destination:
            try:
                with temporary_path.open("rb") as source_file:
                    shutil.copyfileobj(
                        source_file,
                        destination,
                    )
            except Exception:
                destination.close()
                output.unlink(missing_ok=True)
                raise

    except FileExistsError as exc:
        raise BackupError(
            "Backup destination already exists"
        ) from exc

    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)

    return manifest


def _load_verified_archive(
    backup: Path,
) -> tuple[dict, dict[str, bytes]]:
    backup = Path(backup)

    if backup.is_symlink() or not backup.is_file():
        raise BackupError(
            "Backup file is missing or is a symbolic link"
        )

    try:
        with zipfile.ZipFile(backup, "r") as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]

            if (
                len(names) != len(set(names))
                or MANIFEST_NAME not in names
            ):
                raise BackupError(
                    "Invalid or duplicate backup entries"
                )

            allowed = set(DATA_FILES)
            allowed.add(MANIFEST_NAME)

            if not set(names).issubset(allowed):
                raise BackupError(
                    "Unexpected archive entries"
                )

            for info in infos:
                if info.is_dir():
                    raise BackupError(
                        "Archive directories are not allowed"
                    )

                if info.filename == MANIFEST_NAME:
                    limit = MAX_MANIFEST_BYTES
                else:
                    limit = MAX_FILE_BYTES

                if info.file_size > limit:
                    raise BackupError(
                        "Archive entry exceeds size limit"
                    )

            raw_manifest = archive.read(
                MANIFEST_NAME
            )

            if len(raw_manifest) > MAX_MANIFEST_BYTES:
                raise BackupError(
                    "Manifest exceeds size limit"
                )

            manifest = json.loads(
                raw_manifest.decode("utf-8")
            )

            if not isinstance(manifest, dict):
                raise BackupError("Invalid manifest")

            if manifest.get("format_version") != BACKUP_VERSION:
                raise BackupError(
                    "Unsupported backup format"
                )

            expected_files = manifest.get("files")

            if (
                not isinstance(expected_files, dict)
                or not expected_files
                or not set(expected_files).issubset(
                    set(DATA_FILES)
                )
            ):
                raise BackupError(
                    "Invalid manifest file list"
                )

            if set(names) != (
                set(expected_files) | {MANIFEST_NAME}
            ):
                raise BackupError(
                    "Archive does not match manifest"
                )

            recovered = {}
            total_bytes = 0

            for name, metadata in expected_files.items():
                if not isinstance(metadata, dict):
                    raise BackupError(
                        "Invalid file metadata"
                    )

                expected_size = metadata.get("size")
                expected_digest = metadata.get("sha256")

                if (
                    type(expected_size) is not int
                    or expected_size < 0
                    or expected_size > MAX_FILE_BYTES
                    or not isinstance(expected_digest, str)
                    or len(expected_digest) != 64
                ):
                    raise BackupError(
                        "Invalid file integrity metadata"
                    )

                with archive.open(name) as stream:
                    data = stream.read(
                        MAX_FILE_BYTES + 1
                    )

                total_bytes += len(data)

                if total_bytes > MAX_TOTAL_BYTES:
                    raise BackupError(
                        "Archive exceeds total size limit"
                    )

                if (
                    len(data) != expected_size
                    or _digest(data) != expected_digest
                ):
                    raise BackupError(
                        f"Integrity verification failed: {name}"
                    )

                _validate_jsonl(data, name)
                recovered[name] = data

            return manifest, recovered

    except (
        zipfile.BadZipFile,
        UnicodeError,
        json.JSONDecodeError,
        EOFError,
    ) as exc:
        raise BackupError(
            "Corrupted or invalid backup archive"
        ) from exc


def verify_backup(backup: Path) -> dict:
    manifest, _ = _load_verified_archive(backup)
    return manifest


def restore_backup(
    backup: Path,
    destination: Path,
) -> dict:
    destination = Path(destination)

    if destination.exists() or destination.is_symlink():
        raise BackupError(
            "Restore destination already exists"
        )

    if not destination.parent.is_dir():
        raise BackupError(
            "Restore parent directory does not exist"
        )

    # Validate everything before creating the destination.
    manifest, recovered = _load_verified_archive(
        backup
    )

    try:
        destination.mkdir()

        for name, data in recovered.items():
            with (destination / name).open("xb") as stream:
                stream.write(data)

    except Exception:
        if destination.is_dir():
            shutil.rmtree(destination)
        raise

    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Offline SOC backup, integrity verification, "
            "and safe recovery"
        )
    )

    commands = parser.add_subparsers(
        dest="command",
        required=True,
    )

    backup_command = commands.add_parser("backup")
    backup_command.add_argument("--source", required=True)
    backup_command.add_argument("--output", required=True)

    verify_command = commands.add_parser("verify")
    verify_command.add_argument("--backup", required=True)

    restore_command = commands.add_parser("restore")
    restore_command.add_argument("--backup", required=True)
    restore_command.add_argument(
        "--destination",
        required=True,
    )

    args = parser.parse_args()

    try:
        if args.command == "backup":
            manifest = create_backup(
                Path(args.source),
                Path(args.output),
            )
            message = "Backup created"

        elif args.command == "verify":
            manifest = verify_backup(
                Path(args.backup)
            )
            message = "Backup verified"

        else:
            manifest = restore_backup(
                Path(args.backup),
                Path(args.destination),
            )
            message = "Backup restored"

    except (BackupError, OSError) as exc:
        parser.exit(
            status=1,
            message=f"Backup operation failed: {exc}\n",
        )

    print(
        f"{message}: "
        f"{len(manifest['files'])} data file(s)"
    )

    for name in manifest["files"]:
        print(f"  {name}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
