
import hashlib
import zipfile

import pytest

from backend.backup_recovery import (
    BackupError,
    create_backup,
    restore_backup,
    verify_backup,
)


def make_source(tmp_path):
    source = tmp_path / "source"
    source.mkdir()

    records = {
        "security_audit.jsonl": (
            '{"event_type":"test","decision":"allowed"}\n'
        ),
        "investigation_cases.jsonl": (
            '{"case_id":"test-case","status":"open"}\n'
        ),
        "response_plans.jsonl": (
            '{"plan_id":"test-plan","approved":false}\n'
        ),
        "response_simulations.jsonl": (
            '{"simulation_id":"test-simulation"}\n'
        ),
    }

    for filename, content in records.items():
        # Write identical bytes on Windows and Linux.
        (source / filename).write_bytes(
            content.encode("utf-8")
        )

    return source, records


def test_backup_created_with_four_files(tmp_path):
    source, _ = make_source(tmp_path)
    backup = tmp_path / "backup.zip"

    manifest = create_backup(source, backup)

    assert backup.is_file()
    assert manifest["format_version"] == 1
    assert len(manifest["files"]) == 4


def test_valid_backup_verification(tmp_path):
    source, records = make_source(tmp_path)
    backup = tmp_path / "backup.zip"

    create_backup(source, backup)
    manifest = verify_backup(backup)

    for filename, content in records.items():
        expected_hash = hashlib.sha256(
            content.encode("utf-8")
        ).hexdigest()

        assert (
            manifest["files"][filename]["sha256"]
            == expected_hash
        )


def test_restore_preserves_exact_content(tmp_path):
    source, records = make_source(tmp_path)
    backup = tmp_path / "backup.zip"
    destination = tmp_path / "recovered"

    create_backup(source, backup)
    restore_backup(backup, destination)

    for filename, content in records.items():
        assert (
            destination / filename
        ).read_bytes() == content.encode("utf-8")


def test_restore_refuses_existing_directory(tmp_path):
    source, _ = make_source(tmp_path)
    backup = tmp_path / "backup.zip"
    existing = tmp_path / "existing"

    existing.mkdir()
    sentinel = existing / "important.txt"
    sentinel.write_text("DO NOT DELETE")

    create_backup(source, backup)

    with pytest.raises(
        BackupError,
        match="already exists",
    ):
        restore_backup(backup, existing)

    assert sentinel.read_text() == "DO NOT DELETE"


def test_backup_refuses_overwriting_existing_zip(tmp_path):
    source, _ = make_source(tmp_path)
    backup = tmp_path / "backup.zip"

    create_backup(source, backup)
    original = backup.read_bytes()

    with pytest.raises(
        BackupError,
        match="already exists",
    ):
        create_backup(source, backup)

    assert backup.read_bytes() == original


def test_modified_archive_rejected(tmp_path):
    source, _ = make_source(tmp_path)
    backup = tmp_path / "backup.zip"
    modified = tmp_path / "modified.zip"

    create_backup(source, backup)

    with zipfile.ZipFile(backup) as original:
        entries = {
            name: original.read(name)
            for name in original.namelist()
        }

    entries["security_audit.jsonl"] = (
        b'{"event_type":"tampered"}\n'
    )

    with zipfile.ZipFile(
        modified,
        "w",
    ) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)

    with pytest.raises(
        BackupError,
        match="Integrity verification failed",
    ):
        verify_backup(modified)


def test_unexpected_archive_entry_rejected(tmp_path):
    source, _ = make_source(tmp_path)
    backup = tmp_path / "backup.zip"

    create_backup(source, backup)

    with zipfile.ZipFile(backup, "a") as archive:
        archive.writestr(
            "../outside.txt",
            "unsafe content",
        )

    with pytest.raises(
        BackupError,
        match="Unexpected archive entries",
    ):
        verify_backup(backup)


def test_invalid_jsonl_source_rejected(tmp_path):
    source, _ = make_source(tmp_path)
    backup = tmp_path / "backup.zip"

    (source / "security_audit.jsonl").write_bytes(
        b'{"broken":\n'
    )

    with pytest.raises(
        BackupError,
        match="Invalid JSONL",
    ):
        create_backup(source, backup)

    assert not backup.exists()


def test_empty_source_rejected(tmp_path):
    source = tmp_path / "empty"
    source.mkdir()

    with pytest.raises(
        BackupError,
        match="No recognized SOC records",
    ):
        create_backup(
            source,
            tmp_path / "empty.zip",
        )


def test_restore_rejects_corrupted_backup(tmp_path):
    corrupted = tmp_path / "corrupt.zip"
    destination = tmp_path / "recovered"

    corrupted.write_bytes(
        b"This is not a valid ZIP archive"
    )

    with pytest.raises(
        BackupError,
        match="Corrupted or invalid backup",
    ):
        restore_backup(corrupted, destination)

    assert not destination.exists()
