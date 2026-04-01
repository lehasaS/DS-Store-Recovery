from pathlib import Path

import pytest

import ds_store_recovery as mod


def test_normalize_url_adds_http_scheme():
    assert mod.normalize_url("example.com/.DS_Store") == "http://example.com/.DS_Store"
    assert mod.normalize_url("https://example.com/.DS_Store") == "https://example.com/.DS_Store"


def test_safe_ds_entry_parts_filters_unsafe_names():
    assert mod.safe_ds_entry_parts("a/b/c") == ["a", "b", "c"]
    assert mod.safe_ds_entry_parts("../etc/passwd") is None
    assert mod.safe_ds_entry_parts("/root") is None
    assert mod.safe_ds_entry_parts(r"a\\b") is None
    assert mod.safe_ds_entry_parts(".") is None


def test_is_within_root_checks_true_boundary(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    ok = (root / "a" / "b").resolve()
    bad = (tmp_path / "other").resolve()

    assert mod.is_within_root(root.resolve(), ok)
    assert not mod.is_within_root(root.resolve(), bad)


def test_local_recovery_copies_and_creates_placeholder(tmp_path):
    source = tmp_path / "source"
    output = tmp_path / "output"
    source_sub = source / "sub"
    source_sub.mkdir(parents=True)
    (source_sub / ".DS_Store").write_bytes(b"dummy")
    (source_sub / "existing.txt").write_text("content", encoding="utf-8")
    (source_sub / "dir1").mkdir()

    def fake_parser(_):
        return {"existing.txt", "missing.txt", "dir1"}

    rec = mod.LocalRecovery(source, output, create_placeholders=True, ds_store_parser=fake_parser)
    rec.run()

    assert (output / "sub" / "existing.txt").read_text(encoding="utf-8") == "content"
    assert (output / "sub" / "missing.txt").exists()
    assert (output / "sub" / "dir1").is_dir()


def test_local_recovery_no_placeholder_skips_missing_file(tmp_path):
    source = tmp_path / "source"
    output = tmp_path / "output"
    source.mkdir()
    (source / ".DS_Store").write_bytes(b"dummy")

    def fake_parser(_):
        return {"missing.txt"}

    rec = mod.LocalRecovery(source, output, create_placeholders=False, ds_store_parser=fake_parser)
    rec.run()

    assert not (output / "missing.txt").exists()


def test_url_recovery_safe_output_path_blocks_escape(tmp_path):
    rec = mod.URLRecovery("http://example.com/.DS_Store", tmp_path)
    with pytest.raises(ValueError):
        rec._safe_output_path("example.com", "/../../etc/passwd")


class _FakeResponse:
    def __init__(self, status_code, url, content, headers=None):
        self.status_code = status_code
        self.url = url
        self.content = content
        self.headers = headers or {}
        self.is_redirect = False
        self.is_permanent_redirect = False


class _FakeSession:
    def __init__(self):
        self.calls = []

    def get(self, url, allow_redirects=True, timeout=10):
        self.calls.append(url)
        return _FakeResponse(200, url, b"ds")

    def close(self):
        return None


def test_url_recovery_respects_max_requests(tmp_path):
    def fake_parser(_):
        return {"admin", "file.txt"}

    rec = mod.URLRecovery(
        start_url="http://example.com/.DS_Store",
        output_dir=tmp_path,
        thread_count=1,
        timeout=1,
        retries=0,
        max_requests=1,
        ds_store_parser=fake_parser,
    )
    rec.session = _FakeSession()
    rec.run()

    # Max request cap should stop expansion after first URL.
    assert rec.total_requests == 1
    # Initial file should still be written.
    assert (tmp_path / "example.com" / ".DS_Store").exists()


def test_parse_args_includes_new_flags():
    args = mod.parse_args(
        [
            "--url",
            "example.com/.DS_Store",
            "--output",
            "./out",
            "--max-requests",
            "50",
            "--log-level",
            "DEBUG",
        ]
    )
    assert args.url == "example.com/.DS_Store"
    assert args.max_requests == 50
    assert args.log_level == "DEBUG"


def test_should_probe_child_ds_store_heuristic():
    assert mod.should_probe_child_ds_store(["wp-content"])
    assert not mod.should_probe_child_ds_store(["index.php"])
    assert mod.should_probe_child_ds_store([".well-known"])


def test_looks_like_directory_path_heuristic():
    assert mod.looks_like_directory_path("/wp-content")
    assert mod.looks_like_directory_path("/wp-content/")
    assert mod.looks_like_directory_path("/")
    assert mod.looks_like_directory_path("/.well-known")
    assert mod.looks_like_directory_path("/release/v1.0")
    assert not mod.looks_like_directory_path("/index.php")


def test_url_recovery_blocks_unsafe_redirect_to_ip(tmp_path):
    rec = mod.URLRecovery("https://example.com/.DS_Store", tmp_path)
    assert not rec._is_safe_redirect(
        "https://example.com/wp-content",
        "http://173.33.150.140/loop-web/wp-content/",
    )


def test_unsafe_redirect_probe_is_enqueued(tmp_path):
    rec = mod.URLRecovery("https://example.com/.DS_Store", tmp_path)
    rec._enqueue_blocked_redirect_probe("https://example.com/wp-includes")

    assert "https://example.com/wp-includes/.DS_Store" in rec.enqueued_url


def test_unsafe_redirect_probe_skips_file_like_path(tmp_path):
    rec = mod.URLRecovery("https://example.com/.DS_Store", tmp_path)
    rec._enqueue_blocked_redirect_probe("https://example.com/index.php")

    assert "https://example.com/index.php/.DS_Store" not in rec.enqueued_url


def test_enqueue_url_deduplicates_entries(tmp_path):
    rec = mod.URLRecovery("https://example.com/.DS_Store", tmp_path)
    first = rec._enqueue_url("https://example.com/wp-content/.DS_Store", reason="test")
    second = rec._enqueue_url("https://example.com/wp-content/.DS_Store", reason="test")

    assert first is True
    assert second is False


def test_parse_args_supports_disabling_unsafe_redirect_probe():
    args = mod.parse_args(
        [
            "--url",
            "example.com/.DS_Store",
            "--output",
            "./out",
            "--no-unsafe-redirect-probe",
        ]
    )
    assert args.no_unsafe_redirect_probe is True


def test_write_response_skips_when_target_is_existing_directory(tmp_path):
    rec = mod.URLRecovery("http://example.com/.DS_Store", tmp_path)
    target_dir = tmp_path / "example.com" / "loop-web" / "index.php"
    target_dir.mkdir(parents=True)
    parsed = mod.urlparse("http://example.com/loop-web/index.php")

    wrote = rec._write_response_content(parsed, b"abc")
    assert not wrote


def test_url_traversal_depth():
    assert mod.url_traversal_depth("https://example.com/.DS_Store") == 0
    assert mod.url_traversal_depth("https://example.com/wp-admin/.DS_Store") == 1
    assert mod.url_traversal_depth("https://example.com/wp-admin/images") == 2


def test_decode_appledouble_name():
    assert mod.decode_appledouble_name("._images") == "images"
    assert mod.decode_appledouble_name("images") is None


def test_url_recovery_enqueues_decoded_appledouble_variant(tmp_path):
    def fake_parser(_):
        return {"._images"}

    rec = mod.URLRecovery(
        start_url="https://example.com/wp-admin/.DS_Store",
        output_dir=tmp_path,
        ds_store_parser=fake_parser,
    )
    rec._parse_and_enqueue_from_ds_store(b"dummy", "https://example.com/wp-admin/")

    assert "https://example.com/wp-admin/._images" in rec.enqueued_url
    assert "https://example.com/wp-admin/images" in rec.enqueued_url
    assert "https://example.com/wp-admin/images/.DS_Store" in rec.enqueued_url


def test_local_recovery_handles_file_dir_collision_without_crash(tmp_path):
    source = tmp_path / "source"
    output = tmp_path / "output"
    source.mkdir()
    (source / ".DS_Store").write_bytes(b"dummy")

    def fake_parser(_):
        return ["a", "a/b"]

    rec = mod.LocalRecovery(source, output, create_placeholders=True, ds_store_parser=fake_parser)
    rec.run()

    assert (output / "a").is_file()
    assert not (output / "a" / "b").exists()
