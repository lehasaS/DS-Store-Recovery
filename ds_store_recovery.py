#!/usr/bin/env python3

import argparse
import contextlib
import logging
import ipaddress
import queue
import shutil
import sys
import threading
from io import BytesIO
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urljoin, urlparse

import requests
from ds_store import DSStore
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


LOG = logging.getLogger("ds_store_recovery")


def normalize_url(url):
    if not url.lower().startswith(("http://", "https://")):
        return "http://%s" % url
    return url


def parse_ds_store_names(ds_store_bytes):
    stream = BytesIO(ds_store_bytes)
    d = DSStore.open(stream)
    try:
        names = set()
        for entry in d._traverse(None):
            names.add(entry.filename)
        return names
    finally:
        with contextlib.suppress(Exception):
            d.close()


def is_within_root(root, path):
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def is_ip_hostname(hostname):
    if not hostname:
        return False
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def should_probe_child_ds_store(parts):
    # Heuristic: only probe nested .DS_Store for likely directory entries.
    name = parts[-1]
    return "." not in name


class ColorFormatter(logging.Formatter):
    RESET = "\033[0m"
    COLORS = {
        "DEBUG": "\033[36m",
        "INFO": "\033[32m",
        "WARNING": "\033[33m",
        "ERROR": "\033[31m",
        "CRITICAL": "\033[35m",
    }

    def format(self, record):
        message = super().format(record)
        color = self.COLORS.get(record.levelname, "")
        if not color:
            return message
        return "%s%s%s" % (color, message, self.RESET)


def safe_ds_entry_parts(entry_name):
    if not entry_name or entry_name == ".":
        return None
    if entry_name.startswith("/") or entry_name.startswith("\\"):
        return None
    if "\\" in entry_name:
        return None

    posix_path = PurePosixPath(entry_name)
    parts = list(posix_path.parts)
    if any(p in ("", ".", "..") for p in parts):
        return None
    return parts


class URLRecovery(object):
    def __init__(
        self,
        start_url,
        output_dir,
        thread_count=10,
        timeout=10,
        retries=2,
        max_requests=10000,
        max_redirects=5,
        ds_store_parser=parse_ds_store_names,
    ):
        self.start_url = normalize_url(start_url)
        self.output_dir = Path(output_dir).resolve()
        self.thread_count = thread_count
        self.timeout = timeout
        self.retries = retries
        self.max_requests = max_requests
        self.max_redirects = max_redirects
        self.ds_store_parser = ds_store_parser

        self.queue = queue.Queue()
        self.queue.put(self.start_url)
        self.processed_url = set()
        self.active_workers = 0
        self.lock = threading.Lock()
        self.total_requests = 0
        self.total_downloaded = 0
        self.total_errors = 0
        self.stop_requested = False

        self.session = requests.Session()
        retry_cfg = Retry(
            total=self.retries,
            connect=self.retries,
            read=self.retries,
            backoff_factor=0.3,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=("GET",),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry_cfg)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def _safe_output_path(self, netloc, url_path):
        host_dir = netloc.replace(":", "_")
        relative = unquote(url_path.lstrip("/"))
        if not relative:
            relative = "index"

        target = (self.output_dir / host_dir / relative).resolve()
        allowed_root = (self.output_dir / host_dir).resolve()
        if not is_within_root(allowed_root, target):
            raise ValueError("Refusing unsafe target path: %s" % target)
        return target

    @staticmethod
    def _strip_ds_store_suffix(url):
        if url.lower().endswith(".ds_store"):
            return url[:-len(".DS_Store")]
        return url

    def _parse_and_enqueue_from_ds_store(self, ds_store_bytes, base_url):
        try:
            names = self.ds_store_parser(ds_store_bytes)
        except Exception as exc:
            LOG.warning("Skipping invalid .DS_Store content at %s (%s)", base_url, exc)
            return

        for name in names:
            parts = safe_ds_entry_parts(name)
            if not parts:
                continue

            normalized_name = "/".join(parts)
            child_url = urljoin(base_url, normalized_name)
            self.queue.put(child_url)
            if should_probe_child_ds_store(parts):
                self.queue.put(urljoin(base_url, normalized_name.rstrip("/") + "/.DS_Store"))

    def _is_safe_redirect(self, old_url, new_url):
        old = urlparse(old_url)
        new = urlparse(new_url)
        if old.hostname != new.hostname:
            return False
        if is_ip_hostname(new.hostname):
            return False
        if old.scheme == "https" and new.scheme != "https":
            return False
        return True

    def _get_with_safe_redirects(self, url):
        current = url
        for _ in range(self.max_redirects + 1):
            response = self.session.get(current, allow_redirects=False, timeout=self.timeout)
            if response.is_redirect or response.is_permanent_redirect:
                location = response.headers.get("Location")
                if not location:
                    return response
                target = urljoin(current, location)
                if not self._is_safe_redirect(current, target):
                    LOG.warning("Blocked unsafe redirect: %s -> %s", current, target)
                    return response
                current = target
                continue
            return response
        LOG.warning("Redirect limit reached for %s", url)
        return response

    def _write_response_content(self, parsed_url, content):
        target_path = self._safe_output_path(parsed_url.netloc, parsed_url.path)
        parent = target_path.parent

        if parent.exists() and not parent.is_dir():
            LOG.warning("Skipping write due to file/dir collision (parent is file): %s", parent)
            return False

        parent.mkdir(parents=True, exist_ok=True)

        if target_path.exists() and target_path.is_dir():
            LOG.warning("Skipping write due to file/dir collision (target is dir): %s", target_path)
            return False

        target_path.write_bytes(content)
        return True

    def _worker(self):
        while True:
            if self.stop_requested:
                break
            try:
                url = self.queue.get(timeout=1.0)
            except queue.Empty:
                with self.lock:
                    should_exit = self.active_workers == 0 and self.queue.empty()
                if should_exit:
                    break
                continue

            with self.lock:
                self.active_workers += 1

            try:
                with self.lock:
                    if url in self.processed_url:
                        continue
                    if self.total_requests >= self.max_requests:
                        self.stop_requested = True
                        LOG.warning(
                            "Reached max request cap (%d); stopping crawl",
                            self.max_requests,
                        )
                        continue
                    self.processed_url.add(url)
                    self.total_requests += 1

                response = self._get_with_safe_redirects(url)
                status = response.status_code
                final_url = response.url
                LOG.info("[%s] %s", status, final_url)

                if status != 200:
                    continue

                parsed = urlparse(final_url)
                wrote = self._write_response_content(parsed, response.content)
                if not wrote:
                    continue
                with self.lock:
                    self.total_downloaded += 1

                if parsed.path.lower().endswith(".ds_store"):
                    base_url = self._strip_ds_store_suffix(final_url)
                    self._parse_and_enqueue_from_ds_store(response.content, base_url)

            except Exception as exc:
                LOG.error("Worker error: %s", exc)
                with self.lock:
                    self.total_errors += 1
            finally:
                with self.lock:
                    self.active_workers -= 1
                self.queue.task_done()

    def run(self):
        self.output_dir.mkdir(parents=True, exist_ok=True)
        threads = []
        for _ in range(self.thread_count):
            t = threading.Thread(target=self._worker)
            t.start()
            threads.append(t)
        for t in threads:
            t.join()
        self.session.close()
        LOG.info(
            "URL recovery complete: requests=%d downloaded=%d errors=%d",
            self.total_requests,
            self.total_downloaded,
            self.total_errors,
        )


class LocalRecovery(object):
    def __init__(
        self,
        source_dir,
        output_dir,
        create_placeholders=True,
        ds_store_parser=parse_ds_store_names,
    ):
        self.source_dir = Path(source_dir).resolve()
        self.output_dir = Path(output_dir).resolve()
        self.create_placeholders = create_placeholders
        self.ds_store_parser = ds_store_parser
        self.total_ds_store = 0
        self.total_dirs = 0
        self.total_files = 0
        self.total_placeholders = 0

    def _safe_resolve_in_root(self, root, candidate):
        resolved = candidate.resolve()
        root_resolved = root.resolve()
        if not is_within_root(root_resolved, resolved):
            raise ValueError("Refusing unsafe path outside root: %s" % resolved)
        return resolved

    def _out_path_for_entry(self, ds_store_path, entry_parts):
        ds_parent_rel = ds_store_path.parent.relative_to(self.source_dir)
        out_path = self.output_dir / ds_parent_rel / Path(*entry_parts)
        return self._safe_resolve_in_root(self.output_dir, out_path)

    def _src_path_for_entry(self, ds_store_path, entry_parts):
        ds_parent_rel = ds_store_path.parent.relative_to(self.source_dir)
        src_path = self.source_dir / ds_parent_rel / Path(*entry_parts)
        return self._safe_resolve_in_root(self.source_dir, src_path)

    def run(self):
        if not self.source_dir.exists() or not self.source_dir.is_dir():
            raise ValueError("Local source directory does not exist: %s" % self.source_dir)

        self.output_dir.mkdir(parents=True, exist_ok=True)
        ds_store_files = sorted(self.source_dir.rglob(".DS_Store"))
        self.total_ds_store = len(ds_store_files)
        LOG.info("Found %d .DS_Store files", len(ds_store_files))

        for ds_path in ds_store_files:
            LOG.info("Parsing %s", ds_path)
            try:
                names = self.ds_store_parser(ds_path.read_bytes())
            except Exception as exc:
                LOG.error("Failed to parse %s: %s", ds_path, exc)
                continue

            for name in names:
                parts = safe_ds_entry_parts(name)
                if not parts:
                    continue

                out_path = self._out_path_for_entry(ds_path, parts)
                src_path = self._src_path_for_entry(ds_path, parts)

                if src_path.is_dir():
                    out_path.mkdir(parents=True, exist_ok=True)
                    self.total_dirs += 1
                    continue

                out_path.parent.mkdir(parents=True, exist_ok=True)
                if src_path.exists() and src_path.is_file():
                    shutil.copy2(src_path, out_path)
                    self.total_files += 1
                else:
                    if self.create_placeholders:
                        # If data is unavailable locally, create an empty placeholder.
                        out_path.touch(exist_ok=True)
                        self.total_placeholders += 1
                    else:
                        LOG.debug("Skipping missing file without placeholder: %s", src_path)

        LOG.info(
            "Local recovery complete: ds_store=%d dirs=%d files=%d placeholders=%d",
            self.total_ds_store,
            self.total_dirs,
            self.total_files,
            self.total_placeholders,
        )


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Recover file/folder structures from .DS_Store via URL or local directory"
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--url", help="Starting URL (usually ending in /.DS_Store)")
    mode.add_argument("--local", help="Local directory to recursively scan for .DS_Store")
    parser.add_argument(
        "--output",
        required=True,
        help="Output directory where recovered structure/files are written",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=10,
        help="Number of worker threads for URL mode (default: 10)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="HTTP timeout in seconds for URL mode (default: 10)",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=2,
        help="HTTP retry count for URL mode (default: 2)",
    )
    parser.add_argument(
        "--no-placeholders",
        action="store_true",
        help="In local mode, skip creating placeholder files for missing content",
    )
    parser.add_argument(
        "--max-requests",
        type=int,
        default=10000,
        help="Maximum HTTP requests in URL mode before stopping (default: 10000)",
    )
    parser.add_argument(
        "--max-redirects",
        type=int,
        default=5,
        help="Maximum safe redirects to follow for each request (default: 5)",
    )
    parser.add_argument(
        "--log-level",
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
        default="INFO",
        help="Logging verbosity (default: INFO)",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    handler = logging.StreamHandler()
    handler.setFormatter(ColorFormatter("%(levelname)s %(message)s"))
    LOG.handlers = [handler]
    LOG.setLevel(getattr(logging, args.log_level))
    LOG.propagate = False

    try:
        if args.url:
            runner = URLRecovery(
                start_url=args.url,
                output_dir=args.output,
                thread_count=max(1, args.threads),
                timeout=max(1, args.timeout),
                retries=max(0, args.retries),
                max_requests=max(1, args.max_requests),
                max_redirects=max(0, args.max_redirects),
            )
            runner.run()
            return 0

        runner = LocalRecovery(
            source_dir=args.local,
            output_dir=args.output,
            create_placeholders=not args.no_placeholders,
        )
        runner.run()
        return 0
    except KeyboardInterrupt:
        LOG.error("Interrupted by user")
        return 130
    except Exception as exc:
        LOG.error("Fatal error: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())