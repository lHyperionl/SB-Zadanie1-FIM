from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime

from .baseline import Baseline
from .config import Config, trusted_path
from .safefs import Snapshot, scan


@dataclass(frozen=True)
class Finding:
    path: str
    kind: str
    expected: dict | None = None
    actual: dict | None = None
    detail: str = ""

    def data(self) -> dict:
        return asdict(self)

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(json.dumps(self.data(), sort_keys=True, ensure_ascii=True).encode()).hexdigest()


def under(path: str, prefix: str) -> bool:
    return prefix == "." or path == prefix or path.startswith(prefix + "/")


def evaluate(config: Config, baseline: Baseline, snapshot: Snapshot, now: datetime) -> list[Finding]:
    findings = [Finding(path, "scan_error", detail=error) for path, error in sorted(snapshot.issues.items())]
    hashes = baseline.recipe.hashes(now, config.midnight_grace)
    for path in sorted(set(baseline.entries) | set(snapshot.entries)):
        if any(under(path, blocked) for blocked in snapshot.issues):
            continue
        expected = baseline.entries.get(path)
        actual = snapshot.entries.get(path)
        if expected is None:
            findings.append(Finding(path, "added" if actual.kind in ("file", "directory") else "unexpected_type", actual=actual.data()))
        elif actual is None:
            findings.append(Finding(path, "removed", expected=expected.data()))
        elif actual.kind != expected.kind:
            findings.append(Finding(path, "type_changed", expected.data(), actual.data()))
        else:
            e, a = expected.data(), actual.data()
            if (expected.mode, expected.uid, expected.gid) != (actual.mode, actual.uid, actual.gid):
                findings.append(Finding(path, "metadata_changed", e, a))
            if actual.kind == "file":
                if path == "index.html":
                    if actual.sha256 not in hashes:
                        e = {**e, "sha256": sorted(hashes), "size": None}
                        findings.append(Finding(path, "daily_content_changed", e, a))
                elif actual.sha256 != expected.sha256:
                    findings.append(Finding(path, "content_changed", e, a))
    return findings


def inspect(config: Config, baseline: Baseline, clock) -> tuple[list[Finding], set[str]]:
    trusted_path(config.source, root_owned=config.root_owned)
    trusted_path(config.baseline, root_owned=config.root_owned)
    before = clock()
    snapshot = scan(config.web_root, config.max_file_bytes, config.max_entries)
    after = clock()
    if before.date() != after.date():
        # Do not compare a pre-midnight read against a post-midnight expectation.
        snapshot = scan(config.web_root, config.max_file_bytes, config.max_entries)
        after = clock()
    return evaluate(config, baseline, snapshot, after), set(snapshot.issues)
