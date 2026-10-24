#!/usr/bin/env python3
"""Non-destructive organizer for the user's AIRC 2027 research repository.

Dry run by default. Use --apply to move old run outputs and historical docs,
archive old test backups, remove regenerable __pycache__, and write a SHA256
movement manifest. Never modifies benchmark sources, datasets, scenarios,
policies, active Stage 5.2 outputs, tests, .venv, or .git.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import shutil
from pathlib import Path


HISTORY_DOCUMENTS = {
    "STAGE3_1_README.md", "STAGE3_2_REAL_DOCUMENT_README.md",
    "STAGE3_3_README.md", "STAGE3_RESEARCH_LOG.md",
    "STAGE4_RUNTIME_GUARD_README.md", "README_STAGE4_2.md",
    "README_STAGE5.md", "README_STAGE5_1.md", "README_STAGE5_2.md",
}
LATEST_PREFIX = "stage5_2_"
VERIFICATION_FILES = {
    "Stage5_Original_Trace_Verification.json",
    "Stage5_1_Independent_Trace_Review.json",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def bucket(name: str) -> str:
    if name.startswith("stage5_2_"):
        return "stage5_2"
    if name.startswith("stage5_1_"):
        return "stage5_1"
    if name.startswith("stage5_"):
        return "stage5"
    if name.startswith("stage4_2_"):
        return "stage4_2"
    if name.startswith("stage4_"):
        return "stage4"
    if name.startswith("genai_qwen2_guard_v42"):
        return "stage4_2"
    if name.startswith("genai_qwen2_guard_pilot"):
        return "stage4"
    if name.startswith("genai_"):
        return "stage3_4"
    if name.startswith("robustness_"):
        return "stage3_3"
    if name.startswith("nist_real_doc_"):
        return "stage3_2"
    return "other"


def safe_destination(dst: Path, booked: set[Path]) -> Path:
    if dst not in booked and not dst.exists():
        booked.add(dst)
        return dst
    count = 2
    while True:
        candidate = dst.with_name(f"{dst.stem}__preserved_{count}{dst.suffix}")
        if candidate not in booked and not candidate.exists():
            booked.add(candidate)
            return candidate
        count += 1


def discover(root: Path) -> tuple[list[tuple[Path, Path]], list[Path]]:
    moves: list[tuple[Path, Path]] = []
    cache_dirs: list[Path] = []
    booked: set[Path] = set()

    def add(src: Path, rel_dest: Path) -> None:
        if not src.exists() or src.is_symlink():
            return
        if src.is_dir() and not src.name.startswith(("benchmark_before_", "tests_before_")):
            return
        dst = safe_destination(root / rel_dest, booked)
        moves.append((src, dst))

    for name in sorted(HISTORY_DOCUMENTS):
        add(root / name, Path("docs") / "history" / name)
    add(root / "STAGE5_2_PROTOCOL.json", Path("research_evidence") / "stage5_2" / "protocol" / "STAGE5_2_PROTOCOL.json")
    for candidate in sorted(root.iterdir()):
        if candidate.is_dir() and candidate.name.startswith(("benchmark_before_", "tests_before_")):
            add(candidate, Path("research_evidence") / "code_backups" / candidate.name)

    outputs = root / "benchmark" / "outputs"
    if outputs.is_dir():
        for src in sorted(outputs.iterdir()):
            # Stage 5.2 is the current working run; retain it at the old path.
            if not src.is_file() or src.is_symlink() or src.name.startswith(LATEST_PREFIX):
                continue
            add(src, Path("research_evidence") / bucket(src.name) / "outputs" / src.name)

    for folder in (root, root / "benchmark"):
        for name in VERIFICATION_FILES:
            add(folder / name, Path("research_evidence") / "stage5_1" / "verification" / name)

    for base in (root / "benchmark", root / "tests", root / "tests_before_stage4_2"):
        if base.exists() and base.is_dir():
            for directory in base.rglob("__pycache__"):
                if directory.is_dir() and not directory.is_symlink():
                    cache_dirs.append(directory)
    return moves, sorted(set(cache_dirs), key=lambda p: len(p.parts), reverse=True)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", type=Path, default=Path.cwd(), help="Project directory (default: cwd)")
    ap.add_argument("--apply", action="store_true", help="Perform the described moves; otherwise preview only")
    ap.add_argument("--keep-caches", action="store_true", help="Do not remove regenerable Python caches")
    args = ap.parse_args()
    root = args.root.expanduser().resolve()
    markers = [root / "benchmark" / "run_experiment.py", root / "benchmark" / "sim.py",
               root / "tests", root / "data", root / "research_evidence"]
    missing = [str(p.relative_to(root)) for p in markers if not p.exists()]
    if missing:
        ap.error("Not the expected AIRC project root; missing: " + ", ".join(missing))
    moves, caches = discover(root)
    action = "APPLY" if args.apply else "DRY RUN"
    print(f"{action}: AIRC project at {root}")
    print(f"Planning {len(moves)} safe move(s) and {0 if args.keep_caches else len(caches)} cache removal(s).")
    for src, dest in moves:
        print(f"  MOVE  {src.relative_to(root)} -> {dest.relative_to(root)}")
    if not args.keep_caches:
        for cache in caches:
            # Never remove anything except exact regenerable cache directory names.
            print(f"  CACHE {cache.relative_to(root)}")
    if not args.apply:
        print("\nNothing changed. Rerun with --apply after reviewing this list.")
        return

    moved = []
    for src, dest in moves:
        # Fail rather than overwrite a document that appeared since planning.
        if dest.exists() or dest.is_symlink():
            raise RuntimeError(f"Refusing to overwrite {dest}")
        if src.is_file():
            before_hash = sha256(src)
        else:
            before_hash = None
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src), str(dest))
        after_hash = sha256(dest) if dest.is_file() else None
        if before_hash != after_hash:
            raise RuntimeError(f"Integrity error moving {src} -> {dest}")
        moved.append({"from": str(src.relative_to(root)), "to": str(dest.relative_to(root)),
                      "sha256": after_hash, "type": "directory" if dest.is_dir() else "file"})
    removed_caches = []
    if not args.keep_caches:
        for cache in caches:
            if cache.is_dir() and cache.name == "__pycache__" and not cache.is_symlink():
                shutil.rmtree(cache)
                removed_caches.append(str(cache.relative_to(root)))
    (root / "benchmark" / "outputs").mkdir(parents=True, exist_ok=True)
    manifest_dir = root / "research_evidence" / "maintenance"
    manifest_dir.mkdir(parents=True, exist_ok=True)
    time_key = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    manifest = manifest_dir / f"organization_{time_key}.json"
    n = 2
    while manifest.exists():
        manifest = manifest_dir / f"organization_{time_key}_{n}.json"
        n += 1
    manifest.write_text(json.dumps({
        "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "type": "AIRC_REPOSITORY_HOUSEKEEPING",
        "preserves": ["benchmark Python source", "tests", "datasets", "scenario files", "policies",
                       "stage5_2 active outputs", ".git", ".venv"],
        "moves": moved, "regenerable_caches_removed": removed_caches,
    }, indent=2) + "\n", encoding="utf-8")
    print(f"\nCompleted {len(moved)} verified move(s). Manifest: {manifest.relative_to(root)}")
    print("Run unit tests from the project root to confirm your checkout still works.")


if __name__ == "__main__":
    main()
