#!/usr/bin/env python3
"""Sequential fresh-process trials; preserve newly created disk fixtures/results."""
import argparse
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
from datetime import datetime, timezone


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--parent", type=Path, required=True)
    parser.add_argument("--sizes", type=int, nargs="+", default=[10000, 100000, 250000])
    parser.add_argument("--trials", type=int, default=3)
    parser.add_argument("--samples", type=int, default=1000)
    parser.add_argument("--payload", type=int, default=256)
    parser.add_argument("--batch", type=int, default=1000)
    parser.add_argument("--api", choices=["public", "loaded"], default="public")
    parser.add_argument("--existing", type=Path, help="reuse preserved fixtures; appends extend them")
    parser.add_argument("--skip-append", action="store_true", help="verification/startup only; no appended records")
    args = parser.parse_args()
    if not args.parent.is_dir() or min(args.sizes + [args.trials, args.samples, args.batch]) < 1:
        parser.error("existing parent and positive sizes/trials/samples/batch required")
    # Explicit supplied disk-backed parent; mkdtemp makes a new preserved child.
    root = args.existing or Path(tempfile.mkdtemp(prefix="nostoi-large-chain-", dir=args.parent))
    with (root / f"results-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')}.jsonl").open("x") as output:
        def emit(record):
            line = json.dumps(record, sort_keys=True)
            print(line, flush=True)
            output.write(line + "\n")
            output.flush()

        emit({"mode": "context", "root": str(root), "utc": datetime.now(timezone.utc).isoformat(),
              "uname": platform.uname()._asdict(), "cpu": subprocess.check_output(["lscpu"], text=True),
              "filesystem": subprocess.check_output(["df", "-T", str(root)], text=True),
              "rustc": subprocess.check_output(["rustc", "--version"], text=True).strip(),
              "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
              "binary": str(args.binary.resolve()), "arguments": {k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()},
              "cache_policy": "before verify/startup/append, sequentially read both fixture files in 1 MiB chunks; OS pages warm-requested, no cache drop; SQLite process cache fresh"})

        def run(mode, target, trial=None, backend="sqlite", count=None):
            if mode != "seed":
                for name in ["chain.jsonl", "chain.sqlite"]:
                    with (target / name).open("rb") as source:
                        while source.read(1024 * 1024):
                            pass
            command = [str(args.binary.resolve()), mode, "--target", str(target),
                       "--backend", backend, "--api", args.api, "--count", str(count or args.samples),
                       "--payload", str(args.payload), "--batch", str(args.batch)]
            # wait4 supplies per-child ru_maxrss (not the cumulative RUSAGE_CHILDREN
            # maximum). Temporary streams avoid pipe deadlocks on error diagnostics.
            with tempfile.TemporaryFile(mode="w+t") as stdout, tempfile.TemporaryFile(mode="w+t") as stderr:
                child = subprocess.Popen(command, text=True, stdout=stdout, stderr=stderr)
                _, status, usage = os.wait4(child.pid, 0)
                child.returncode = os.waitstatus_to_exitcode(status)
                stdout.seek(0)
                stderr.seek(0)
                if child.returncode:
                    raise RuntimeError(f"{command}: exit {child.returncode}: {stderr.read()}")
                result = json.loads(stdout.read())
            # Linux wait4 may retain the pre-exec Python fork RSS floor. Use
            # the executable's own post-exec /proc VmHWM for the reported peak.
            result["child_rusage_peak_rss_kib"] = usage.ru_maxrss
            result.update(trial=trial, command=command, rss_source="Linux /proc/self/status VmHWM (KiB)")
            emit(result)

        for size in args.sizes:
            target = root / str(size)
            if not args.existing:
                run("seed", target, count=size)
            # All verification/startup trials precede appends, so use exact base sizes.
            for trial in range(1, args.trials + 1):
                for backend in ["jsonl", "sqlite"]:
                    run("verify", target, trial, backend)
                run("startup", target, trial)
            if not args.skip_append:
                for trial in range(1, args.trials + 1):
                    run("append", target, trial)
                # Confirm both the original JSONL and extended SQLite remain valid.
                for backend in ["jsonl", "sqlite"]:
                    run("verify", target, "post-append", backend)


if __name__ == "__main__":
    main()
