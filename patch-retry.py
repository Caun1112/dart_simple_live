#!/usr/bin/env python3
"""
patch-retry.py — Patch Claude Code binary to:
  1. Remove the 15-retry cap on CLAUDE_CODE_MAX_RETRIES
  2. Replace exponential backoff with fixed 1s interval
  3. Patch the Anthropic SDK's built-in retry backoff
  4. Lower rate-limit fallback delays

Usage:
  sudo python3 patch-retry.py [--dry-run] [--restore]

Options:
  --dry-run   Show what would be changed without modifying the binary
  --restore   Restore the original binary from backup

Environment variables (after patching):
  CLAUDE_CODE_MAX_RETRIES=10000     — Max retry attempts (no longer capped at 15)
  CLAUDE_CODE_RETRY_INTERVAL_MS=1   — Fixed 1s delay for rate-limit retries

Version-agnostic: This script dynamically discovers minified variable names
by searching for code structure patterns (e.g. "clamped to ${VAR}" near
"CLAUDE_CODE_MAX_RETRIES") rather than hardcoding variable names. This
allows it to work across versions where minification produces different names.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile


def find_binary() -> str:
    """Find the Claude Code binary path."""
    # Try `which claude` first
    try:
        result = subprocess.run(
            ["which", "claude"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            path = os.path.realpath(result.stdout.strip())
            if os.path.isfile(path):
                return path
    except Exception:
        pass

    # Fallback: look in npm global packages
    try:
        result = subprocess.run(
            ["npm", "root", "-g"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            npm_root = result.stdout.strip()
            candidates = [
                os.path.join(npm_root, "@anthropic-ai/claude-code/bin/claude.exe"),
                os.path.join(npm_root, "@anthropic-ai/claude-code-linux-x64/claude"),
                os.path.join(npm_root, "@anthropic-ai/claude-code-linux-arm64/claude"),
                os.path.join(npm_root, "@anthropic-ai/claude-code-darwin-arm64/claude"),
                os.path.join(npm_root, "@anthropic-ai/claude-code-darwin-x64/claude"),
            ]
            for c in candidates:
                if os.path.isfile(c):
                    return os.path.realpath(c)
    except Exception:
        pass

    print("ERROR: Could not find Claude Code binary. Is it installed?", file=sys.stderr)
    print("Try: npm install -g @anthropic-ai/claude-code", file=sys.stderr)
    sys.exit(1)


def find_all(data: bytes, pattern: bytes) -> list[int]:
    """Find all offsets of a byte pattern in data."""
    offsets = []
    start = 0
    while True:
        idx = data.find(pattern, start)
        if idx == -1:
            break
        offsets.append(idx)
        start = idx + 1
    return offsets


def find_nearest(data: bytes, pattern: bytes, ref_offset: int, max_dist: int) -> int | None:
    """Find the offset of pattern closest to ref_offset, within max_dist."""
    offsets = find_all(data, pattern)
    best = None
    best_dist = max_dist
    for off in offsets:
        dist = abs(off - ref_offset)
        if dist < best_dist:
            best_dist = dist
            best = off
    return best


def apply_byte_patch(data: bytearray, desc: str, search: bytes, replace: bytes,
                     stats: dict, hint_offset: int | None = None,
                     max_dist: int = 0) -> bytearray:
    """Apply a single search→replace byte patch. Returns modified data.

    If hint_offset is provided, finds the search pattern nearest to that offset
    within max_dist. Otherwise, uses the first occurrence.
    """
    if len(search) != len(replace):
        print(f"  SKIP: {desc} — byte length mismatch ({len(search)} vs {len(replace)})", file=sys.stderr)
        stats["failed"] += 1
        return data

    if hint_offset is not None:
        offset = find_nearest(data, search, hint_offset, max_dist)
        if offset is None:
            print(f"  WARN: Could not find pattern near hint for: {desc}", file=sys.stderr)
            stats["failed"] += 1
            return data
    else:
        offsets = find_all(data, search)
        if not offsets:
            print(f"  WARN: Could not find pattern for: {desc}", file=sys.stderr)
            stats["failed"] += 1
            return data
        offset = offsets[0]

    # Verify the bytes at the offset match
    actual = data[offset:offset + len(search)]
    if actual != search:
        print(f"  SKIP: {desc} — byte mismatch at offset {offset}", file=sys.stderr)
        print(f"    Expected: {search.hex()}", file=sys.stderr)
        print(f"    Actual:   {actual.hex()}", file=sys.stderr)
        stats["failed"] += 1
        return data

    print(f"  ✓ {desc} @ offset {offset}")
    data[offset:offset + len(replace)] = replace
    stats["applied"] += 1
    return data


def apply_retry_cap_patch(data: bytearray, retry_cap_var: bytes, stats: dict) -> bytearray:
    """把重试次数上限提升到 10000，并保持二进制长度不变。"""
    already_patched = retry_cap_var + b"=1e4"
    if already_patched in data:
        print(f"  SKIP: Retry cap already set to 10000 ({retry_cap_var.decode()})")
        return data

    # 用 1e4 表示 10000，同时把相邻的 3000 改成等价的 3e3，以抵消新增字节。
    pattern = re.compile(
        re.escape(retry_cap_var)
        + rb"=(15|99),([a-zA-Z_$][a-zA-Z0-9_$]*)=3000,"
    )
    match = pattern.search(data)
    if not match:
        print(
            f"  WARN: Could not find retry cap declaration for: {retry_cap_var.decode()}",
            file=sys.stderr,
        )
        stats["failed"] += 1
        return data

    search = match.group(0)
    adjacent_var = match.group(2)
    replace = retry_cap_var + b"=1e4," + adjacent_var + b"=3e3,"
    data = apply_byte_patch(
        data,
        f"Raise retry cap from {match.group(1).decode()} to 10000 ({retry_cap_var.decode()})",
        search,
        replace,
        stats,
    )
    return data


def verify_signature(binary_path: str) -> bool:
    """检查二进制签名是否有效。"""
    if sys.platform != "darwin":
        return True

    result = subprocess.run(
        ["codesign", "--verify", "--verbose=4", binary_path],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def extract_entitlements(source_path: str) -> bytes | None:
    """从已签名的 macOS 二进制里提取 entitlements。"""
    if sys.platform != "darwin":
        return None

    result = subprocess.run(
        ["codesign", "-d", "--entitlements", ":-", source_path],
        capture_output=True,
    )
    if result.returncode != 0:
        return None

    entitlements = result.stdout.strip()
    if not entitlements.startswith(b"<?xml"):
        return None
    return entitlements


def ad_hoc_sign(binary_path: str, entitlement_source: str | None = None) -> None:
    """重新签名修改后的 Mach-O，避免 macOS 启动时直接终止。"""
    if sys.platform != "darwin":
        return

    entitlements = None
    if entitlement_source and os.path.isfile(entitlement_source):
        entitlements = extract_entitlements(entitlement_source)
    if entitlements is None:
        entitlements = extract_entitlements(binary_path)

    cmd = ["codesign", "--force", "--sign", "-"]
    tmp_path = None
    try:
        if entitlements:
            fd, tmp_path = tempfile.mkstemp(suffix=".entitlements.plist")
            with os.fdopen(fd, "wb") as f:
                f.write(entitlements)
            cmd.extend(["--entitlements", tmp_path])
        cmd.append(binary_path)

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()
            raise RuntimeError(detail or "codesign failed")

        if not verify_signature(binary_path):
            raise RuntimeError("codesign verification failed after signing")
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


# ─── Dynamic pattern discovery ────────────────────────────────────────────────
# These functions discover minified variable names by searching for code
# structure patterns that are stable across versions (the logic stays the
# same even as minifier output changes variable names).

def discover_retry_cap_var(data: bytes) -> bytes | None:
    """Discover the retry cap variable name from the 'clamped to' message.

    The code always contains:
        `CLAUDE_CODE_MAX_RETRIES=${e} clamped to ${VARNAME}`
    where VARNAME=15 is the cap we want to raise.
    """
    for m in re.finditer(rb'CLAUDE_CODE_MAX_RETRIES=\$\{', data):
        ctx = data[m.start():m.start() + 200]
        clamped = re.search(rb'clamped to \$\{([a-zA-Z_$][a-zA-Z0-9_$]*)\}', ctx)
        if clamped:
            return clamped.group(1)
    return None


def discover_backoff_base_var(data: bytes) -> bytes | None:
    """Discover the backoff base variable name from the retry delay formula.

    The code always contains:
        Math.min(VARNAME*Math.pow(2,e-1),n)
    where VARNAME=500 is the base delay in ms.
    """
    for m in re.finditer(rb'Math\.min\(([a-zA-Z_$][a-zA-Z0-9_$]*)\*Math\.pow\(2,e-1\)', data):
        return m.group(1)
    return None


def discover_rate_limit_vars(data: bytes) -> tuple[bytes | None, bytes | None, bytes | None]:
    """Discover rate-limit variable names from the rate-limit handling code.

    The code always contains:
        R!==null&&R<THRESHOLD_VAR   — if retry interval < threshold, use it
        Math.max(R??FALLBACK_VAR,MIN_VAR)  — fallback and minimum delays
    near the string "rate_limit".

    Returns (fallback_var, min_var, threshold_var) or Nones.
    """
    fallback_var = None
    min_var = None
    threshold_var = None

    idx = data.find(b'rate_limit')
    while idx != -1:
        before = data[max(0, idx - 500):idx]
        if b'Math.max' in before:
            # Extract Math.max(R??VAR1,VAR2)
            pos = before.rfind(b'Math.max(R??')
            if pos >= 0:
                rest = before[pos + len(b'Math.max(R??'):]
                m = re.match(rb'([a-zA-Z_$][a-zA-Z0-9_$]*),([a-zA-Z_$][a-zA-Z0-9_$]*)\)', rest)
                if m:
                    fallback_var = m.group(1)
                    min_var = m.group(2)

            # Extract R!==null&&R<THRESHOLD
            m2 = re.search(rb'R!==null&&R<([a-zA-Z_$][a-zA-Z0-9_$]*)', before)
            if m2:
                threshold_var = m2.group(1)

            if fallback_var and min_var and threshold_var:
                return fallback_var, min_var, threshold_var

        idx = data.find(b'rate_limit', idx + 1)

    return fallback_var, min_var, threshold_var


def main():
    parser = argparse.ArgumentParser(
        description="Patch Claude Code binary: remove retry cap, fix backoff to 1s interval"
    )
    parser.add_argument("--dry-run", action="store_true", help="Show changes without modifying the binary")
    parser.add_argument("--restore", action="store_true", help="Restore the original binary from backup")
    args = parser.parse_args()

    binary_path = find_binary()
    print(f"Found binary: {binary_path}")
    print(f"Binary size: {os.path.getsize(binary_path)} bytes")

    backup_path = binary_path + ".orig"

    # ── Restore mode ──────────────────────────────────────────────────────────
    if args.restore:
        if not os.path.isfile(backup_path):
            print(f"ERROR: No backup found at {backup_path}", file=sys.stderr)
            sys.exit(1)
        print(f"Restoring original binary from {backup_path} ...")
        try:
            shutil.copy2(backup_path, binary_path)
            os.chmod(binary_path, 0o755)
            if sys.platform == "darwin" and not verify_signature(binary_path):
                print("正在为恢复后的二进制重新签名 ...")
                ad_hoc_sign(binary_path, backup_path)
            print("Restored successfully.")
        except OSError as e:
            print(f"ERROR: Failed to restore: {e}", file=sys.stderr)
            print("Is claude running? Stop it first.", file=sys.stderr)
            sys.exit(1)
        except RuntimeError as e:
            print(f"ERROR: 恢复后的二进制签名失败: {e}", file=sys.stderr)
            sys.exit(1)
        return

    # ── Create backup ─────────────────────────────────────────────────────────
    if not os.path.isfile(backup_path):
        print(f"Creating backup at {backup_path} ...")
        try:
            shutil.copy2(binary_path, backup_path)
        except OSError as e:
            print(f"ERROR: Failed to create backup: {e}", file=sys.stderr)
            print("Is claude running? Stop it first.", file=sys.stderr)
            sys.exit(1)

    # ── Read binary ───────────────────────────────────────────────────────────
    with open(binary_path, "rb") as f:
        data = bytearray(f.read())

    # ── Discover minified variable names dynamically ──────────────────────────
    print()
    print("=== Discovering version-specific patterns ===")

    retry_cap_var = discover_retry_cap_var(data)
    if retry_cap_var:
        print(f"  Retry cap variable: {retry_cap_var.decode()}")
    else:
        print("  WARN: Could not discover retry cap variable", file=sys.stderr)

    backoff_base_var = discover_backoff_base_var(data)
    if backoff_base_var:
        print(f"  Backoff base variable: {backoff_base_var.decode()}")
    else:
        print("  WARN: Could not discover backoff base variable", file=sys.stderr)

    rl_fallback_var, rl_min_var, rl_threshold_var = discover_rate_limit_vars(data)
    if rl_fallback_var:
        print(f"  Rate-limit fallback variable: {rl_fallback_var.decode()}")
    if rl_min_var:
        print(f"  Rate-limit minimum variable: {rl_min_var.decode()}")
    if rl_threshold_var:
        print(f"  Rate-limit threshold variable: {rl_threshold_var.decode()}")
    if not rl_fallback_var or not rl_min_var or not rl_threshold_var:
        print("  WARN: Could not discover all rate-limit variables", file=sys.stderr)

    # ── Save hint offset for Math.pow patch before backoff base is overwritten ──
    backoff_base_hint_offset = None
    if backoff_base_var:
        search = backoff_base_var + b"=500"
        hits = find_all(data, search)
        if hits:
            backoff_base_hint_offset = hits[0]
            print(f"  Saved backoff base hint offset: {backoff_base_hint_offset}")

    # ── Apply patches ─────────────────────────────────────────────────────────
    stats = {"applied": 0, "failed": 0}

    # ── Patch 1: Remove 15-retry cap ──────────────────────────────────────────
    print()
    print("=== Patch 1: Remove 15-retry cap ===")
    if retry_cap_var:
        data = apply_retry_cap_patch(data, retry_cap_var, stats)
    else:
        print("  SKIP: Retry cap variable not discovered", file=sys.stderr)
        stats["failed"] += 1

    # ── Patch 2a: Change backoff base from 500ms to 1000ms ────────────────────
    print()
    print("=== Patch 2: Replace exponential backoff with fixed 1s interval ===")
    if backoff_base_var:
        search = backoff_base_var + b"=500"
        replace = backoff_base_var + b"=1e3"
        data = apply_byte_patch(data, f"Change backoff base from 500ms to 1000ms ({backoff_base_var.decode()})", search, replace, stats)
    else:
        print("  SKIP: Backoff base variable not discovered", file=sys.stderr)
        stats["failed"] += 1

    # ── Patch 2b: Disable exponential growth ──────────────────────────────────
    # Math.pow(2,e-1) → Math.pow(1,e-1)  (pow(1,n) always = 1)
    # Use the saved hint offset from the backoff base variable to find the
    # correct occurrence (there may be multiple Math.pow(2,e-1) in the binary)
    if backoff_base_hint_offset is not None:
        data = apply_byte_patch(
            data,
            "Change pow base 2→1 (disables exponential growth)",
            b"Math.pow(2,e-1)",
            b"Math.pow(1,e-1)",
            stats,
            hint_offset=backoff_base_hint_offset,
            max_dist=100000,
        )
    else:
        print("  SKIP: Backoff base hint not available", file=sys.stderr)
        stats["failed"] += 1

    # ── Patch 3: Patch Anthropic SDK built-in retry backoff ───────────────────
    # 0.5*Math.pow(2,o) → 1.0*Math.pow(1,o)
    # This is in the SDK code, not minified app code, so the pattern is stable
    print()
    print("=== Patch 3: Patch Anthropic SDK built-in retry backoff ===")
    data = apply_byte_patch(
        data,
        "Change SDK backoff from 0.5*2^o to 1.0*1^o (fixed ~1s delay)",
        b"0.5*Math.pow(2,o)",
        b"1.0*Math.pow(1,o)",
        stats,
    )

    # ── Patch 4: Lower rate-limit fallback delays ─────────────────────────────
    print()
    print("=== Patch 4: Lower rate-limit fallback delays ===")
    if rl_fallback_var:
        # Fallback: 1800000ms (30min) → 0010000ms (10s)
        search = rl_fallback_var + b"=1800000"
        replace = rl_fallback_var + b"=0010000"
        data = apply_byte_patch(data, f"Lower rate-limit fallback from 30min to 10s ({rl_fallback_var.decode()})", search, replace, stats)
    else:
        print("  SKIP: Rate-limit fallback variable not discovered", file=sys.stderr)
        stats["failed"] += 1

    if rl_min_var:
        # Minimum: 600000ms (10min) → 001000ms (1s)
        search = rl_min_var + b"=600000"
        replace = rl_min_var + b"=001000"
        data = apply_byte_patch(data, f"Lower rate-limit minimum from 10min to 1s ({rl_min_var.decode()})", search, replace, stats)
    else:
        print("  SKIP: Rate-limit minimum variable not discovered", file=sys.stderr)
        stats["failed"] += 1

    if rl_threshold_var:
        # Threshold: 20000ms (20s) → 99999ms (100s)
        search = rl_threshold_var + b"=20000"
        replace = rl_threshold_var + b"=99999"
        data = apply_byte_patch(data, f"Raise rate-limit env-var threshold from 20s to 100s ({rl_threshold_var.decode()})", search, replace, stats)
    else:
        print("  SKIP: Rate-limit threshold variable not discovered", file=sys.stderr)
        stats["failed"] += 1

    # ── Summary ───────────────────────────────────────────────────────────────
    print()
    print("═══════════════════════════════════════════════════════════")
    print(f"  Patches applied: {stats['applied']}")
    print(f"  Patches skipped: {stats['failed']}")
    print("═══════════════════════════════════════════════════════════")

    if args.dry_run:
        print()
        print("DRY RUN — no changes were made.")
        print("Run without --dry-run to apply patches.")
        return

    # ── Write patched binary ──────────────────────────────────────────────────
    # Use a temp file + os.rename() to avoid "Text file busy" (ETXTBSY) when
    # the binary is currently running. On Linux, rename() is atomic and
    # replaces the inode — the running process keeps its old mapping, while
    # new invocations use the patched binary.
    if stats["applied"] > 0:
        binary_dir = os.path.dirname(binary_path)
        try:
            fd, tmp_path = tempfile.mkstemp(dir=binary_dir, suffix=".tmp")
            try:
                os.write(fd, data)
                os.close(fd)
                os.chmod(tmp_path, 0o755)
                os.rename(tmp_path, binary_path)
            except Exception:
                os.close(fd) if not getattr(fd, 'closed', True) else None
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise
            if sys.platform == "darwin":
                print("正在为修改后的二进制重新签名 ...")
                ad_hoc_sign(binary_path, backup_path)
            print()
            print("Patches applied successfully!")
            print("(Running claude sessions still use the old binary; new sessions will use the patched one.)")
        except OSError as e:
            print(f"\nERROR: Failed to write patched binary: {e}", file=sys.stderr)
            print("Is claude running? Stop it first, then re-run this script.", file=sys.stderr)
            sys.exit(1)
        except RuntimeError as e:
            print(f"\nERROR: 修改后的二进制签名失败: {e}", file=sys.stderr)
            sys.exit(1)
    elif sys.platform == "darwin" and not args.dry_run and not verify_signature(binary_path):
        try:
            print()
            print("没有应用新的补丁，但当前二进制签名无效。")
            print("正在为现有二进制重新签名 ...")
            ad_hoc_sign(binary_path, backup_path)
            print("重新签名成功。")
        except RuntimeError as e:
            print(f"\nERROR: 二进制签名失败: {e}", file=sys.stderr)
            sys.exit(1)

    print()
    print("To restore the original binary:")
    print(f"  sudo python3 {sys.argv[0]} --restore")
    print()
    print("Set these environment variables before running claude:")
    print("  export CLAUDE_CODE_MAX_RETRIES=10000      # Max retry attempts (no longer capped at 15)")
    print("  export CLAUDE_CODE_RETRY_INTERVAL_MS=1    # 1s delay for rate-limit retries")
    print()
    print("Retry behavior after patching:")
    print("  ┌─────────────────────────┬──────────────────────────────────┐")
    print("  │ Setting                 │ Behavior                         │")
    print("  ├─────────────────────────┼──────────────────────────────────┤")
    print("  │ Max retries             │ CLAUDE_CODE_MAX_RETRIES (≤10000) │")
    print("  │ General retry delay     │ Fixed ~1 second                  │")
    print("  │ Rate-limit retry delay  │ Fixed ~1 second                  │")
    print("  │ SDK-level retry delay   │ Fixed ~0.75-1 second             │")
    print("  └─────────────────────────┴──────────────────────────────────┘")
    print()
    print("NOTE: After updating Claude Code (npm update), re-run this script.")


if __name__ == "__main__":
    main()
