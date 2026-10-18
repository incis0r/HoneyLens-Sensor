"""
ebpf_check.py — eBPF Capability & Dependency Checker
======================================================
Validates that the host can run eBPF programs before the sensor starts.
Checks: kernel version, BPF syscall, CAP_BPF / root, debugfs, BCC install.

Requires: Python >= 3.9 (Rocky Linux 9 default)

Usage:
    from honeylens.ebpf.ebpf_check import preflight_check
    preflight_check()   # raises SystemExit on fatal issues
"""

from __future__ import annotations

import logging
import os
import platform
import struct
import sys

logger = logging.getLogger("ebpf_check")

# Minimum kernel version for the BPF features we need (socket filter, perf output)
MIN_KERNEL = (4, 15)


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------


def _parse_kernel_version() -> tuple[int, ...]:
    """Return (major, minor, patch) from uname."""
    release = platform.release()  # e.g. "5.15.0-91-generic"
    parts = release.split("-")[0].split(".")
    return tuple(int(p) for p in parts[:3])


def check_kernel_version() -> bool:
    ver = _parse_kernel_version()
    ok = ver[:2] >= MIN_KERNEL
    if ok:
        logger.info("Kernel %s — OK (minimum %s.%s)", platform.release(), *MIN_KERNEL)
    else:
        logger.error(
            "Kernel %s is too old.  eBPF socket filters require >= %s.%s",
            platform.release(),
            *MIN_KERNEL,
        )
    return ok


def check_root_or_cap_bpf() -> bool:
    """We need either root (euid 0) or CAP_BPF + CAP_NET_RAW."""
    if os.geteuid() == 0:
        logger.info("Running as root — OK")
        return True

    # Try to read effective capabilities from /proc
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("CapEff:"):
                    cap_hex = int(line.split(":")[1].strip(), 16)
                    CAP_NET_RAW = 1 << 13
                    CAP_BPF = 1 << 39  # since Linux 5.8
                    if (cap_hex & CAP_NET_RAW) and (cap_hex & CAP_BPF):
                        logger.info("CAP_BPF + CAP_NET_RAW detected — OK")
                        return True
    except Exception as exc:
        logger.debug("capability check via /proc failed: %s", exc)

    logger.error(
        "Not running as root and CAP_BPF/CAP_NET_RAW not detected. "
        "Run with sudo or grant capabilities: "
        "sudo setcap cap_bpf,cap_net_raw+ep %s",
        sys.executable,
    )
    return False


def check_bpf_syscall() -> bool:
    """Attempt a harmless BPF syscall (BPF_PROG_GET_FD_BY_ID with id=0)."""
    try:
        import ctypes

        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        SYS_BPF = 321 if struct.calcsize("P") == 8 else 357  # x86_64 / i386
        # cmd=13 (BPF_PROG_GET_FD_BY_ID), attr=null-ish, size=4
        attr = ctypes.create_string_buffer(128)
        ret = libc.syscall(SYS_BPF, 13, ctypes.byref(attr), 128)
        # We expect EINVAL or ENOENT — that's fine, it means the syscall exists
        errno_val = ctypes.get_errno()
        if ret < 0 and errno_val in (1, 2, 22):  # EPERM, ENOENT, EINVAL
            logger.info("BPF syscall reachable — OK")
            return True
        if ret >= 0:
            logger.info("BPF syscall reachable — OK")
            os.close(ret)
            return True
        logger.warning("BPF syscall returned unexpected errno %d", errno_val)
        return True  # optimistic
    except Exception as exc:
        logger.warning("Could not probe BPF syscall: %s (continuing anyway)", exc)
        return True  # non-fatal; BCC will fail later with a clear message


def check_debugfs() -> bool:
    """BCC's perf output needs debugfs / tracefs mounted."""
    paths = ["/sys/kernel/debug/tracing", "/sys/kernel/tracing"]
    for p in paths:
        if os.path.isdir(p):
            logger.info("Tracing filesystem found at %s — OK", p)
            return True
    logger.warning(
        "Neither /sys/kernel/debug/tracing nor /sys/kernel/tracing found. "
        "Try: sudo mount -t debugfs none /sys/kernel/debug"
    )
    return False


def check_bcc_installed() -> bool:
    """Verify the BCC Python bindings are importable."""
    try:
        from bcc import BPF  # noqa: F401

        logger.info("BCC Python bindings available — OK")
        return True
    except ImportError:
        logger.error(
            "BCC Python bindings not found.  Install: "
            "apt install bpfcc-tools python3-bpfcc  (Debian/Ubuntu) or "
            "dnf install python3-bcc  (Fedora/RHEL)"
        )
        return False


def check_kernel_headers() -> bool:
    """Verify kernel headers/devel are installed and match the running kernel."""
    release = platform.release()

    # Check for the kconfig.h include that BCC needs
    kconfig_path = f"/usr/src/kernels/{release}/include/linux/kconfig.h"
    # Also check /lib/modules path (Debian/Ubuntu layout)
    modules_build = f"/lib/modules/{release}/build/include/linux/kconfig.h"

    if os.path.isfile(kconfig_path) or os.path.isfile(modules_build):
        logger.info("Kernel headers match running kernel %s — OK", release)
        return True

    # Headers missing — check what IS installed
    installed = []
    kernels_dir = "/usr/src/kernels"
    if os.path.isdir(kernels_dir):
        installed = os.listdir(kernels_dir)

    if installed:
        logger.error(
            "Kernel headers MISMATCH — running %s but headers installed for: %s",
            release,
            ", ".join(sorted(installed)),
        )
        logger.error(
            "  This usually means the kernel was updated but the system was not rebooted,\n"
            "  or kernel-devel was not installed for the running kernel.\n"
            "  Fix options:\n"
            "    Option A (recommended): reboot into the new kernel, then verify:\n"
            "      reboot\n"
            "      uname -r\n"
            "      ls /usr/src/kernels/$(uname -r)/include/linux/kconfig.h\n"
            "\n"
            "    Option B (install headers for current kernel):\n"
            "      dnf install -y kernel-devel-%s kernel-headers-%s\n"
            "      (may fail if old kernel packages were removed from repos)",
            release,
            release,
        )
    else:
        logger.error(
            "Kernel headers NOT FOUND for running kernel %s.\n"
            "  Install:\n"
            "    dnf install -y kernel-devel-$(uname -r) kernel-headers-$(uname -r)\n"
            "  If that fails (package not available), update and reboot:\n"
            "    dnf update -y kernel kernel-devel kernel-headers\n"
            "    reboot",
            release,
        )

    return False


def check_source_files(*paths: str) -> bool:
    """Verify that required eBPF C source files exist."""
    ok = True
    for p in paths:
        if os.path.isfile(p):
            logger.info("eBPF source %s — found", p)
        else:
            logger.error("eBPF source %s — MISSING", p)
            ok = False
    return ok


# ---------------------------------------------------------------------------
# Aggregate preflight
# ---------------------------------------------------------------------------


def preflight_check(
    source_files: list[str] | None = None,
    exit_on_fail: bool = True,
) -> bool:
    """
    Run all eBPF readiness checks.  Returns True if everything passed.
    If *exit_on_fail* is True, calls sys.exit(1) on any fatal failure.
    """
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    print("=" * 60)
    print("  eBPF Preflight Check")
    print("=" * 60)

    results = {
        "kernel_version": check_kernel_version(),
        "root_or_cap_bpf": check_root_or_cap_bpf(),
        "bpf_syscall": check_bpf_syscall(),
        "debugfs": check_debugfs(),
        "bcc_installed": check_bcc_installed(),
        "kernel_headers": check_kernel_headers(),
    }

    if source_files:
        results["source_files"] = check_source_files(*source_files)

    fatal_keys = {"kernel_version", "root_or_cap_bpf", "bcc_installed", "kernel_headers"}
    fatal_fail = any(not results[k] for k in fatal_keys if k in results)
    warn_fail = any(not v for k, v in results.items() if k not in fatal_keys)

    print()
    if fatal_fail:
        print("[FAIL] One or more fatal checks did not pass — eBPF sensor cannot start.")
        if exit_on_fail:
            sys.exit(1)
        return False
    elif warn_fail:
        print("[WARN] Non-fatal issues detected — sensor may work but review warnings above.")
    else:
        print("[PASS] All eBPF preflight checks passed.")

    return True


if __name__ == "__main__":
    preflight_check()
