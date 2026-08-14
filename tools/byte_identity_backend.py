#!/usr/bin/env python3
"""Platform execution primitives for the byte-identity framework.

The manifest/composer/verifier live in :mod:`byte_identity`.  This module is
the deliberately small operating-system boundary: advisory build locks,
owned compiler process trees, and the native-Windows logical-drive mapping.
It imports on every supported host so backend-neutral policy tests can run on
both GitHub Linux/macOS and Windows runners.
"""

from __future__ import annotations

from dataclasses import dataclass
from contextlib import contextmanager
import hashlib
import ntpath
import os
from pathlib import Path
import subprocess
import stat
import sys
import uuid


POSIX_WINE_BACKEND = "posix_wine_virtual_z_v1"
WINDOWS_NATIVE_BACKEND = "windows_native_z_v1"
SUPPORTED_BACKENDS = {POSIX_WINE_BACKEND, WINDOWS_NATIVE_BACKEND}


class BackendError(RuntimeError):
    """A platform authority/process primitive failed closed."""


class BackendLockBusy(BackendError):
    """A nonblocking byte-identity lock is owned by another process."""


def host_backend() -> str:
    return WINDOWS_NATIVE_BACKEND if os.name == "nt" else POSIX_WINE_BACKEND


def selected_backend(identifier: str | None = None) -> str:
    """Return the explicit backend and reject cross-host impersonation.

    The environment override is intentionally an attestation knob, not an
    emulation switch.  Tests may inspect either capability record, but a real
    compiler launch may select only the backend implemented by its host.
    """
    selected = identifier or os.environ.get(
        "ISLE_BYTE_IDENTITY_BACKEND", host_backend()
    )
    if selected not in SUPPORTED_BACKENDS:
        raise BackendError(f"unsupported byte-identity backend: {selected}")
    if selected != host_backend():
        raise BackendError(
            f"byte-identity backend {selected} cannot run on host {os.name}"
        )
    return selected


@dataclass(frozen=True)
class BackendCapabilities:
    identifier: str
    logical_drive_snapshot: bool
    wine_prefix: bool
    process_tree_primitive: str
    filesystem_authority: str


@dataclass(frozen=True)
class WindowsEntryMetadata:
    """Portable subset of ``stat_result`` backed by a Win32 handle/name."""

    st_mode: int
    st_dev: int
    st_ino: int
    st_size: int
    st_mtime_ns: int
    st_nlink: int
    attributes: int


def capabilities(identifier: str | None = None) -> BackendCapabilities:
    identifier = identifier or host_backend()
    if identifier == POSIX_WINE_BACKEND:
        return BackendCapabilities(
            identifier=identifier,
            logical_drive_snapshot=True,
            wine_prefix=True,
            process_tree_primitive="posix_process_group",
            filesystem_authority="root_fd_openat_nofollow",
        )
    if identifier == WINDOWS_NATIVE_BACKEND:
        return BackendCapabilities(
            identifier=identifier,
            logical_drive_snapshot=True,
            wine_prefix=False,
            process_tree_primitive="windows_kill_on_close_job_object",
            filesystem_authority="held_nofollow_handle_chain",
        )
    raise BackendError(f"unsupported byte-identity backend: {identifier}")


if os.name == "nt":
    import ctypes
    from ctypes import wintypes
    import msvcrt

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)

    INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value
    ERROR_LOCK_VIOLATION = 33
    ERROR_IO_PENDING = 997
    LOCKFILE_FAIL_IMMEDIATELY = 0x00000001
    LOCKFILE_EXCLUSIVE_LOCK = 0x00000002
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
    JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS = 9
    JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION_CLASS = 1
    CREATE_SUSPENDED = 0x00000004
    CREATE_NEW_PROCESS_GROUP = 0x00000200
    DDD_RAW_TARGET_PATH = 0x00000001
    DDD_REMOVE_DEFINITION = 0x00000002
    DDD_EXACT_MATCH_ON_REMOVE = 0x00000004
    DDD_NO_BROADCAST_SYSTEM = 0x00000008
    FILE_LIST_DIRECTORY = 0x00000001
    FILE_READ_ATTRIBUTES = 0x00000080
    FILE_WRITE_ATTRIBUTES = 0x00000100
    SYNCHRONIZE = 0x00100000
    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    CREATE_NEW = 1
    CREATE_ALWAYS = 2
    OPEN_EXISTING = 3
    OPEN_ALWAYS = 4
    FILE_ATTRIBUTE_READONLY = 0x00000001
    FILE_ATTRIBUTE_DIRECTORY = 0x00000010
    FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
    FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000
    MOVEFILE_REPLACE_EXISTING = 0x00000001
    MOVEFILE_WRITE_THROUGH = 0x00000008
    INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    WAIT_OBJECT_0 = 0x00000000
    WAIT_ABANDONED = 0x00000080
    WAIT_TIMEOUT = 0x00000102
    INFINITE = 0xFFFFFFFF
    ERROR_INVALID_PARAMETER = 87
    ERROR_ACCESS_DENIED = 5
    MUTEX_ALL_ACCESS = 0x001F0001

    class OVERLAPPED(ctypes.Structure):
        _fields_ = [
            ("Internal", ctypes.c_size_t),
            ("InternalHigh", ctypes.c_size_t),
            ("Offset", wintypes.DWORD),
            ("OffsetHigh", wintypes.DWORD),
            ("hEvent", wintypes.HANDLE),
        ]

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
            ("IoInfo", IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    class JOBOBJECT_BASIC_ACCOUNTING_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("TotalUserTime", ctypes.c_longlong),
            ("TotalKernelTime", ctypes.c_longlong),
            ("ThisPeriodTotalUserTime", ctypes.c_longlong),
            ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
            ("TotalPageFaultCount", wintypes.DWORD),
            ("TotalProcesses", wintypes.DWORD),
            ("ActiveProcesses", wintypes.DWORD),
            ("TotalTerminatedProcesses", wintypes.DWORD),
        ]

    class BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", wintypes.FILETIME),
            ("ftLastAccessTime", wintypes.FILETIME),
            ("ftLastWriteTime", wintypes.FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        ]

    kernel32.LockFileEx.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
        wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(OVERLAPPED),
    ]
    kernel32.LockFileEx.restype = wintypes.BOOL
    kernel32.UnlockFileEx.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
        wintypes.DWORD, ctypes.POINTER(OVERLAPPED),
    ]
    kernel32.UnlockFileEx.restype = wintypes.BOOL
    kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
    ]
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateJobObject.restype = wintypes.BOOL
    kernel32.QueryInformationJobObject.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
        wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.QueryInformationJobObject.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.DefineDosDeviceW.argtypes = [
        wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR,
    ]
    kernel32.DefineDosDeviceW.restype = wintypes.BOOL
    kernel32.QueryDosDeviceW.argtypes = [
        wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD,
    ]
    kernel32.QueryDosDeviceW.restype = wintypes.DWORD
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.GetFileInformationByHandle.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(BY_HANDLE_FILE_INFORMATION),
    ]
    kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
    kernel32.GetFinalPathNameByHandleW.argtypes = [
        wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD,
    ]
    kernel32.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    kernel32.ReadFile.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p,
    ]
    kernel32.ReadFile.restype = wintypes.BOOL
    kernel32.WriteFile.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p,
    ]
    kernel32.WriteFile.restype = wintypes.BOOL
    kernel32.FlushFileBuffers.argtypes = [wintypes.HANDLE]
    kernel32.FlushFileBuffers.restype = wintypes.BOOL
    kernel32.MoveFileExW.argtypes = [
        wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
    ]
    kernel32.MoveFileExW.restype = wintypes.BOOL
    kernel32.DeleteFileW.argtypes = [wintypes.LPCWSTR]
    kernel32.DeleteFileW.restype = wintypes.BOOL
    kernel32.GetFileAttributesW.argtypes = [wintypes.LPCWSTR]
    kernel32.GetFileAttributesW.restype = wintypes.DWORD
    kernel32.CreateDirectoryW.argtypes = [wintypes.LPCWSTR, ctypes.c_void_p]
    kernel32.CreateDirectoryW.restype = wintypes.BOOL
    kernel32.RemoveDirectoryW.argtypes = [wintypes.LPCWSTR]
    kernel32.RemoveDirectoryW.restype = wintypes.BOOL
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
    kernel32.CreateMutexW.restype = wintypes.HANDLE
    kernel32.ReleaseMutex.argtypes = [wintypes.HANDLE]
    kernel32.ReleaseMutex.restype = wintypes.BOOL
    ntdll.NtResumeProcess.argtypes = [wintypes.HANDLE]
    ntdll.NtResumeProcess.restype = ctypes.c_long


def _win32_error(context: str) -> BackendError:
    if os.name != "nt":
        return BackendError(f"{context}: Win32 APIs are unavailable")
    return BackendError(
        f"{context} failed with Win32 error {ctypes.get_last_error()}"
    )


def _close_windows_handle(handle) -> None:
    if os.name == "nt" and handle not in (None, 0, INVALID_HANDLE_VALUE):
        if not kernel32.CloseHandle(handle):
            raise _win32_error("CloseHandle")


def process_is_alive(pid: int) -> bool:
    """Check one process without sending it a signal on either backend."""
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        raise BackendError("process identity must be a positive integer")
    if os.name != "nt":
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True
    handle = kernel32.OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, False, pid
    )
    if not handle:
        error = ctypes.get_last_error()
        if error == ERROR_INVALID_PARAMETER:
            return False
        if error == ERROR_ACCESS_DENIED:
            return True
        raise BackendError(f"OpenProcess failed with Win32 error {error}")
    try:
        status = int(kernel32.WaitForSingleObject(handle, 0))
        if status == WAIT_TIMEOUT:
            return True
        if status == WAIT_OBJECT_0:
            return False
        raise BackendError(
            f"WaitForSingleObject(process) returned unexpected status 0x{status:08x}"
        )
    finally:
        _close_windows_handle(handle)


class WindowsNamedMutex:
    """Bounded cross-process lock for the session-global logical Z: seat."""

    def __init__(self, name: str):
        if os.name != "nt":
            raise BackendError("Windows named mutexes require Windows")
        if not isinstance(name, str) or not name or "\0" in name:
            raise BackendError("Windows mutex name is unsafe")
        self.handle = kernel32.CreateMutexW(None, False, name)
        if not self.handle:
            raise _win32_error("CreateMutexW")
        self.owned = False

    def acquire(self, timeout_seconds: float) -> None:
        if not isinstance(timeout_seconds, (int, float)) or timeout_seconds <= 0:
            raise BackendError("Windows mutex timeout is invalid")
        milliseconds = min(int(timeout_seconds * 1000), INFINITE - 1)
        status = int(kernel32.WaitForSingleObject(self.handle, milliseconds))
        if status in (WAIT_OBJECT_0, WAIT_ABANDONED):
            self.owned = True
            return
        if status == WAIT_TIMEOUT:
            raise BackendLockBusy("Windows logical-drive mutex wait timed out")
        raise BackendError(
            f"WaitForSingleObject(mutex) returned unexpected status 0x{status:08x}"
        )

    def release(self) -> None:
        if self.owned:
            if not kernel32.ReleaseMutex(self.handle):
                raise _win32_error("ReleaseMutex")
            self.owned = False

    def close(self) -> None:
        error = None
        try:
            self.release()
        except BackendError as current:
            error = current
        if self.handle:
            try:
                _close_windows_handle(self.handle)
            except BackendError as current:
                error = error or current
            self.handle = None
        if error is not None:
            raise error


def _windows_handle_information(handle) -> tuple[int, int, int, int, int]:
    """Return attributes, volume, file-id, size, and link count."""
    if os.name != "nt":
        raise BackendError("Windows handle metadata is unavailable on this host")
    info = BY_HANDLE_FILE_INFORMATION()
    if not kernel32.GetFileInformationByHandle(handle, ctypes.byref(info)):
        raise _win32_error("GetFileInformationByHandle")
    return (
        int(info.dwFileAttributes),
        int(info.dwVolumeSerialNumber),
        (int(info.nFileIndexHigh) << 32) | int(info.nFileIndexLow),
        (int(info.nFileSizeHigh) << 32) | int(info.nFileSizeLow),
        int(info.nNumberOfLinks),
    )


def _windows_final_path(handle) -> str:
    if os.name != "nt":
        raise BackendError("Windows final paths are unavailable on this host")
    size = 32768
    buffer = ctypes.create_unicode_buffer(size)
    length = int(kernel32.GetFinalPathNameByHandleW(handle, buffer, size, 0))
    if length == 0 or length >= size:
        raise _win32_error("GetFinalPathNameByHandleW")
    value = buffer.value
    if value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\"):
        value = value[4:]
    return ntpath.normcase(ntpath.normpath(value))


def _open_windows_path(
    path: str, *, directory: bool, access: int, disposition: int = None,
    share: int | None = None,
):
    if os.name != "nt":
        raise BackendError("Windows namespace handles are unavailable on this host")
    disposition = OPEN_EXISTING if disposition is None else disposition
    flags = FILE_FLAG_OPEN_REPARSE_POINT
    if directory:
        flags |= FILE_FLAG_BACKUP_SEMANTICS
    else:
        flags |= FILE_FLAG_SEQUENTIAL_SCAN
    handle = kernel32.CreateFileW(
        path,
        access,
        (FILE_SHARE_READ | FILE_SHARE_WRITE) if share is None else share,
        None,
        disposition,
        flags,
        None,
    )
    if handle == INVALID_HANDLE_VALUE:
        raise _win32_error(f"CreateFileW({path})")
    try:
        attributes, *_ = _windows_handle_information(handle)
        if attributes & FILE_ATTRIBUTE_REPARSE_POINT:
            raise BackendError(f"Windows namespace entry is a reparse point: {path}")
        if bool(attributes & FILE_ATTRIBUTE_DIRECTORY) != directory:
            raise BackendError(
                f"Windows namespace entry has the wrong type: {path}"
            )
        return handle
    except BaseException:
        _close_windows_handle(handle)
        raise


class WindowsHeldDirectoryChain:
    """No-reparse, no-share-delete handle chain for one absolute directory.

    Windows has no public ``openat`` equivalent.  Holding every component from
    the volume root without ``FILE_SHARE_DELETE`` prevents rename/removal of
    any admitted ancestor while a pathname operation is in flight.  Each
    component is opened with ``FILE_FLAG_OPEN_REPARSE_POINT`` and is rejected
    if it is a junction, symlink, mount reparse, or other reparse point.
    """

    def __init__(self, path: Path | str):
        if os.name != "nt":
            raise BackendError("held Windows directory chains require Windows")
        raw = ntpath.abspath(os.fspath(path))
        drive, tail = ntpath.splitdrive(raw)
        if not drive or not tail.startswith(("\\", "/")):
            raise BackendError(f"Windows authority path is not absolute: {path}")
        self.path = ntpath.normpath(raw)
        self.handles = []
        self.records = []
        current = drive + "\\"
        components = [part for part in tail.replace("/", "\\").split("\\") if part]
        try:
            for part in [None, *components]:
                if part is not None:
                    if part in (".", "..") or "\0" in part:
                        raise BackendError("unsafe Windows authority path component")
                    current = ntpath.join(current, part)
                handle = _open_windows_path(
                    current,
                    directory=True,
                    access=FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                )
                information = _windows_handle_information(handle)
                final_path = _windows_final_path(handle)
                self.handles.append(handle)
                self.records.append((ntpath.normpath(current), information, final_path))
            if ntpath.normcase(self.path) != ntpath.normcase(self.records[-1][0]):
                raise BackendError("Windows authority path normalization changed")
            self.revalidate()
        except BaseException:
            self.close()
            raise

    @property
    def identity(self) -> tuple[int, int]:
        information = self.records[-1][1]
        return information[1], information[2]

    def revalidate(self) -> None:
        for named, expected, final_path in self.records:
            handle = _open_windows_path(
                named,
                directory=True,
                access=FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            )
            try:
                current = _windows_handle_information(handle)
                if current[1:3] != expected[1:3]:
                    raise BackendError(
                        f"Windows directory identity changed: {named}"
                    )
                if _windows_final_path(handle) != final_path:
                    raise BackendError(
                        f"Windows directory final path changed: {named}"
                    )
            finally:
                _close_windows_handle(handle)

    def close(self) -> None:
        error = None
        for handle in reversed(self.handles):
            try:
                _close_windows_handle(handle)
            except BackendError as current:
                error = error or current
        self.handles.clear()
        self.records.clear()
        if error is not None:
            raise error


class WindowsHeldFile:
    """A no-reparse regular file held without delete sharing until close."""

    def __init__(self, path: Path | str, *, maximum: int = 1 << 30):
        if os.name != "nt":
            raise BackendError("held Windows files require Windows")
        self.path = ntpath.normpath(ntpath.abspath(os.fspath(path)))
        self.parent = WindowsHeldDirectoryChain(ntpath.dirname(self.path))
        self.handle = None
        try:
            self.handle = _open_windows_path(
                self.path,
                directory=False,
                access=GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                share=FILE_SHARE_READ,
            )
            information = _windows_handle_information(self.handle)
            if information[3] > maximum:
                raise BackendError(f"held Windows file is not bounded: {self.path}")
            self.identity = information
            self.final_path = _windows_final_path(self.handle)
            self.data = WindowsNamespaceAuthority._read_handle(
                self.handle, maximum
            )
            self.revalidate()
        except BaseException:
            self.close()
            raise

    def read_bytes(self, *, maximum: int = 1 << 30) -> bytes:
        if self.handle is None:
            raise BackendError("held Windows file is closed")
        if len(self.data) > maximum:
            raise BackendError(f"held Windows file is not bounded: {self.path}")
        self.revalidate()
        return self.data

    def revalidate(self) -> None:
        if self.handle is None:
            raise BackendError("held Windows file is closed")
        self.parent.revalidate()
        if _windows_handle_information(self.handle) != self.identity:
            raise BackendError(f"held Windows file changed: {self.path}")
        current = _open_windows_path(
            self.path,
            directory=False,
            access=GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        )
        try:
            if (
                _windows_handle_information(current)[1:3]
                != self.identity[1:3]
                or _windows_final_path(current) != self.final_path
            ):
                raise BackendError(f"held Windows file was replaced: {self.path}")
        finally:
            _close_windows_handle(current)

    def close(self) -> None:
        error = None
        if self.handle is not None:
            try:
                _close_windows_handle(self.handle)
            except BackendError as current:
                error = current
            self.handle = None
        self.data = b""
        try:
            self.parent.close()
        except BackendError as current:
            error = error or current
        if error is not None:
            raise error


class WindowsNamespaceAuthority:
    """Minimal held-handle Windows authority for build-state primitives.

    This class is intentionally independent of the manifest/composer.  The
    platform-neutral framework may use it for locks, snapshots, audits and
    compiler outputs while retaining one policy implementation above it.
    """

    def __init__(self, root: Path | str):
        if os.name != "nt":
            raise BackendError("Windows namespace authority requires Windows")
        self.root = ntpath.normpath(ntpath.abspath(os.fspath(root)))
        self.root_chain = WindowsHeldDirectoryChain(self.root)
        self.retained_chains = []

    def close(self) -> None:
        error = None
        for chain in reversed(self.retained_chains):
            try:
                chain.close()
            except BackendError as current:
                error = error or current
        self.retained_chains.clear()
        try:
            self.root_chain.close()
        except BackendError as current:
            error = error or current
        if error is not None:
            raise error

    def _path(self, path: Path | str, *, allow_root: bool = False) -> str:
        value = ntpath.normpath(ntpath.abspath(os.fspath(path)))
        try:
            common = ntpath.commonpath([ntpath.normcase(self.root), ntpath.normcase(value)])
        except ValueError as error:
            raise BackendError(f"Windows path escapes build authority: {path}") from error
        if (common != ntpath.normcase(self.root)
                or (not allow_root and ntpath.normcase(value)
                    == ntpath.normcase(self.root))):
            raise BackendError(f"Windows path escapes or names authority root: {path}")
        return value

    def revalidate(self) -> None:
        self.root_chain.revalidate()

    def relative_parts(
        self, path: Path | str, *, allow_root: bool = False
    ) -> tuple[str, ...]:
        value = self._path(path, allow_root=allow_root)
        relative = ntpath.relpath(value, self.root)
        if relative == ".":
            return ()
        parts = tuple(relative.replace("/", "\\").split("\\"))
        if any(
            not part or part in (".", "..") or "\0" in part
            for part in parts
        ):
            raise BackendError(f"unsafe Windows authority path: {path}")
        return parts

    @contextmanager
    def hold_parent(self, path: Path | str):
        value = self._path(path)
        chain = WindowsHeldDirectoryChain(ntpath.dirname(value))
        try:
            self.root_chain.revalidate()
            yield value, chain
            chain.revalidate()
            self.root_chain.revalidate()
        finally:
            chain.close()

    @staticmethod
    def _metadata(path: str) -> WindowsEntryMetadata | None:
        attributes = int(kernel32.GetFileAttributesW(path))
        if attributes == INVALID_FILE_ATTRIBUTES:
            error = ctypes.get_last_error()
            if error in (2, 3):
                return None
            raise BackendError(
                f"GetFileAttributesW failed with Win32 error {error}: {path}"
            )
        try:
            named = os.lstat(path)
        except OSError as error:
            raise BackendError(f"cannot lstat Windows authority entry: {path}") from error
        if attributes & FILE_ATTRIBUTE_REPARSE_POINT:
            kind = stat.S_IFLNK
        elif attributes & FILE_ATTRIBUTE_DIRECTORY:
            kind = stat.S_IFDIR
        else:
            kind = stat.S_IFREG
        return WindowsEntryMetadata(
            st_mode=kind | stat.S_IMODE(named.st_mode),
            st_dev=int(named.st_dev),
            st_ino=int(named.st_ino),
            st_size=int(named.st_size),
            st_mtime_ns=int(named.st_mtime_ns),
            st_nlink=int(named.st_nlink),
            attributes=attributes,
        )

    def lstat(self, path: Path | str) -> WindowsEntryMetadata | None:
        with self.hold_parent(path) as (value, _chain):
            return self._metadata(value)

    def list_entries(
        self, path: Path | str
    ) -> tuple[tuple[str, WindowsEntryMetadata], ...]:
        value = self._path(path, allow_root=True)
        chain = WindowsHeldDirectoryChain(value)
        try:
            self.root_chain.revalidate()
            names_before = sorted(os.listdir(value), key=str.casefold)
            if len({name.casefold() for name in names_before}) != len(names_before):
                raise BackendError(
                    f"case-insensitive Windows namespace collision: {value}"
                )
            entries = []
            for name in names_before:
                if not name or name in (".", "..") or "\0" in name:
                    raise BackendError(f"unsafe Windows namespace entry: {value}")
                metadata = self._metadata(ntpath.join(value, name))
                if metadata is None:
                    raise BackendError(
                        f"Windows namespace changed while enumerated: {value}"
                    )
                entries.append((name, metadata))
            if sorted(os.listdir(value), key=str.casefold) != names_before:
                raise BackendError(
                    f"Windows namespace changed while enumerated: {value}"
                )
            chain.revalidate()
            self.root_chain.revalidate()
            return tuple(entries)
        finally:
            chain.close()

    def mkdirs(self, path: Path | str) -> None:
        value = self._path(path, allow_root=True)
        if ntpath.normcase(value) == ntpath.normcase(self.root):
            self.root_chain.revalidate()
            return
        parts = self.relative_parts(value)
        current = self.root
        holds = []
        try:
            for part in parts:
                parent = WindowsHeldDirectoryChain(current)
                holds.append(parent)
                candidate = ntpath.join(current, part)
                metadata = self._metadata(candidate)
                if metadata is None:
                    if not kernel32.CreateDirectoryW(candidate, None):
                        raise _win32_error(f"CreateDirectoryW({candidate})")
                elif not stat.S_ISDIR(metadata.st_mode):
                    raise BackendError(
                        f"Windows build directory component has wrong type: {candidate}"
                    )
                current = candidate
            final = WindowsHeldDirectoryChain(value)
            try:
                final.revalidate()
                self.root_chain.revalidate()
            finally:
                final.close()
        finally:
            for chain in reversed(holds):
                chain.close()

    def mkdir_exclusive(self, path: Path | str) -> None:
        value = self._path(path)
        self.mkdirs(ntpath.dirname(value))
        with self.hold_parent(value):
            if self._metadata(value) is not None:
                raise BackendError(f"private Windows directory already exists: {value}")
            if not kernel32.CreateDirectoryW(value, None):
                raise _win32_error(f"CreateDirectoryW({value})")
            chain = WindowsHeldDirectoryChain(value)
            chain.close()
        self.root_chain.revalidate()

    def chmod(self, path: Path | str, mode: int) -> None:
        value = self._path(path, allow_root=True)
        metadata = self._metadata(value)
        if metadata is None:
            raise BackendError(f"cannot chmod absent Windows authority entry: {value}")
        if stat.S_ISLNK(metadata.st_mode):
            raise BackendError(
                f"refusing to chmod a Windows reparse-point entry: {value}"
            )
        chain = (
            WindowsHeldDirectoryChain(value)
            if stat.S_ISDIR(metadata.st_mode) else None
        )
        try:
            parent = None if chain is not None else WindowsHeldDirectoryChain(
                ntpath.dirname(value)
            )
            try:
                os.chmod(value, mode)
            finally:
                if parent is not None:
                    parent.close()
        except OSError as error:
            raise BackendError(f"cannot chmod Windows authority entry: {value}") from error
        finally:
            if chain is not None:
                chain.close()
        self.root_chain.revalidate()

    @staticmethod
    def _read_handle(handle, maximum: int) -> bytes:
        information = _windows_handle_information(handle)
        size = information[3]
        if size < 0 or size > maximum:
            raise BackendError("Windows authority file is not bounded")
        chunks = []
        remaining = size
        while remaining:
            length = min(remaining, 1024 * 1024)
            buffer = ctypes.create_string_buffer(length)
            read = wintypes.DWORD()
            if not kernel32.ReadFile(
                handle, buffer, length, ctypes.byref(read), None
            ):
                raise _win32_error("ReadFile")
            if int(read.value) <= 0:
                raise BackendError("Windows authority file changed while read")
            chunks.append(buffer.raw[: int(read.value)])
            remaining -= int(read.value)
        data = b"".join(chunks)
        if _windows_handle_information(handle) != information:
            raise BackendError("Windows authority file changed while read")
        return data

    def read_bytes(self, path: Path | str, *, maximum: int = 1 << 30) -> bytes:
        with self.hold_parent(path) as (value, _chain):
            handle = _open_windows_path(
                value, directory=False, access=GENERIC_READ | FILE_READ_ATTRIBUTES
            )
            try:
                before = _windows_handle_information(handle)
                data = self._read_handle(handle, maximum)
                current = _open_windows_path(
                    value, directory=False,
                    access=GENERIC_READ | FILE_READ_ATTRIBUTES,
                )
                try:
                    if _windows_handle_information(current)[1:3] != before[1:3]:
                        raise BackendError("Windows authority file was replaced")
                finally:
                    _close_windows_handle(current)
                return data
            finally:
                _close_windows_handle(handle)

    def atomic_write(self, path: Path | str, data: bytes) -> str:
        if not isinstance(data, bytes):
            raise BackendError("Windows atomic output must be bytes")
        with self.hold_parent(path) as (value, _chain):
            attributes = kernel32.GetFileAttributesW(value)
            if (attributes != INVALID_FILE_ATTRIBUTES
                    and attributes & FILE_ATTRIBUTE_REPARSE_POINT):
                raise BackendError(
                    f"Windows atomic target is a reparse point: {value}"
                )
            temporary = ntpath.join(
                ntpath.dirname(value),
                f".{ntpath.basename(value)}.byte-identity-{os.getpid()}-{uuid.uuid4().hex}.tmp",
            )
            handle = _open_windows_path(
                temporary, directory=False,
                access=GENERIC_READ | GENERIC_WRITE | FILE_READ_ATTRIBUTES,
                disposition=CREATE_NEW,
            )
            try:
                offset = 0
                while offset < len(data):
                    chunk = data[offset : offset + 1024 * 1024]
                    buffer = ctypes.create_string_buffer(chunk)
                    written = wintypes.DWORD()
                    if not kernel32.WriteFile(
                        handle, buffer, len(chunk), ctypes.byref(written), None
                    ):
                        raise _win32_error("WriteFile")
                    if int(written.value) != len(chunk):
                        raise BackendError("Windows atomic output write was short")
                    offset += len(chunk)
                if not kernel32.FlushFileBuffers(handle):
                    raise _win32_error("FlushFileBuffers")
            except BaseException:
                _close_windows_handle(handle)
                handle = None
                kernel32.DeleteFileW(temporary)
                raise
            finally:
                if handle is not None:
                    _close_windows_handle(handle)
            if not kernel32.MoveFileExW(
                temporary,
                value,
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            ):
                error = _win32_error("MoveFileExW")
                kernel32.DeleteFileW(temporary)
                raise error
            installed = self.read_bytes(value, maximum=max(len(data), 1))
            if installed != data:
                raise BackendError("Windows atomic output reconstruction differs")
            return hashlib.sha256(data).hexdigest()

    def unlink(self, path: Path | str, *, missing_ok: bool = True) -> bool:
        with self.hold_parent(path) as (value, _chain):
            attributes = kernel32.GetFileAttributesW(value)
            if attributes == INVALID_FILE_ATTRIBUTES:
                if missing_ok:
                    return False
                raise _win32_error("GetFileAttributesW")
            if attributes & FILE_ATTRIBUTE_DIRECTORY:
                if not attributes & FILE_ATTRIBUTE_REPARSE_POINT:
                    raise BackendError(
                        f"refusing to unlink a real directory as a file: {value}"
                    )
                if not kernel32.RemoveDirectoryW(value):
                    raise _win32_error("RemoveDirectoryW(reparse point)")
            elif not kernel32.DeleteFileW(value):
                raise _win32_error("DeleteFileW")
            if kernel32.GetFileAttributesW(value) != INVALID_FILE_ATTRIBUTES:
                raise BackendError(f"Windows output remained visible: {value}")
            return True

    def remove_tree(self, path: Path | str, *, missing_ok: bool = True) -> bool:
        value = self._path(path)
        metadata = self._metadata(value)
        if metadata is None:
            if missing_ok:
                return False
            raise BackendError(f"Windows tree is absent: {value}")
        if stat.S_ISLNK(metadata.st_mode):
            return self.unlink(value, missing_ok=missing_ok)
        if not stat.S_ISDIR(metadata.st_mode):
            return self.unlink(value, missing_ok=missing_ok)
        chain = WindowsHeldDirectoryChain(value)
        try:
            entries = self.list_entries(value)
            for name, child in entries:
                child_path = ntpath.join(value, name)
                if stat.S_ISDIR(child.st_mode):
                    self.remove_tree(child_path, missing_ok=False)
                else:
                    self.unlink(child_path, missing_ok=False)
            chain.revalidate()
        finally:
            chain.close()
        with self.hold_parent(value):
            if not kernel32.RemoveDirectoryW(value):
                raise _win32_error(f"RemoveDirectoryW({value})")
        return True

    def open_lock(self, path: Path | str):
        value = self._path(path)
        self.mkdirs(ntpath.dirname(value))
        chain = WindowsHeldDirectoryChain(ntpath.dirname(value))
        handle = None
        try:
            handle = _open_windows_path(
                value,
                directory=False,
                access=GENERIC_READ | GENERIC_WRITE | FILE_READ_ATTRIBUTES,
                disposition=OPEN_ALWAYS,
            )
            flags = os.O_RDWR | getattr(os, "O_BINARY", 0)
            descriptor = msvcrt.open_osfhandle(int(handle), flags)
            handle = None  # fd owns it now
            stream = os.fdopen(descriptor, "r+b", buffering=0)
            self.retained_chains.append(chain)
            chain = None
            return stream
        except BaseException:
            if handle is not None:
                _close_windows_handle(handle)
            raise
        finally:
            if chain is not None:
                chain.close()


class PlatformFileLock:
    """One-byte shared/exclusive lock with identical nonblocking semantics."""

    def __init__(self, stream):
        self.stream = stream
        self.locked = False

    def acquire(self, *, exclusive: bool, nonblocking: bool) -> None:
        if os.name != "nt":
            import fcntl

            operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
            if nonblocking:
                operation |= fcntl.LOCK_NB
            try:
                fcntl.flock(self.stream.fileno(), operation)
            except BlockingIOError as error:
                raise BackendLockBusy("byte-identity lock is busy") from error
            self.locked = True
            return

        flags = LOCKFILE_EXCLUSIVE_LOCK if exclusive else 0
        if nonblocking:
            flags |= LOCKFILE_FAIL_IMMEDIATELY
        overlapped = OVERLAPPED()
        handle = wintypes.HANDLE(msvcrt.get_osfhandle(self.stream.fileno()))
        if not kernel32.LockFileEx(
            handle, flags, 0, 1, 0, ctypes.byref(overlapped)
        ):
            error = ctypes.get_last_error()
            if error in (ERROR_LOCK_VIOLATION, ERROR_IO_PENDING):
                raise BackendLockBusy("byte-identity lock is busy")
            raise BackendError(f"LockFileEx failed with Win32 error {error}")
        self.locked = True

    def release(self) -> None:
        if not self.locked:
            return
        if os.name != "nt":
            import fcntl

            fcntl.flock(self.stream.fileno(), fcntl.LOCK_UN)
        else:
            overlapped = OVERLAPPED()
            handle = wintypes.HANDLE(msvcrt.get_osfhandle(self.stream.fileno()))
            if not kernel32.UnlockFileEx(
                handle, 0, 1, 0, ctypes.byref(overlapped)
            ):
                raise BackendError(
                    f"UnlockFileEx failed with Win32 error {ctypes.get_last_error()}"
                )
        self.locked = False


class WindowsJob:
    """Kill-on-close Job Object assigned before a suspended child is resumed."""

    def __init__(self):
        if os.name != "nt":
            raise BackendError("Windows Job Objects are unavailable on this host")
        self.handle = kernel32.CreateJobObjectW(None, None)
        if not self.handle:
            raise BackendError(
                f"CreateJobObjectW failed with Win32 error {ctypes.get_last_error()}"
            )
        limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not kernel32.SetInformationJobObject(
            self.handle,
            JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
            ctypes.byref(limits),
            ctypes.sizeof(limits),
        ):
            error = ctypes.get_last_error()
            self.close()
            raise BackendError(
                f"SetInformationJobObject failed with Win32 error {error}"
            )

    @staticmethod
    def creationflags() -> int:
        return CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP

    def assign_and_resume(self, process: subprocess.Popen) -> None:
        process_handle = wintypes.HANDLE(int(process._handle))  # noqa: SLF001
        if not kernel32.AssignProcessToJobObject(self.handle, process_handle):
            error = ctypes.get_last_error()
            # The child is still suspended and is not yet owned by this job.
            # Terminating the job cannot reach it, so terminate/reap the
            # direct child explicitly before reporting the failed authority
            # transfer.  This is the only pre-assignment failure window.
            try:
                process.terminate()
                process.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                pass
            raise BackendError(
                f"AssignProcessToJobObject failed with Win32 error {error}"
            )
        status = int(ntdll.NtResumeProcess(process_handle))
        if status < 0:
            self.terminate(0xEF)
            raise BackendError(f"NtResumeProcess failed with NTSTATUS 0x{status & 0xffffffff:08x}")

    def active_processes(self) -> int:
        accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION()
        returned = wintypes.DWORD()
        if not kernel32.QueryInformationJobObject(
            self.handle,
            JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION_CLASS,
            ctypes.byref(accounting),
            ctypes.sizeof(accounting),
            ctypes.byref(returned),
        ):
            raise BackendError(
                f"QueryInformationJobObject failed with Win32 error {ctypes.get_last_error()}"
            )
        return int(accounting.ActiveProcesses)

    def terminate(self, exit_code: int = 1) -> None:
        if self.handle and not kernel32.TerminateJobObject(self.handle, exit_code):
            raise BackendError(
                f"TerminateJobObject failed with Win32 error {ctypes.get_last_error()}"
            )

    def close(self) -> None:
        if self.handle:
            _close_windows_handle(self.handle)
            self.handle = None


class WindowsDriveMapping:
    """Exact session-scoped DOS drive mapping used by the native backend.

    A DOS-device letter is shared by processes in the logon session.  Keep a
    named mutex for the complete mapping lifetime and keep a no-reparse,
    no-share-delete handle chain on the target for the same interval.  This
    prevents cooperating builds from aliasing the logical seat and prevents
    the admitted target or any ancestor from being renamed after validation.
    """

    def __init__(self, letter: str, target: Path):
        if os.name != "nt":
            raise BackendError("native DOS-device mappings require Windows")
        letter = letter.upper().rstrip(":")
        if len(letter) != 1 or not ("A" <= letter <= "Z"):
            raise BackendError(f"invalid DOS drive letter: {letter}")
        self.device = f"{letter}:"
        self.target = ntpath.normpath(ntpath.abspath(os.fspath(target)))
        self.target_chain = WindowsHeldDirectoryChain(self.target)
        self.raw_target = "\\??\\" + self.target
        self.mutex = WindowsNamedMutex(
            rf"Local\ISLEByteIdentityLogicalDrive{letter}"
        )
        self.locked = False
        self.mapped = False

    def _query(self) -> str | None:
        buffer = ctypes.create_unicode_buffer(32768)
        length = kernel32.QueryDosDeviceW(self.device, buffer, len(buffer))
        if length == 0:
            error = ctypes.get_last_error()
            if error == 2:
                return None
            raise BackendError(f"QueryDosDeviceW failed with Win32 error {error}")
        return buffer.value

    def map(self, *, wait_seconds: float = 30.0) -> None:
        if self.mapped or self.locked:
            raise BackendError(f"DOS drive {self.device} mapping is already active")
        try:
            self.mutex.acquire(wait_seconds)
            self.locked = True
            self.target_chain.revalidate()
            if self._query() is not None:
                raise BackendError(f"DOS drive {self.device} is already mapped")
            flags = DDD_RAW_TARGET_PATH | DDD_NO_BROADCAST_SYSTEM
            if not kernel32.DefineDosDeviceW(flags, self.device, self.raw_target):
                raise BackendError(
                    f"DefineDosDeviceW failed with Win32 error {ctypes.get_last_error()}"
                )
            self.mapped = True
            self.target_chain.revalidate()
            if self._query() != self.raw_target:
                raise BackendError(
                    "DOS-device mapping did not resolve to its exact target"
                )
        except BaseException:
            try:
                if self.mapped:
                    self.unmap()
                else:
                    self._release_authority()
            except BackendError:
                pass
            raise

    def unmap(self) -> None:
        error = None
        try:
            if self.mapped:
                try:
                    self.target_chain.revalidate()
                except BackendError as current:
                    error = current
                current_target = self._query()
                if current_target != self.raw_target:
                    error = error or BackendError(
                        f"DOS drive {self.device} no longer names its admitted target"
                    )
                else:
                    flags = (
                        DDD_REMOVE_DEFINITION
                        | DDD_EXACT_MATCH_ON_REMOVE
                        | DDD_RAW_TARGET_PATH
                        | DDD_NO_BROADCAST_SYSTEM
                    )
                    if not kernel32.DefineDosDeviceW(
                        flags, self.device, self.raw_target
                    ):
                        error = error or BackendError(
                            "DefineDosDeviceW removal failed with Win32 error "
                            f"{ctypes.get_last_error()}"
                        )
                    elif self._query() is not None:
                        error = error or BackendError(
                            f"DOS drive {self.device} remained mapped after cleanup"
                        )
                    else:
                        self.mapped = False
        except BackendError as current:
            error = error or current
        finally:
            try:
                self._release_authority()
            except BackendError as current:
                error = error or current
        if error is not None:
            raise error

    def _release_authority(self) -> None:
        error = None
        if self.locked:
            try:
                self.mutex.release()
            except BackendError as current:
                error = current
            self.locked = False
        try:
            self.mutex.close()
        except BackendError as current:
            error = error or current
        try:
            self.target_chain.close()
        except BackendError as current:
            error = error or current
        if error is not None:
            raise error

    def close(self) -> None:
        if self.mapped or self.locked:
            self.unmap()
            return
        self._release_authority()

    def __enter__(self):
        self.map()
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.close()


def windows_creationflags() -> int:
    return WindowsJob.creationflags() if os.name == "nt" else 0


def quote_windows_command(command: list[str]) -> str:
    """Expose Python's exact CreateProcess quoting for audit/unit coverage."""
    if not command or any(not isinstance(item, str) or "\0" in item for item in command):
        raise BackendError("Windows child argv is empty or unsafe")
    return subprocess.list2cmdline(command)


__all__ = [
    "BackendCapabilities", "BackendError", "BackendLockBusy",
    "PlatformFileLock", "POSIX_WINE_BACKEND", "SUPPORTED_BACKENDS",
    "WINDOWS_NATIVE_BACKEND", "WindowsDriveMapping", "WindowsEntryMetadata",
    "WindowsNamedMutex", "WindowsHeldDirectoryChain", "WindowsHeldFile",
    "WindowsJob", "WindowsNamespaceAuthority",
    "capabilities", "host_backend", "process_is_alive",
    "quote_windows_command", "selected_backend", "windows_creationflags",
]
