"""Cross-platform primitives for the auto-spawning client-daemon pattern.

Provides a canonical, well-known communication point that only one process
can hold, with clients finding and connecting to it.

Main entry points:

- ``dockpoint.claim(app_name, instance="default")`` tries to claim the
  canonical endpoint and returns a ``Dockpoint`` object on success,
  ``None`` on failure. A ``Dockpoint`` owns an OS resource for its
  lifetime, accepts incoming client connections via ``.accept()``,
  and releases the resource when closed.

- ``dockpoint.connect(app_name, instance="default")`` tries to connect to
  an existing endpoint and returns a ``DockpointConnection`` object on
  success, ``None`` on failure. A ``DockpointConnection`` represents one
  connected byte stream and supports ``.read()``, ``.write()``, and
  ``.close()``.

Platform behavior:

- POSIX uses a Unix-domain socket under a canonical runtime directory
  with a sidecar lock file for coordination.
- Windows uses a named pipe scoped to the current user's SID.
"""
from __future__ import unicode_literals
import errno
import os
from typing import FrozenSet, List, Optional, Text, Tuple


DEFAULT_INSTANCE = "default"  # type: Text
DEFAULT_BUFFER_SIZE = 65536  # type: int
_PORTABLE_NAME_CHARS = frozenset(  # type: FrozenSet[Text]
    "-.0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz"
)
_PORTABLE_NAME_DESC = (  # type: Text
    "ASCII letters (A-Z, a-z), digits (0-9), underscore (_), "
    "hyphen (-), and period (.)"
)


class DockpointConnection:
    """Base class for OS-specific connection objects.

    Represents one connected byte stream to a dockpoint.
    """

    def read(self, max_bytes=DEFAULT_BUFFER_SIZE):
        # type: (int) -> bytes
        raise NotImplementedError

    def write(self, data):
        # type: (bytes) -> int
        raise NotImplementedError

    def close(self):
        # type: () -> None
        raise NotImplementedError

    def __enter__(self):
        # type: () -> DockpointConnection
        return self

    def __exit__(self, _exc_type, _exc, _tb):
        # type: (object, object, object) -> None
        self.close()


class Dockpoint:
    """Base class for OS-specific dockpoint objects.

    A concrete instance owns the claimed OS resource, accepts incoming
    client connections, and releases the endpoint when closed.
    """

    def accept(self):
        # type: () -> DockpointConnection
        raise NotImplementedError

    def close(self):
        # type: () -> None
        self.release()

    def release(self):
        # type: () -> None
        raise NotImplementedError

    def __enter__(self):
        # type: () -> Dockpoint
        return self

    def __exit__(self, _exc_type, _exc, _tb):
        # type: (object, object, object) -> None
        self.close()


def validate_path_component(path_component):
    # type: (object) -> bool
    """Return whether a value is a valid portable path component.

    Valid path components are non-empty text values containing only
    ASCII letters, digits, ``_``, ``-``, and ``.``.
    """
    return (
        isinstance(path_component, Text)
        and bool(path_component)
        and all(ch in _PORTABLE_NAME_CHARS for ch in path_component)
    )


# ---------------------------------------------------------------------------
# Windows: named pipes
# ---------------------------------------------------------------------------
if os.name == "nt":
    import ctypes
    from ctypes import wintypes

    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    _GENERIC_READ = 0x80000000
    _GENERIC_WRITE = 0x40000000
    _OPEN_EXISTING = 3
    _PIPE_ACCESS_DUPLEX = 0x00000003
    _FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000
    _PIPE_TYPE_BYTE = 0x00000000
    _PIPE_READMODE_BYTE = 0x00000000
    _PIPE_WAIT = 0x00000000
    _PIPE_UNLIMITED_INSTANCES = 255

    _ERROR_ACCESS_DENIED = 5
    _ERROR_FILE_NOT_FOUND = 2
    _ERROR_BROKEN_PIPE = 109
    _ERROR_INSUFFICIENT_BUFFER = 122
    _ERROR_NO_DATA = 232
    _ERROR_PIPE_BUSY = 231
    _ERROR_PIPE_CONNECTED = 535
    _TOKEN_QUERY = 0x0008
    _TOKEN_USER_CLASS = 1

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

    _CreateNamedPipeW = _kernel32.CreateNamedPipeW
    _CreateNamedPipeW.argtypes = [  # type: List[object]
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
        wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
    ]
    _CreateNamedPipeW.restype = wintypes.HANDLE

    _ConnectNamedPipe = _kernel32.ConnectNamedPipe
    _ConnectNamedPipe.argtypes = [wintypes.HANDLE, wintypes.LPVOID]  # type: List[object]
    _ConnectNamedPipe.restype = wintypes.BOOL

    _CreateFileW = _kernel32.CreateFileW
    _CreateFileW.argtypes = [  # type: List[object]
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    _CreateFileW.restype = wintypes.HANDLE

    _ReadFile = _kernel32.ReadFile
    _ReadFile.argtypes = [  # type: List[object]
        wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID,
    ]
    _ReadFile.restype = wintypes.BOOL

    _WriteFile = _kernel32.WriteFile
    _WriteFile.argtypes = [  # type: List[object]
        wintypes.HANDLE, wintypes.LPCVOID, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID,
    ]
    _WriteFile.restype = wintypes.BOOL

    _DisconnectNamedPipe = _kernel32.DisconnectNamedPipe
    _DisconnectNamedPipe.argtypes = [wintypes.HANDLE]  # type: List[object]
    _DisconnectNamedPipe.restype = wintypes.BOOL

    _CloseHandle = _kernel32.CloseHandle
    _CloseHandle.argtypes = [wintypes.HANDLE]  # type: List[object]
    _CloseHandle.restype = wintypes.BOOL

    _GetCurrentProcess = _kernel32.GetCurrentProcess
    _GetCurrentProcess.restype = wintypes.HANDLE

    _LocalFree = _kernel32.LocalFree
    _LocalFree.argtypes = [wintypes.HLOCAL]  # type: List[object]
    _LocalFree.restype = wintypes.HLOCAL

    _OpenProcessToken = _advapi32.OpenProcessToken
    _OpenProcessToken.argtypes = [  # type: List[object]
        wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE),
    ]
    _OpenProcessToken.restype = wintypes.BOOL

    _GetTokenInformation = _advapi32.GetTokenInformation
    _GetTokenInformation.argtypes = [  # type: List[object]
        wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID,
        wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
    ]
    _GetTokenInformation.restype = wintypes.BOOL

    _ConvertSidToStringSidW = _advapi32.ConvertSidToStringSidW
    _ConvertSidToStringSidW.argtypes = [  # type: List[object]
        wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR),
    ]
    _ConvertSidToStringSidW.restype = wintypes.BOOL

    class _SID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [  # type: List[Tuple[Text, object]]
            ("Sid", wintypes.LPVOID),
            ("Attributes", wintypes.DWORD),
        ]

    class _TOKEN_USER(ctypes.Structure):
        _fields_ = [("User", _SID_AND_ATTRIBUTES)]  # type: List[Tuple[Text, object]]

    class _NamedPipeConnection(DockpointConnection):
        """A connected named-pipe byte stream."""

        __slots__ = ("handle",)

        def __init__(self, handle):
            # type: (Optional[int]) -> None
            self.handle = handle

        def read(self, max_bytes=DEFAULT_BUFFER_SIZE):
            # type: (int) -> bytes
            if self.handle is None:
                raise ValueError("connection is closed")
            buffer = ctypes.create_string_buffer(max_bytes)
            read_count = wintypes.DWORD()
            ok = _ReadFile(
                wintypes.HANDLE(self.handle), buffer, max_bytes,
                ctypes.byref(read_count), None,
            )
            if not ok:
                error = ctypes.get_last_error()
                if error in {_ERROR_BROKEN_PIPE, _ERROR_NO_DATA}:
                    return b""
                raise ctypes.WinError(error)
            return buffer.raw[: read_count.value]

        def write(self, data):
            # type: (bytes) -> int
            if self.handle is None:
                raise ValueError("connection is closed")
            written = wintypes.DWORD()
            ok = _WriteFile(
                wintypes.HANDLE(self.handle), data, len(data),
                ctypes.byref(written), None,
            )
            if not ok:
                raise ctypes.WinError(ctypes.get_last_error())
            return written.value

        def close(self):
            # type: () -> None
            handle = self.handle
            self.handle = None
            if handle is None:
                return
            _CloseHandle(wintypes.HANDLE(handle))

    class _NamedPipeDockpoint(Dockpoint):
        """A claimed Windows named-pipe dockpoint."""

        __slots__ = ("identifier", "_pending_handle", "buffer_size")

        def __init__(self, identifier, handle, buffer_size=DEFAULT_BUFFER_SIZE):
            # type: (Text, Optional[int], int) -> None
            self.identifier = identifier
            self._pending_handle = handle
            self.buffer_size = buffer_size

        def accept(self):
            # type: () -> _NamedPipeConnection
            if self._pending_handle is None:
                self._pending_handle = _create_pipe_instance(
                    self.identifier, self.buffer_size,
                )

            handle = self._pending_handle
            self._pending_handle = None
            ok = _ConnectNamedPipe(wintypes.HANDLE(handle), None)
            if not ok:
                error = ctypes.get_last_error()
                if error != _ERROR_PIPE_CONNECTED:
                    _CloseHandle(wintypes.HANDLE(handle))
                    raise ctypes.WinError(error)

            self._pending_handle = _create_pipe_instance(
                self.identifier, self.buffer_size,
            )
            return _NamedPipeConnection(handle)

        def release(self):
            # type: () -> None
            handle = self._pending_handle
            self._pending_handle = None
            if handle is None:
                return
            _DisconnectNamedPipe(wintypes.HANDLE(handle))
            _CloseHandle(wintypes.HANDLE(handle))

    def _current_windows_user_sid():
        # type: () -> Text
        """Return the current process user's Windows SID string."""
        token = wintypes.HANDLE()
        if not _OpenProcessToken(
            _GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token),
        ):
            raise ctypes.WinError(ctypes.get_last_error())

        try:
            size = wintypes.DWORD()
            _GetTokenInformation(token, _TOKEN_USER_CLASS, None, 0, ctypes.byref(size))
            error = ctypes.get_last_error()
            if error not in (0, _ERROR_INSUFFICIENT_BUFFER):
                raise ctypes.WinError(error)

            buffer = ctypes.create_string_buffer(size.value)
            if not _GetTokenInformation(
                token, _TOKEN_USER_CLASS, buffer, size.value, ctypes.byref(size),
            ):
                raise ctypes.WinError(ctypes.get_last_error())

            token_user = ctypes.cast(buffer, ctypes.POINTER(_TOKEN_USER)).contents
            sid_string = wintypes.LPWSTR()
            if not _ConvertSidToStringSidW(
                token_user.User.Sid, ctypes.byref(sid_string),
            ):
                raise ctypes.WinError(ctypes.get_last_error())

            try:
                return sid_string.value
            finally:
                _LocalFree(ctypes.cast(sid_string, wintypes.HLOCAL))
        finally:
            _CloseHandle(token)

    def _canonical_windows_pipe_name(app_name, instance=DEFAULT_INSTANCE):
        # type: (Text, Text) -> Text
        """Return the canonical named-pipe path on Windows."""
        if not validate_path_component(app_name):
            raise ValueError(
                "Invalid app name. Allowed characters: %s." % _PORTABLE_NAME_DESC
            )

        if not validate_path_component(instance):
            raise ValueError(
                "Invalid instance name. Allowed characters: %s." % _PORTABLE_NAME_DESC
            )

        user_id = _current_windows_user_sid()
        if not validate_path_component(user_id):
            raise ValueError(
                "Invalid Windows user SID. Allowed characters: %s." % _PORTABLE_NAME_DESC
            )

        pipe_name = "%s-%s-%s" % (app_name, user_id, instance)
        return "\\\\.\\pipe\\%s" % pipe_name

    def _create_pipe_instance(identifier, buffer_size):
        # type: (Text, int) -> int
        handle = _CreateNamedPipeW(
            identifier,
            _PIPE_ACCESS_DUPLEX,
            _PIPE_TYPE_BYTE | _PIPE_READMODE_BYTE | _PIPE_WAIT,
            _PIPE_UNLIMITED_INSTANCES,
            buffer_size,
            buffer_size,
            0,
            None,
        )
        if handle == _INVALID_HANDLE_VALUE:
            raise ctypes.WinError(ctypes.get_last_error())
        return int(handle)

    def claim(app_name, instance=DEFAULT_INSTANCE):
        # type: (Text, Text) -> Optional[Dockpoint]
        """Claim the canonical dockpoint on Windows.

        Returns a ``Dockpoint`` when the named pipe is created as the first
        instance. Returns ``None`` when another process already owns it.
        """
        identifier = _canonical_windows_pipe_name(app_name, instance)
        handle = _CreateNamedPipeW(
            identifier,
            _PIPE_ACCESS_DUPLEX | _FILE_FLAG_FIRST_PIPE_INSTANCE,
            _PIPE_TYPE_BYTE | _PIPE_READMODE_BYTE | _PIPE_WAIT,
            _PIPE_UNLIMITED_INSTANCES,
            0, 0, 0, None,
        )
        if handle == _INVALID_HANDLE_VALUE:
            error = ctypes.get_last_error()
            if error == _ERROR_ACCESS_DENIED:
                return None
            raise ctypes.WinError(error)

        return _NamedPipeDockpoint(identifier=identifier, handle=int(handle))

    def connect(app_name, instance=DEFAULT_INSTANCE):
        # type: (Text, Text) -> Optional[DockpointConnection]
        """Connect to an existing Windows dockpoint."""
        identifier = _canonical_windows_pipe_name(app_name, instance)
        handle = _CreateFileW(
            identifier,
            _GENERIC_READ | _GENERIC_WRITE,
            0,
            None,
            _OPEN_EXISTING,
            0,
            None,
        )
        if handle == _INVALID_HANDLE_VALUE:
            error = ctypes.get_last_error()
            if error in {_ERROR_FILE_NOT_FOUND, _ERROR_PIPE_BUSY}:
                return None
            raise ctypes.WinError(error)
        return _NamedPipeConnection(int(handle))

# ---------------------------------------------------------------------------
# POSIX: Unix-domain sockets + sidecar lock file
# ---------------------------------------------------------------------------
else:
    import ctypes
    import socket

    _libc = ctypes.CDLL(None, use_errno=True)
    _getuid = _libc.getuid
    _getuid.argtypes = []  # type: List[object]
    _getuid.restype = ctypes.c_uint
    _chmod = _libc.chmod
    _chmod.argtypes = [ctypes.c_char_p, ctypes.c_uint]  # type: List[object]
    _chmod.restype = ctypes.c_int
    _mkdir = _libc.mkdir
    _mkdir.argtypes = [ctypes.c_char_p, ctypes.c_uint]  # type: List[object]
    _mkdir.restype = ctypes.c_int
    _strerror = _libc.strerror
    _strerror.argtypes = [ctypes.c_int]  # type: List[object]
    _strerror.restype = ctypes.c_char_p
    _unlink = _libc.unlink
    _unlink.argtypes = [ctypes.c_char_p]  # type: List[object]
    _unlink.restype = ctypes.c_int
    _lockf = _libc.lockf
    _lockf.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_long]  # type: List[object]
    _lockf.restype = ctypes.c_int

    _DEFAULT_POSIX_RUNTIME_ROOT = "/tmp"  # type: Text
    _F_ULOCK = 0
    _F_TLOCK = 2

    class _UnixSocketConnection(DockpointConnection):
        """A connected Unix-domain stream socket."""

        __slots__ = ("sock",)

        def __init__(self, sock):
            # type: (socket.socket) -> None
            self.sock = sock

        def read(self, max_bytes=DEFAULT_BUFFER_SIZE):
            # type: (int) -> bytes
            return self.sock.recv(max_bytes)

        def write(self, data):
            # type: (bytes) -> int
            self.sock.sendall(data)
            return len(data)

        def close(self):
            # type: () -> None
            self.sock.close()

    class _UnixSocketDockpoint(Dockpoint):
        """A claimed POSIX Unix-socket dockpoint."""

        __slots__ = ("identifier", "listener", "lock_fd", "lock_path")

        def __init__(self, identifier, listener, lock_fd, lock_path):
            # type: (Text, Optional[socket.socket], Optional[int], Text) -> None
            self.identifier = identifier
            self.listener = listener
            self.lock_fd = lock_fd
            self.lock_path = lock_path

        def accept(self):
            # type: () -> _UnixSocketConnection
            if self.listener is None:
                raise ValueError("dockpoint is closed")
            conn, _addr = self.listener.accept()
            return _UnixSocketConnection(conn)

        def release(self):
            # type: () -> None
            listener = self.listener
            lock_fd = self.lock_fd
            self.listener = None
            self.lock_fd = None
            try:
                if listener is not None:
                    listener.close()
            finally:
                try:
                    _do_unlink(self.identifier)
                finally:
                    if lock_fd is not None:
                        _do_unlock_file(lock_fd)
                        os.close(lock_fd)

    def _strerror_text(error):
        # type: (int) -> Text
        message = _strerror(error)
        if message is None:
            return "errno %s" % error
        return message.decode()

    def _uid():
        # type: () -> int
        return int(_getuid())

    def _do_chmod(path, mode):
        # type: (Text, int) -> None
        ctypes.set_errno(0)
        result = _chmod(path.encode(), mode)
        if result == 0:
            return
        error = ctypes.get_errno()
        raise OSError(error, "chmod failed: %s" % _strerror_text(error))

    def _do_mkdir(path, mode):
        # type: (Text, int) -> None
        ctypes.set_errno(0)
        result = _mkdir(path.encode(), mode)
        if result == 0:
            return
        error = ctypes.get_errno()
        if error == errno.EEXIST and os.path.isdir(path):
            return
        raise OSError(error, "mkdir failed: %s" % _strerror_text(error))

    def _canonical_posix_runtime_dir(app_name, root=_DEFAULT_POSIX_RUNTIME_ROOT):
        # type: (Text, Text) -> Text
        """Return the canonical POSIX runtime directory for the dockpoint."""
        if not validate_path_component(app_name):
            raise ValueError(
                "Invalid app name. Allowed characters: %s." % _PORTABLE_NAME_DESC
            )
        return os.path.join(root, "%s-%s" % (app_name, _uid()))

    def _canonical_socket_path(
        app_name,
        instance=DEFAULT_INSTANCE,
        root=_DEFAULT_POSIX_RUNTIME_ROOT,
    ):
        # type: (Text, Text, Text) -> Text
        """Return the canonical Unix socket path."""
        if not validate_path_component(app_name):
            raise ValueError(
                "Invalid app name. Allowed characters: %s." % _PORTABLE_NAME_DESC
            )

        if not validate_path_component(instance):
            raise ValueError(
                "Invalid instance name. Allowed characters: %s." % _PORTABLE_NAME_DESC
            )

        runtime_dir = _canonical_posix_runtime_dir(app_name, root)
        return os.path.join(runtime_dir, "%s.sock" % instance)

    def _sidecar_lock_path(identifier):
        # type: (Text) -> Text
        base, _ext = os.path.splitext(identifier)
        return "%s.lock" % base

    def _ensure_parent_dir(path):
        # type: (Text) -> None
        parent = os.path.dirname(path)
        if not parent or os.path.isdir(parent):
            return
        grandparent = os.path.dirname(parent)
        if grandparent and grandparent != parent:
            _ensure_parent_dir(parent)
        _do_mkdir(parent, 0o700)

    def claim(app_name, instance=DEFAULT_INSTANCE):
        # type: (Text, Text) -> Optional[Dockpoint]
        """Claim the canonical dockpoint on POSIX.

        Returns a ``Dockpoint`` when the socket path can be bound. Returns
        ``None`` when another process already owns the endpoint.
        """
        identifier = _canonical_socket_path(app_name, instance)
        lock_path = _sidecar_lock_path(identifier)
        _ensure_parent_dir(identifier)

        lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            _do_chmod(lock_path, 0o600)
            try:
                _do_lock_file_nonblocking(lock_fd)
            except OSError as exc:
                if exc.errno in {errno.EACCES, errno.EAGAIN}:
                    os.close(lock_fd)
                    return None
                raise

            # Double-check: someone else might have claimed while we waited.
            probe = connect(app_name, instance)
            if probe is not None:
                probe.close()
                _do_unlock_file(lock_fd)
                os.close(lock_fd)
                return None

            _do_unlink(identifier)

            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                listener.bind(identifier)
                listener.listen()
                _do_chmod(identifier, 0o600)
                return _UnixSocketDockpoint(
                    identifier=identifier,
                    listener=listener,
                    lock_fd=lock_fd,
                    lock_path=lock_path,
                )
            except Exception:
                listener.close()
                raise
        except Exception:
            try:
                _do_unlock_file(lock_fd)
            finally:
                os.close(lock_fd)
            raise

    def connect(app_name, instance=DEFAULT_INSTANCE):
        # type: (Text, Text) -> Optional[DockpointConnection]
        """Connect to an existing POSIX dockpoint."""
        identifier = _canonical_socket_path(app_name, instance)
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            conn.connect(identifier)
        except OSError as exc:
            conn.close()
            if exc.errno in {errno.ENOENT, errno.ECONNREFUSED, errno.ENOTSOCK}:
                return None
            raise
        return _UnixSocketConnection(conn)

    def _do_lock_file_nonblocking(fd):
        # type: (int) -> None
        os.lseek(fd, 0, os.SEEK_SET)
        ctypes.set_errno(0)
        result = _lockf(fd, _F_TLOCK, 0)
        if result == 0:
            return
        error = ctypes.get_errno()
        raise OSError(error, "lockf failed: %s" % _strerror_text(error))

    def _do_unlock_file(fd):
        # type: (int) -> None
        os.lseek(fd, 0, os.SEEK_SET)
        ctypes.set_errno(0)
        result = _lockf(fd, _F_ULOCK, 0)
        if result == 0:
            return
        error = ctypes.get_errno()
        raise OSError(error, "lockf unlock failed: %s" % _strerror_text(error))

    def _do_unlink(path):
        # type: (Text) -> None
        ctypes.set_errno(0)
        result = _unlink(path.encode())
        if result == 0:
            return
        error = ctypes.get_errno()
        if error == errno.ENOENT:
            return
        raise OSError(error, "unlink failed: %s" % _strerror_text(error))
