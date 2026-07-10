"""Secure endpoint descriptor persistence."""

from __future__ import annotations

import os
import stat
import uuid
from pathlib import Path

from diagnose.ipc.errors import ProtocolError, ProtocolErrorCode
from diagnose.ipc.protocol import EndpointDescriptor


def endpoint_permissions_are_private(path: Path) -> bool:
    """Return whether an endpoint is restricted to the current OS user."""

    path = path.expanduser().resolve()
    try:
        if os.name != "nt":
            return stat.S_IMODE(path.stat().st_mode) & 0o077 == 0

        import win32api
        import win32con
        import win32security

        process_token = win32security.OpenProcessToken(
            win32api.GetCurrentProcess(),
            win32con.TOKEN_QUERY,
        )
        try:
            current_sid = win32security.GetTokenInformation(
                process_token,
                win32security.TokenUser,
            )[0]
        finally:
            process_token.Close()
        security = win32security.GetNamedSecurityInfo(
            str(path),
            win32security.SE_FILE_OBJECT,
            win32security.DACL_SECURITY_INFORMATION,
        )
        dacl = security.GetSecurityDescriptorDacl()
        control, _revision = security.GetSecurityDescriptorControl()
        return bool(
            dacl is not None
            and dacl.GetAceCount() == 1
            and dacl.GetAce(0)[2] == current_sid
            and control & win32security.SE_DACL_PROTECTED
        )
    except Exception:
        return False


def write_endpoint_descriptor(path: Path, descriptor: EndpointDescriptor) -> None:
    """Atomically write a user-private endpoint descriptor.

    Windows ACL setup is fail-closed: a descriptor that could not be restricted
    is removed and the server startup must fail.
    """

    path = path.expanduser().resolve()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name != "nt":
        os.chmod(path.parent, 0o700)

    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    replaced = False
    try:
        descriptor_bytes = descriptor.to_wire_bytes()
        descriptor_fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor_fd, "wb") as file_handle:
                file_handle.write(descriptor_bytes)
                file_handle.flush()
                os.fsync(file_handle.fileno())
        except BaseException:
            # fdopen owns and closes descriptor_fd.
            raise

        os.chmod(temporary, 0o600)
        if os.name == "nt":
            _restrict_windows_acl(temporary)
        os.replace(temporary, path)
        replaced = True
        if os.name == "nt":
            _restrict_windows_acl(path)
        else:
            os.chmod(path, 0o600)
    except BaseException:
        temporary.unlink(missing_ok=True)
        if replaced:
            path.unlink(missing_ok=True)
        raise


def read_endpoint_descriptor(path: Path) -> EndpointDescriptor:
    path = path.expanduser().resolve()
    try:
        if os.name != "nt":
            mode = stat.S_IMODE(path.stat().st_mode)
            if mode & 0o077:
                raise ProtocolError(
                    ProtocolErrorCode.PERMISSION_DENIED,
                    "Endpoint descriptor permissions are not user-private.",
                )
        return EndpointDescriptor.from_wire_bytes(path.read_bytes())
    except ProtocolError:
        raise
    except (OSError, ValueError) as exc:
        raise ProtocolError(
            ProtocolErrorCode.ENDPOINT_UNAVAILABLE,
            "Endpoint descriptor is unavailable.",
        ) from exc


def remove_endpoint_descriptor(path: Path, *, expected_token: str | None = None) -> None:
    """Remove only the descriptor owned by this server startup."""

    path = path.expanduser().resolve()
    if expected_token is not None and path.exists():
        try:
            current = read_endpoint_descriptor(path)
        except ProtocolError:
            return
        if current.auth_token != expected_token:
            return
    try:
        path.unlink(missing_ok=True)
    except OSError:
        # Shutdown remains best effort; stale descriptors fail safely at connect.
        return


def _restrict_windows_acl(path: Path) -> None:
    """Replace inheritance with an ACL granting access only to current user."""

    try:
        import win32api
        import win32con
        import win32security

        process_token = win32security.OpenProcessToken(
            win32api.GetCurrentProcess(),
            win32con.TOKEN_QUERY,
        )
        try:
            user_sid = win32security.GetTokenInformation(
                process_token,
                win32security.TokenUser,
            )[0]
        finally:
            process_token.Close()

        dacl = win32security.ACL()
        # FILE_ALL_ACCESS; kept local to avoid another platform-only import.
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, 0x001F01FF, user_sid)
        win32security.SetNamedSecurityInfo(
            str(path),
            win32security.SE_FILE_OBJECT,
            win32security.DACL_SECURITY_INFORMATION
            | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            dacl,
            None,
        )
    except Exception as exc:
        raise ProtocolError(
            ProtocolErrorCode.PERMISSION_DENIED,
            "Could not restrict endpoint descriptor to the current user.",
        ) from exc


__all__ = [
    "endpoint_permissions_are_private",
    "read_endpoint_descriptor",
    "remove_endpoint_descriptor",
    "write_endpoint_descriptor",
]
