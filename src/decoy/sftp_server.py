"""Virtual SFTP / SCP for the SSH decoy: capture what attackers upload, never touch the host's disk.

asyncssh's stock SFTPServer works on the real filesystem, so EVERY operation is overridden here and runs against the
per-(IP, user) PseudoFilesystem the shell uses: an uploaded file shows up in `ls` and can be read back, bait files
(`~/.aws/credentials`, ...) are served as honeytokens with an alert, and nothing else exists. `scp` goes through the
same class (asyncssh runs its SCP server on top of the SFTP server), so `scp file user@decoy:/tmp/` is captured too.

Every finished upload is handed to DecoyServer.capture (SHA-256, quarantine, alert, `payload_hashes`).
"""
import posixpath
import time
from typing import Dict, Optional

import asyncssh
from asyncssh import SFTPAttrs, SFTPName

from .llm_provider import is_honeytoken
from .pseudo_fs import STATIC_FILES

MAX_UPLOADS_PER_SESSION = 20
MAX_KEPT_BYTES = 256 * 1024  # an upload this small is kept so it can be read back; bigger ones are only captured
S_IFDIR, S_IFREG = 0o040000, 0o100000
DIR_TYPE, FILE_TYPE = asyncssh.sftp.FILEXFER_TYPE_DIRECTORY, asyncssh.sftp.FILEXFER_TYPE_REGULAR  # scp checks the type


class _Upload:
    def __init__(self, path: str):
        self.path, self.data = path, bytearray()


class _Download:
    def __init__(self, path: str, data: bytes):
        self.path, self.data = path, data


class VirtualSFTP(asyncssh.SFTPServer):
    def __init__(self, chan, decoy, fs, session_id: str, source_ip: str):
        super().__init__(chan)
        self.decoy, self.fs, self.session_id, self.source_ip = decoy, fs, session_id, source_ip
        self.uploads_started = 0

    # -- path and file helpers -------------------------------------------------------------------------
    def _path(self, raw: bytes) -> str:
        return self.fs._resolve(raw.decode("utf-8", "replace") or ".")

    def _kept(self) -> Dict[str, bytes]:
        if not hasattr(self.fs, "uploads"):
            self.fs.uploads = {}  # path -> bytes of small uploads, per persistent filesystem
        return self.fs.uploads

    def _exists(self, path: str) -> bool:
        return (self.fs._is_dir(path) or self.fs._is_file(path) or path in self.fs.written or path in self._kept()
                or path in STATIC_FILES or is_honeytoken(path))

    def _contents(self, path: str) -> Optional[bytes]:
        if path in self._kept():
            return self._kept()[path]
        if self.fs.written.get(path) is not None or self.fs._is_file(path) or path in STATIC_FILES or is_honeytoken(path):
            return self.fs._cat(path).encode("utf-8", "surrogateescape")  # also raises the honeytoken alert
        return None

    def _attrs(self, path: str) -> SFTPAttrs:
        if self.fs._is_dir(path):
            return SFTPAttrs(size=4096, uid=0, gid=0, permissions=S_IFDIR | 0o755, type=DIR_TYPE, atime=0, mtime=int(time.time()))
        data = self._contents(path) if self._exists(path) else None
        if data is None:
            raise asyncssh.SFTPNoSuchFile("No such file")
        return SFTPAttrs(size=len(data), uid=0, gid=0, permissions=S_IFREG | 0o644, type=FILE_TYPE, atime=0, mtime=int(time.time()))

    # -- files -----------------------------------------------------------------------------------------
    def open(self, path: bytes, pflags: int, attrs: SFTPAttrs):
        target = self._path(path)
        if pflags & (asyncssh.FXF_WRITE | asyncssh.FXF_APPEND):
            if self.uploads_started >= MAX_UPLOADS_PER_SESSION:
                raise asyncssh.SFTPNoSpaceOnFilesystem("Disk quota exceeded")
            if self.fs._is_dir(target) or not self.fs._is_dir(posixpath.dirname(target)):
                raise asyncssh.SFTPNoSuchFile("No such file")
            self.uploads_started += 1
            upload = _Upload(target)
            if (pflags & asyncssh.FXF_APPEND) and target in self._kept():
                upload.data += self._kept()[target]
            return upload
        if self.fs._is_dir(target):
            raise asyncssh.SFTPFailure("Is a directory")
        data = self._contents(target)
        if data is None:
            raise asyncssh.SFTPNoSuchFile("No such file")
        return _Download(target, data)

    def open56(self, path, desired_access, flags, attrs):
        raise asyncssh.SFTPOpUnsupported("Operation unsupported")

    def read(self, file_obj, offset: int, size: int) -> bytes:
        if not isinstance(file_obj, _Download):
            raise asyncssh.SFTPPermissionDenied("Permission denied")
        if offset >= len(file_obj.data):
            raise asyncssh.SFTPEOFError("")
        return bytes(file_obj.data[offset:offset + size])

    def write(self, file_obj, offset: int, data: bytes) -> int:
        if not isinstance(file_obj, _Upload):
            raise asyncssh.SFTPPermissionDenied("Permission denied")
        if offset + len(data) > self.decoy.config.max_sample_bytes:
            raise asyncssh.SFTPNoSpaceOnFilesystem("No space left on device")
        if offset > len(file_obj.data):
            file_obj.data += bytes(offset - len(file_obj.data))
        file_obj.data[offset:offset + len(data)] = data
        return len(data)

    def close(self, file_obj) -> None:
        if not isinstance(file_obj, _Upload) or not file_obj.data:
            if isinstance(file_obj, _Upload):
                self.fs._add_file(file_obj.path)  # an empty upload (touch) still creates the file
            return
        data = bytes(file_obj.data)
        self.fs._add_file(file_obj.path)
        self.fs.written.pop(file_obj.path, None)  # the upload replaces any text written earlier
        if len(data) <= MAX_KEPT_BYTES and len(self._kept()) < MAX_UPLOADS_PER_SESSION:
            self._kept()[file_obj.path] = data
        self.decoy.capture(data, "upload", f"sftp {file_obj.path}", self.session_id, self.source_ip, "SSH")
        self.decoy.signal_logger.log(self.session_id, self.source_ip, "SSH", "sftp_upload",
                                     f"{file_obj.path} {len(data)}B")

    def fsync(self, file_obj) -> None:
        return None

    def lock(self, file_obj, offset, length, flags) -> None:
        return None

    def unlock(self, file_obj, offset, length) -> None:
        return None

    # -- metadata and directories ------------------------------------------------------------------------
    def stat(self, path: bytes) -> SFTPAttrs:
        return self._attrs(self._path(path))

    lstat = stat

    def fstat(self, file_obj) -> SFTPAttrs:
        return SFTPAttrs(size=len(file_obj.data), uid=0, gid=0, permissions=S_IFREG | 0o644, type=FILE_TYPE, mtime=int(time.time()))

    async def scandir(self, path: bytes):
        target = self._path(path)
        if not self.fs._is_dir(target):
            raise asyncssh.SFTPNoSuchFile("No such file")
        for name in [".", ".."] + sorted(self.fs.virtual_tree[target]):
            full = posixpath.normpath(posixpath.join(target, name))
            try:
                attrs = self._attrs(full)
            except asyncssh.SFTPNoSuchFile:
                attrs = SFTPAttrs(size=0, uid=0, gid=0, permissions=S_IFREG | 0o644, type=FILE_TYPE, mtime=int(time.time()))
            yield SFTPName(name.encode(), attrs=attrs)

    def realpath(self, path: bytes) -> bytes:
        return self._path(path).encode()

    def map_path(self, path: bytes) -> bytes:
        return path  # no chroot to map: paths are virtual

    def reverse_map_path(self, path: bytes) -> bytes:
        return path

    def mkdir(self, path: bytes, attrs: SFTPAttrs) -> None:
        target = self._path(path)
        if self._exists(target):
            raise asyncssh.SFTPFileAlreadyExists("File exists")
        if not self.fs._is_dir(posixpath.dirname(target)):
            raise asyncssh.SFTPNoSuchFile("No such file")
        self.fs._add_file(target)
        self.fs.virtual_tree[target] = []

    def remove(self, path: bytes) -> None:
        target = self._path(path)
        parent, name = posixpath.split(target)
        if self.fs._is_dir(target) or name not in self.fs.virtual_tree.get(parent, []):
            raise asyncssh.SFTPNoSuchFile("No such file")
        self.fs.virtual_tree[parent].remove(name)
        self.fs.written.pop(target, None)
        self._kept().pop(target, None)

    def rmdir(self, path: bytes) -> None:
        target = self._path(path)
        if not self.fs._is_dir(target) or self.fs.virtual_tree[target] or target in ("/", self.fs.home):
            raise asyncssh.SFTPFailure("Directory not empty")
        parent, name = posixpath.split(target)
        self.fs.virtual_tree[parent].remove(name)
        del self.fs.virtual_tree[target]

    def rename(self, oldpath: bytes, newpath: bytes) -> None:
        old, new = self._path(oldpath), self._path(newpath)
        parent, name = posixpath.split(old)
        if self.fs._is_dir(old) or name not in self.fs.virtual_tree.get(parent, []) or not self.fs._is_dir(posixpath.dirname(new)):
            raise asyncssh.SFTPNoSuchFile("No such file")
        self.fs.virtual_tree[parent].remove(name)
        self.fs._add_file(new)
        for table in (self.fs.written, self._kept()):
            if old in table:
                table[new] = table.pop(old)

    posix_rename = rename

    def setstat(self, path: bytes, attrs: SFTPAttrs) -> None:
        return None  # chmod / chown / utime: accepted, nothing to change

    lsetstat = setstat

    def fsetstat(self, file_obj, attrs: SFTPAttrs) -> None:
        return None

    def readlink(self, path: bytes) -> bytes:
        raise asyncssh.SFTPOpUnsupported("Operation unsupported")

    def symlink(self, oldpath: bytes, newpath: bytes) -> None:
        raise asyncssh.SFTPPermissionDenied("Permission denied")

    link = symlink

    def statvfs(self, path: bytes):
        raise asyncssh.SFTPOpUnsupported("Operation unsupported")

    def fstatvfs(self, file_obj):
        raise asyncssh.SFTPOpUnsupported("Operation unsupported")

    def exit(self) -> None:
        """Report success when the client ends the session: OpenSSH's scp (SFTP mode) treats a channel that closes
        without an exit status as a failed transfer, which is not what a real sshd does."""
        try:
            self._chan.exit(0)
        except Exception:  # channel already closed
            pass
