"""Bounded, non-executing archive operations with portable path validation."""
from __future__ import annotations
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tarfile
import zipfile

MAX_BYTES = 12 * 1024**3
MAX_FILES = 200000
MAX_PATH = 4096
MAX_DEPTH = 64
RESERVED = re.compile(r"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)", re.I)


def parts(name: str) -> tuple[str, ...]:
    if (not isinstance(name, str) or not name or len(name) > MAX_PATH
            or any(c in name for c in '\\:"<>|?*')
            or any(ord(c) < 32 or ord(c) == 127 for c in name)):
        raise ValueError("unsafe archive path")
    raw = name.rstrip("/").split("/")
    p = PurePosixPath(name)
    if (p.is_absolute() or len(raw) > MAX_DEPTH
            or any(x in ("", ".", "..") or x.endswith((" ", ".")) or RESERVED.match(x) for x in raw)):
        raise ValueError("unsafe archive path")
    if any(x.casefold() == ".git" for x in raw):
        raise ValueError("git metadata is forbidden")
    return tuple(raw)


class _PathIndex:
    """Reject aliases in every component, including implicit parent directories."""
    def __init__(self):
        self.nodes: dict[tuple[str, ...], tuple[tuple[str, ...], bool]] = {}
        self.explicit: set[tuple[str, ...]] = set()

    def add(self, name: str, directory: bool) -> None:
        path = parts(name)
        folded = tuple(x.casefold() for x in path)
        if folded in self.explicit:
            raise ValueError("duplicate archive entry")
        for size in range(1, len(path) + 1):
            node = path[:size]
            key = folded[:size]
            is_dir = size < len(path) or directory
            previous = self.nodes.get(key)
            if previous is not None and previous != (node, is_dir):
                raise ValueError("case alias or file/directory collision")
            self.nodes[key] = (node, is_dir)
        self.explicit.add(folded)


def regular(path: Path) -> bool:
    info = path.lstat()
    return (not stat.S_ISLNK(info.st_mode)
            and not getattr(info, "st_file_attributes", 0) & 0x400
            and stat.S_ISREG(info.st_mode))


def _target(root: Path, name: str) -> Path:
    result = root.joinpath(*parts(name))
    if not result.resolve().is_relative_to(root.resolve()):
        raise ValueError("archive escape")
    return result


def _regular_files(root: Path):
    """Do not silently skip junctions or symlink directories when packaging."""
    info = root.lstat()
    if (not stat.S_ISDIR(info.st_mode) or root.is_symlink()
            or getattr(info, "st_file_attributes", 0) & 0x400):
        raise ValueError("unsafe archive root")
    index = _PathIndex()
    count = total = 0
    for current, directories, filenames in os.walk(root, followlinks=False):
        directories.sort()
        filenames.sort()
        for name in directories:
            path = Path(current) / name
            info = path.lstat()
            if (not stat.S_ISDIR(info.st_mode) or path.is_symlink()
                    or getattr(info, "st_file_attributes", 0) & 0x400):
                raise ValueError("links and reparse directories are forbidden")
            index.add(path.relative_to(root).as_posix(), True)
            count += 1
        for name in filenames:
            path = Path(current) / name
            if not regular(path):
                raise ValueError("cannot package link or special file")
            index.add(path.relative_to(root).as_posix(), False)
            count += 1
            total += path.stat().st_size
            if count > MAX_FILES or total > MAX_BYTES:
                raise ValueError("archive limits exceeded")
            yield path
        if count > MAX_FILES:
            raise ValueError("archive limits exceeded")


def extract_tar(archive: Path, root: Path) -> None:
    root.mkdir(parents=True, exist_ok=False)
    index = _PathIndex()
    total = 0
    with tarfile.open(archive, "r:*") as tar:
        for count, item in enumerate(tar):
            if count >= MAX_FILES or item.size < 0:
                raise ValueError("archive limits exceeded")
            if not item.isdir() and not item.isfile():
                raise ValueError("links and special files are forbidden")
            index.add(item.name, item.isdir())
            target = _target(root, item.name)
            if item.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                total += item.size
                if total > MAX_BYTES:
                    raise ValueError("archive too large")
                target.parent.mkdir(parents=True, exist_ok=True)
                with tar.extractfile(item) as src, target.open("xb") as dst:
                    shutil.copyfileobj(src, dst, 1024 * 1024)
                target.chmod(0o755 if item.mode & 0o111 else 0o644)


def pack_tar(root: Path, archive: Path) -> None:
    with tarfile.open(archive, "w:gz", format=tarfile.PAX_FORMAT) as tar:
        for item in _regular_files(root):
            tar.add(item, arcname=item.relative_to(root).as_posix(), recursive=False)


def zip_files(archive: Path) -> list[zipfile.ZipInfo]:
    with zipfile.ZipFile(archive) as z:
        entries = z.infolist()
        if len(entries) > MAX_FILES:
            raise ValueError("too many zip entries")
        index = _PathIndex()
        total = 0
        for item in entries:
            index.add(item.filename, item.is_dir())
            kind = stat.S_IFMT(item.external_attr >> 16)
            if (item.flag_bits & 1 or item.external_attr & 0x400
                    or kind not in {0, stat.S_IFREG, stat.S_IFDIR}
                    or (kind == stat.S_IFDIR and not item.is_dir())
                    or (kind == stat.S_IFREG and item.is_dir())
                    or item.file_size < 0 or item.compress_size < 0
                    or (item.is_dir() and item.file_size != 0)):
                raise ValueError("unsupported zip entry")
            total += item.file_size
            if total > MAX_BYTES:
                raise ValueError("zip too large")
        return entries


def extract_zip(archive: Path, root: Path) -> None:
    entries = zip_files(archive)
    root.mkdir(parents=True, exist_ok=False)
    with zipfile.ZipFile(archive) as z:
        for item in entries:
            target = _target(root, item.filename)
            if item.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with z.open(item) as src, target.open("xb") as dst:
                    shutil.copyfileobj(src, dst, 1024 * 1024)
                target.chmod(0o755 if item.external_attr >> 16 & 0o111 else 0o644)


def forbidden_sdk_tree(name: str) -> bool:
    """Reject build/configuration roots, not legitimate include/debug headers."""
    lowered = [p.casefold() for p in parts(name)]
    return (any(p in {".git", "downloads", "buildtrees"} for p in lowered)
            or lowered[0] == "debug"
            or (len(lowered) >= 3 and lowered[0] == "installed" and lowered[2] == "debug"))


def sdk_zip(root: Path, archive: Path) -> None:
    """Package the export only, with normalized portable ZIP metadata."""
    banned_suffix = {".pdb", ".ilk", ".obj", ".o", ".pch", ".idb", ".ipch", ".dmp", ".log"}
    banned_names = {"cmakecache.txt", "compile_commands.json", "credentials", ".git-credentials"}
    with zipfile.ZipFile(archive, "x", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for item in _regular_files(root):
            rel = item.relative_to(root)
            if forbidden_sdk_tree(rel.as_posix()):
                raise ValueError("workspace or debug tree in SDK")
            if item.suffix.casefold() in banned_suffix or item.name.casefold() in banned_names:
                continue
            if item.suffix.casefold() in {".c", ".cc", ".cpp", ".cxx"}:
                raise ValueError("implementation source in SDK; review required")
            info = zipfile.ZipInfo(rel.as_posix(), date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.compress_type = zipfile.ZIP_DEFLATED
            source_info = item.stat()
            mode = 0o755 if source_info.st_mode & 0o111 else 0o644
            info.external_attr = (stat.S_IFREG | mode) << 16
            info.file_size = source_info.st_size
            with item.open("rb") as source, z.open(info, "w", force_zip64=True) as target:
                shutil.copyfileobj(source, target, 1024 * 1024)
    if archive.stat().st_size > 1900 * 1024**2:
        raise ValueError("SDK exceeds the 1900 MiB initial release limit")
    zip_files(archive)
