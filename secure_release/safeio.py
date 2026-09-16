"""Bounded, non-executing archive operations shared by fetcher and publisher."""
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
RESERVED = re.compile(r"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)", re.I)


def parts(name: str) -> tuple[str, ...]:
    if not name or "\\" in name or ":" in name or any(ord(c) < 32 for c in name):
        raise ValueError("unsafe archive path")
    p = PurePosixPath(name)
    if p.is_absolute() or any(x in ("", ".", "..") or x.endswith((" ", ".")) or RESERVED.match(x) for x in name.rstrip("/").split("/")):
        raise ValueError("unsafe archive path")
    if any(x.casefold() == ".git" for x in p.parts):
        raise ValueError("git metadata is forbidden")
    return p.parts


def regular(path: Path) -> bool:
    info = path.lstat()
    if path.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
        return False
    return stat.S_ISREG(info.st_mode)


def _target(root: Path, name: str) -> Path:
    result = root.joinpath(*parts(name))
    if not result.resolve().is_relative_to(root.resolve()):
        raise ValueError("archive escape")
    return result


def extract_tar(archive: Path, root: Path) -> None:
    root.mkdir(parents=True, exist_ok=False)
    seen = set()
    total = 0
    with tarfile.open(archive, "r:*") as tar:
        for index, item in enumerate(tar):
            if index >= MAX_FILES or item.size < 0:
                raise ValueError("archive limits exceeded")
            target = _target(root, item.name)
            folded = str(target.relative_to(root)).casefold()
            if folded in seen:
                raise ValueError("duplicate archive entry")
            seen.add(folded)
            if item.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif item.isfile():
                total += item.size
                if total > MAX_BYTES:
                    raise ValueError("archive too large")
                target.parent.mkdir(parents=True, exist_ok=True)
                with tar.extractfile(item) as src, target.open("xb") as dst:
                    shutil.copyfileobj(src, dst, 1024 * 1024)
                target.chmod(0o755 if item.mode & 0o111 else 0o644)
            else:
                raise ValueError("links and special files are forbidden")


def pack_tar(root: Path, archive: Path) -> None:
    with tarfile.open(archive, "w:gz", format=tarfile.PAX_FORMAT) as tar:
        for item in sorted(root.rglob("*")):
            if item.is_dir() and not item.is_symlink():
                continue
            if not regular(item):
                raise ValueError("cannot package link or special file")
            name = item.relative_to(root).as_posix()
            parts(name)
            tar.add(item, arcname=name, recursive=False)


def zip_files(archive: Path) -> list[zipfile.ZipInfo]:
    with zipfile.ZipFile(archive) as z:
        entries = z.infolist()
        if len(entries) > MAX_FILES:
            raise ValueError("too many zip entries")
        seen = set()
        total = 0
        for item in entries:
            parts(item.filename)
            if item.filename.casefold() in seen:
                raise ValueError("duplicate zip entry")
            seen.add(item.filename.casefold())
            mode = item.external_attr >> 16
            if item.flag_bits & 1 or stat.S_ISLNK(mode) or stat.S_ISFIFO(mode) or stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
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


def sdk_zip(root: Path, archive: Path) -> None:
    """Package the export only, never the workspace. Debug symbols are omitted."""
    banned_suffix = {".pdb", ".ilk", ".obj", ".o", ".pch", ".idb", ".ipch", ".dmp", ".log"}
    banned_names = {"cmakecache.txt", "compile_commands.json", "credentials", ".git-credentials"}
    with zipfile.ZipFile(archive, "x", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for item in sorted(root.rglob("*")):
            if item.is_dir() and not item.is_symlink():
                continue
            if not regular(item):
                raise ValueError("unsafe SDK member")
            rel = item.relative_to(root)
            parts(rel.as_posix())
            lowered = [p.casefold() for p in rel.parts]
            if any(p in {".git", "downloads", "buildtrees", "debug"} for p in lowered):
                raise ValueError("workspace or debug tree in SDK")
            if item.suffix.casefold() in banned_suffix or item.name.casefold() in banned_names:
                continue
            if item.suffix.casefold() in {".c", ".cc", ".cpp", ".cxx"}:
                raise ValueError("implementation source in SDK; review required")
            z.write(item, rel.as_posix())
    zip_files(archive)
