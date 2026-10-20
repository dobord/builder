"""Linux full-profile CLI proof: no ELF interpreter or DT_NEEDED dependencies."""
import hashlib
import json
from pathlib import Path
import struct
import zipfile

FREERDP_TOOLS = ("xfreerdp", "freerdp-proxy", "freerdp-shadow-cli", "winpr-hash", "winpr-makecert")


def _tool_record(path: Path) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 512 * 1024**2:
        raise ValueError("Missing or redirected multimedia tool")
    data = path.read_bytes()
    static_elf(data)
    return {"sha256": hashlib.sha256(data).hexdigest(), "dt_needed": 0, "interpreter": False}


def static_elf(data: bytes) -> None:
    if (len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01" or
            struct.unpack_from("<HH", data, 16) not in ((2, 62), (3, 62))):
        raise ValueError("Multimedia tool is not a native x64 ELF executable")
    offset = struct.unpack_from("<Q", data, 32)[0]
    size, count = struct.unpack_from("<HH", data, 54)
    if size != 56 or not 0 < count <= 128 or offset < 64 or offset + size * count > len(data):
        raise ValueError("Invalid multimedia ELF program headers")
    for index in range(count):
        start = offset + index * size
        kind = struct.unpack_from("<I", data, start)[0]
        position, length = struct.unpack_from("<Q", data, start + 8)[0], struct.unpack_from("<Q", data, start + 32)[0]
        if position + length > len(data):
            raise ValueError("Invalid multimedia ELF segment")
        if kind == 3:
            raise ValueError("Multimedia tool has a dynamic ELF interpreter")
        if kind == 2:
            if length % 16 or length > 1024**2:
                raise ValueError("Invalid multimedia ELF dynamic table")
            for entry in range(position, position + length, 16):
                tag = struct.unpack_from("<q", data, entry)[0]
                if tag == 0:
                    break
                if tag == 1:
                    raise ValueError("Multimedia tool has a DT_NEEDED dependency")


def verify_linux(sdk: Path, work: Path, execute, *, freerdp_full: bool = False) -> dict:
    tools = sdk / "installed/x64-linux-static-release/tools/ffmpeg"
    records = {}
    for name in ("ffmpeg", "ffprobe"):
        path = tools / name
        records[name] = _tool_record(path)
        execute([str(path), "-version"], stage="consumer-test", timeout=60)
    media = work / "multimedia-h264-probe.mkv"
    execute([str(tools / "ffmpeg"), "-nostdin", "-v", "error", "-f", "lavfi", "-i",
             "testsrc2=size=64x64:rate=5", "-t", "0.4", "-c:v", "libx264", "-y", str(media)],
            stage="consumer-test", timeout=60)
    execute([str(tools / "ffmpeg"), "-nostdin", "-v", "error", "-i", str(media), "-f", "null", "-"],
            stage="consumer-test", timeout=60)
    report = work / "multimedia-ffprobe.json"
    execute([str(tools / "ffprobe"), "-v", "error", "-show_entries", "stream=codec_name,width,height",
             "-of", "json", "-o", str(report), str(media)], stage="consumer-test", timeout=60)
    if report.is_symlink() or not report.is_file() or report.stat().st_size > 65536:
        raise ValueError("Missing multimedia probe result")
    if json.loads(report.read_bytes()).get("streams") != [{"codec_name": "h264", "width": 64, "height": 64}]:
        raise ValueError("ffprobe did not verify the encoded H.264 video")
    proof = {"tools": records, "h264_roundtrip": True}
    if freerdp_full:
        prefix = sdk / "installed/x64-linux-static-release/tools/freerdp"
        proof["freerdp_tools"] = {name: _tool_record(prefix / name) for name in FREERDP_TOOLS}
    return proof


def validate_archive(archive: Path, proof: dict, *, freerdp_full: bool = False) -> None:
    fields = {"tools", "h264_roundtrip"} | ({"freerdp_tools"} if freerdp_full else set())
    if (not isinstance(proof, dict) or set(proof) != fields or
            proof["h264_roundtrip"] is not True or not isinstance(proof["tools"], dict) or
            set(proof["tools"]) != {"ffmpeg", "ffprobe"}):
        raise ValueError("Missing static multimedia CLI proof")
    if freerdp_full and (not isinstance(proof["freerdp_tools"], dict) or set(proof["freerdp_tools"]) != set(FREERDP_TOOLS)):
        raise ValueError("Missing static FreeRDP CLI proof")
    records = [("ffmpeg/" + name, record) for name, record in proof["tools"].items()]
    if freerdp_full:
        records += [("freerdp/" + name, record) for name, record in proof["freerdp_tools"].items()]
    with zipfile.ZipFile(archive) as sdk:
        for name, record in records:
            info = sdk.getinfo("installed/x64-linux-static-release/tools/" + name)
            if info.file_size > 512 * 1024**2:
                raise ValueError("Oversized multimedia tool")
            data = sdk.read(info)
            static_elf(data)
            if record != {"sha256": hashlib.sha256(data).hexdigest(), "dt_needed": 0, "interpreter": False}:
                raise ValueError("Static multimedia tool differs from its runtime proof")
