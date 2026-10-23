

# __init__.py
"""Local, read-only media metadata audits. No runtime third-party dependencies."""

__version__ = "0.1.0"


# paths.py
"""Keep report paths natural while enabling native Windows extended-length I/O."""

import os
from pathlib import Path


def display_path(value):
    text = str(value)
    if os.name == "nt":
        if text.startswith("\\\\?\\UNC\\"):
            text = "\\\\" + text[8:]
        elif text.startswith("\\\\?\\"):
            text = text[4:]
    return Path(text)


def absolute(value):
    return display_path(os.path.abspath(value))


def io_path(value):
    """Long local/UNC paths do not require changing machine long-path policy."""
    path = absolute(value)
    text = str(path)
    if os.name == "nt" and len(text) >= 240:
        text = "\\\\?\\UNC\\" + text[2:] if text.startswith("\\\\") else "\\\\?\\" + text
    return Path(text)


def resolved(value):
    return display_path(io_path(value).resolve())


# model.py
"""Small JSON-compatible result objects."""


def reject_constant(value):
    raise ValueError("non-finite JSON number is not supported")


def finding(rule, severity, actual, expected, provenance, explanation, evidence="heuristic"):
    return dict(rule_id=rule, severity=severity, actual=actual, expected=expected,
                provenance=provenance, explanation=explanation, evidence=evidence)


def record(path, findings, metadata=None, kind="file"):
    return dict(type=kind, path=str(path), metadata=metadata or {}, findings=findings)


def issue(path, rule, severity, explanation, actual=None, expected=None):
    return record(path, [finding(rule, severity, actual, expected, "filesystem",
                                explanation, "unavailable")], kind="event")


# config.py
"""Strict, versioned configuration. Defaults do not infer capture timestamps."""

import copy
import json
import math
import re
import string
from datetime import datetime, timedelta, timezone
from pathlib import PurePosixPath


DEFAULTS = {
    "version": 1,
    "extensions": [".mp4", ".mov", ".mkv", ".webm", ".avi", ".m4v", ".mts",
                   ".m2ts", ".mp3", ".m4a", ".aac", ".wav", ".flac", ".ogg", ".opus"],
    "include": ["*"], "exclude": [], "follow_symlinks": False,
    "probe_timeout": 20.0, "probe_output_limit": 2097152,
    "fail_on": "warning", "unusual_fps_min": 1.0, "unusual_fps_max": 120.0,
    "timestamps": {"enabled": False, "tolerance_seconds": 300.0,
                   "naive_timezone": None, "filename_regex": None,
                   "filename_format": None, "filename_timezone": None,
                   "filesystem": []},
    "companions": [],
    "grouping": None,
}


class ConfigError(ValueError):
    pass


def fixed_timezone(value):
    if value == "UTC":
        return timezone.utc
    if not isinstance(value, str) or not re.fullmatch(r"[+-](?:0\d|1\d|2[0-3]):[0-5]\d", value):
        raise ConfigError("timezone must be UTC or an explicit ±HH:MM fixed offset")
    sign = 1 if value[0] == "+" else -1
    return timezone(sign * timedelta(hours=int(value[1:3]), minutes=int(value[4:6])))


def _number(value, name, low, high):
    if type(value) not in (int, float) or not math.isfinite(value) or not low <= value <= high:
        raise ConfigError(f"{name} must be a finite number between {low} and {high}")


def _pattern(value, name, group=None):
    if not isinstance(value, str) or len(value) > 256:
        raise ConfigError(f"{name} must be a regex string of at most 256 characters")
    try:
        compiled = re.compile(value)
    except re.error as exc:
        raise ConfigError(f"invalid {name}: {exc}") from exc
    if group and group not in compiled.groupindex:
        raise ConfigError(f"{name} needs a named '{group}' capture")


def validate(raw):
    if not isinstance(raw, dict) or type(raw.get("version")) is not int or raw["version"] != 1:
        raise ConfigError("settings must be a JSON object with version set to 1; use rules --defaults for a template")
    unknown = set(raw) - set(DEFAULTS)
    if unknown:
        raise ConfigError(f"unknown configuration keys: {', '.join(sorted(unknown))}")
    cfg = copy.deepcopy(DEFAULTS)
    cfg.update(raw)
    for key in ("extensions", "include", "exclude"):
        if not isinstance(cfg[key], list) or not all(isinstance(x, str) and x for x in cfg[key]):
            raise ConfigError(f"{key} must be an array of nonempty strings")
    if not cfg["extensions"] or any(not re.fullmatch(r"\.[A-Za-z0-9]+", e) for e in cfg["extensions"]):
        raise ConfigError("extensions must be a nonempty list such as ['.mp4', '.wav']")
    cfg["extensions"] = [e.lower() for e in cfg["extensions"]]
    if type(cfg["follow_symlinks"]) is not bool:
        raise ConfigError("follow_symlinks must be boolean")
    _number(cfg["probe_timeout"], "probe_timeout", 0.1, 3600)
    if type(cfg["probe_output_limit"]) is not int or not 1024 <= cfg["probe_output_limit"] <= 16777216:
        raise ConfigError("probe_output_limit must be an integer from 1024 to 16777216")
    if cfg["fail_on"] not in ("error", "warning", "info", "none"):
        raise ConfigError("fail_on must be error, warning, info, or none")
    _number(cfg["unusual_fps_min"], "unusual_fps_min", 0.01, 10000)
    _number(cfg["unusual_fps_max"], "unusual_fps_max", cfg["unusual_fps_min"], 10000)
    ts = cfg["timestamps"]
    if not isinstance(ts, dict) or set(ts) - set(DEFAULTS["timestamps"]):
        raise ConfigError("invalid timestamps object or unknown timestamp key")
    ts = {**DEFAULTS["timestamps"], **ts}
    cfg["timestamps"] = ts
    if type(ts["enabled"]) is not bool:
        raise ConfigError("timestamps.enabled must be boolean")
    _number(ts["tolerance_seconds"], "timestamps.tolerance_seconds", 0, 315576000)
    for key in ("naive_timezone", "filename_timezone"):
        if ts[key] is not None:
            fixed_timezone(ts[key])
    if not isinstance(ts["filesystem"], list) or any(v not in ("mtime", "birthtime") for v in ts["filesystem"]):
        raise ConfigError("timestamps.filesystem supports only mtime and birthtime")
    if ts["filename_regex"] is not None:
        _pattern(ts["filename_regex"], "timestamps.filename_regex", "date")
        if not isinstance(ts["filename_format"], str) or not ts["filename_format"]:
            raise ConfigError("filename dates need filename_format, such as %Y-%m-%d, matching the text captured by filename_regex")
        if ts["filename_timezone"] is None:
            raise ConfigError("filename dates require an explicit filename_timezone")
        try:
            datetime.now().strftime(ts["filename_format"])
        except (ValueError, TypeError) as exc:
            raise ConfigError("invalid filename_format") from exc
    elif ts["filename_format"] is not None or ts["filename_timezone"] is not None:
        raise ConfigError("filename format/timezone require filename_regex")
    if not isinstance(cfg["companions"], list):
        raise ConfigError("companions must be an array")
    for c in cfg["companions"]:
        if not isinstance(c, dict) or set(c) != {"template", "required", "kind"}:
            raise ConfigError("each companion needs template, required, and kind")
        if type(c["required"]) is not bool or c["kind"] not in ("file", "directory"):
            raise ConfigError("invalid companion required/kind")
        template = c["template"]
        if not isinstance(template, str) or not template:
            raise ConfigError("companion template must be nonempty text")
        try:
            for _, field, spec, conversion in string.Formatter().parse(template):
                if field is not None and (field not in ("stem", "name", "suffix") or spec or conversion):
                    raise ValueError("unsupported placeholder")
            formatted = template.format(stem="asset", name="asset.mp4", suffix=".mp4")
        except (KeyError, ValueError, IndexError, AttributeError) as exc:
            raise ConfigError("companion placeholders are {stem}, {name}, {suffix}") from exc
        if (PurePosixPath(formatted).is_absolute() or ".." in PurePosixPath(formatted).parts
                or "\\" in formatted or ":" in formatted or "{" in formatted):
            raise ConfigError("companion template must stay in the media parent; use forward slashes")
    g = cfg["grouping"]
    if g is not None:
        if not isinstance(g, dict) or set(g) != {"regex", "fields", "max_peers"}:
            raise ConfigError("grouping needs regex, fields, max_peers")
        _pattern(g["regex"], "grouping.regex", "group")
        if not isinstance(g["fields"], list) or not g["fields"] or any(
                f not in ("video_codec", "audio_codec", "width", "height", "sample_rate", "channels", "fps")
                for f in g["fields"]):
            raise ConfigError("invalid grouping.fields")
        if type(g["max_peers"]) is not int or not 1 <= g["max_peers"] <= 1000:
            raise ConfigError("grouping.max_peers must be 1..1000")
    return cfg


def load(path=None):
    if path is None:
        return validate({"version": 1})
    try:
        with open(io_path(path), encoding="utf-8") as handle:
            raw = json.load(handle, parse_constant=reject_constant)
        return validate(raw)
    except (OSError, ValueError, RecursionError) as exc:
        raise ConfigError(f"cannot load configuration: {exc}") from exc


# probe.py
"""Bounded local FFmpeg subprocesses. Never uses a shell or a network protocol."""

import json
import shutil
import subprocess
import threading



def discover(name):
    return shutil.which(name)


def bounded_run(args, timeout, limit):
    """Drain both pipes concurrently, kill at the byte limit, and cap retained data."""
    try:
        proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, shell=False)
    except OSError:
        return {"status": "launch_error"}
    overflow = threading.Event()
    chunks = [bytearray(), bytearray()]

    def drain(pipe, index):
        try:
            while True:
                block = pipe.read(8192)
                if not block:
                    break
                room = limit - len(chunks[index])
                chunks[index].extend(block[:max(0, room)])
                if len(block) > room:
                    overflow.set()
                    try:
                        proc.kill()
                    except OSError:
                        pass
                    break
        finally:
            pipe.close()

    threads = [threading.Thread(target=drain, args=(pipe, i), daemon=True)
               for i, pipe in enumerate((proc.stdout, proc.stderr))]
    for thread in threads:
        thread.start()
    status = "ok"
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        status = "timeout"
        proc.kill()
        proc.wait()
    except BaseException:
        proc.kill()
        proc.wait()
        raise
    for thread in threads:
        thread.join(timeout=1)
    if overflow.is_set() or any(t.is_alive() for t in threads):
        status = "output_limit"
    if status == "ok" and proc.returncode != 0:
        status = "nonzero"
    elif status == "ok" and chunks[1]:
        status = "diagnostic"
    return {"status": status, "returncode": proc.returncode,
            "stdout": bytes(chunks[0]), "diagnostic_bytes": len(chunks[1])}


def probe(path, executable, timeout=20, limit=2097152):
    if not executable:
        return {"status": "missing"}
    args = [executable, "-v", "error", "-max_alloc", "67108864", "-threads", "1",
            "-protocol_whitelist", "file", "-show_entries",
            "format=format_name,duration:format_tags=creation_time:"
            "stream=index,codec_type,codec_name,width,height,r_frame_rate,avg_frame_rate,"
            "sample_rate,channels,duration:stream_tags=creation_time",
            "-of", "json", "-i", str(io_path(path))]
    result = bounded_run(args, timeout, limit)
    if result["status"] != "ok":
        return {"status": result["status"]}
    try:
        data = json.loads(result["stdout"], parse_constant=reject_constant)
    except (ValueError, UnicodeError, RecursionError):
        return {"status": "malformed_json"}
    if (not isinstance(data, dict) or not isinstance(data.get("streams"), list)
            or not isinstance(data.get("format"), dict)
            or any(not isinstance(s, dict) for s in data["streams"])):
        return {"status": "malformed_json"}
    return {"status": "ok", "data": data}


def decode(path, executable, timeout=120, limit=2097152):
    if not executable:
        return {"status": "missing"}
    return bounded_run(
        [executable, "-nostdin", "-v", "error", "-xerror", "-max_alloc", "67108864",
         "-protocol_whitelist", "file", "-threads", "1", "-filter_threads", "1",
         "-filter_complex_threads", "1", "-i", str(io_path(path)),
         "-map", "0:v?", "-map", "0:a?", "-threads", "1", "-f", "null", "-"],
        timeout, limit)


# scanner.py
"""Streaming discovery with explicit traversal failures and safe symlink defaults."""

import fnmatch
import os
import stat



def selected(path, root, cfg):
    relative = path.relative_to(root).as_posix()
    # fnmatchcase preserves case-sensitive include/exclude behavior everywhere.
    matches = lambda p: fnmatch.fnmatchcase(relative, p)
    return (path.suffix.lower() in cfg["extensions"] and
            any(matches(p) for p in cfg["include"]) and
            not any(matches(p) for p in cfg["exclude"]))


def walk(target, cfg):
    """Yield (candidate Path, None) or (None, event); memory scales with depth.

    Opt-in symlink following additionally retains directory identities for cycle
    prevention. Excludes filter files, not directories (so patterns are uniform).
    """
    target = absolute(target)
    try:
        info = io_path(target).stat(follow_symlinks=False)
        if (stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)) and not cfg["follow_symlinks"]:
            yield None, issue(target, "FS_SYMLINK", "info", "Symlink skipped; opt in to follow root-contained links.")
            return
        is_directory = io_path(target).is_dir()
        root = target if is_directory else target.parent
        boundary = resolved(root)
        if not is_directory:
            if not resolved(target).is_relative_to(boundary):
                yield None, issue(target, "FS_SYMLINK", "info", "Link outside the scan root was skipped.")
            elif not io_path(target).is_file():
                yield None, issue(target, "FS_READ", "inconclusive", "Target is not a readable regular file.")
            elif selected(target, root, cfg):
                yield target, None
            return
    except (OSError, ValueError, RuntimeError):
        yield None, issue(target, "FS_READ", "inconclusive", "Cannot inspect the scan target; check its existence and permissions.")
        return
    stack = []
    seen = set()

    def enter(directory):
        if cfg["follow_symlinks"]:
            destination = resolved(directory)
            if not destination.is_relative_to(boundary):
                return issue(directory, "FS_SYMLINK", "info", "Link outside the scan root was skipped.")
            st = io_path(directory).stat()
            identity = (st.st_dev, st.st_ino)
            if identity in seen:
                return issue(directory, "FS_SYMLINK", "info", "Repeated directory or symlink cycle was skipped.")
            seen.add(identity)
        stack.append(os.scandir(io_path(directory)))
        return None

    try:
        event = enter(target)
        if event:
            yield None, event
        while stack:
            try:
                entry = next(stack[-1])
            except StopIteration:
                stack.pop().close()
                continue
            except OSError:
                yield None, issue(target, "FS_READ", "inconclusive", "Directory enumeration failed; scan is incomplete.")
                stack.pop().close()
                continue
            path = display_path(entry.path)
            try:
                # Windows junctions/reparse points are links for traversal safety.
                is_link = entry.is_symlink() or bool(getattr(entry.stat(follow_symlinks=False), "st_file_attributes", 0) & 0x400)
                if is_link and not cfg["follow_symlinks"]:
                    yield None, issue(path, "FS_SYMLINK", "info", "Symlink or reparse point skipped by default.")
                    continue
                if is_link and not resolved(path).is_relative_to(boundary):
                    yield None, issue(path, "FS_SYMLINK", "info", "Link outside the scan root was skipped.")
                    continue
                if entry.is_dir(follow_symlinks=cfg["follow_symlinks"]):
                    if len(stack) >= 256:
                        yield None, issue(path, "FS_DEPTH", "inconclusive", "Traversal depth exceeded 256; scan this subtree separately.")
                        continue
                    event = enter(path)
                    if event:
                        yield None, event
                elif entry.is_file(follow_symlinks=cfg["follow_symlinks"]) and selected(path, root, cfg):
                    yield path, None
                elif is_link:
                    yield None, issue(path, "FS_READ", "inconclusive", "Link target is missing or unsupported.")
            except (OSError, ValueError, RuntimeError):
                yield None, issue(path, "FS_READ", "inconclusive", "Cannot inspect this entry; check permissions and link target.")
    except (OSError, ValueError, RuntimeError):
        yield None, issue(target, "FS_READ", "inconclusive", "Cannot open the directory; scan is incomplete.")
    finally:
        for iterator in stack:
            iterator.close()


# rules.py
"""Evidence-based checks. Heuristics never assert original capture time or health."""

import math
import os
import re
import stat
from datetime import datetime, timezone
from fractions import Fraction


CONTAINERS = {
    ".mp4": {"mov", "mp4"}, ".mov": {"mov", "mp4"}, ".m4v": {"mov", "mp4"},
    ".m4a": {"mov", "mp4"}, ".mkv": {"matroska", "webm"}, ".webm": {"matroska", "webm"},
    ".avi": {"avi"}, ".mts": {"mpegts"}, ".m2ts": {"mpegts"}, ".mp3": {"mp3"},
    ".aac": {"aac"}, ".wav": {"wav"}, ".flac": {"flac"}, ".ogg": {"ogg"}, ".opus": {"ogg"},
}
RULES = {
    "CONTAINER_EXTENSION": "Container family vs extension; shared demuxer aliases are accepted (not strict brand validation).",
    "CONTAINER_CODEC": "WebM filename with a reported codec outside VP8/VP9/AV1 or Vorbis/Opus; verify intended container profile.",
    "STREAMS_MISSING": "No audio/video streams described; unsupported contents or incomplete metadata.",
    "METADATA_MALFORMED": "Missing/invalid container, stream codec, dimensions, sample rate, channels, duration or rational frame rate.",
    "FPS_UNUSUAL": "Frame rate outside configured min/max (default 1..120 fps); heuristic only.",
    "VFR_INDICATION": "Different positive average and nominal frame rates (relative difference >0.1%); possible VFR, not proof.",
    "TIMESTAMP_MISSING": "No embedded creation timestamp when timestamp checks are enabled.",
    "TIMESTAMP_MALFORMED": "An explicitly configured timestamp source cannot be parsed.",
    "TIMESTAMP_NAIVE": "Naive date has no configured timezone; comparison withheld.",
    "TIMESTAMP_DIFFERENCE": "Available instants differ by more than configured tolerance (default 300 s); heuristic.",
    "TIMESTAMP_UNAVAILABLE": "Requested filesystem birth time is unavailable; ctime is never substituted.",
    "COMPANION_MISSING": "Configured companion is absent: warning if required, info if optional.",
    "COMPANION_UNAVAILABLE": "Companion could not be checked safely or access failed.",
    "GROUP_DIFFERENCE": "Configured fields differ between matching peers in the same directory; heuristic.",
    "GROUP_INCONCLUSIVE": "Peer probing, metadata, permissions or configured peer cap prevented complete comparison.",
    "PROBE_UNAVAILABLE": "ffprobe missing or could not launch; filesystem checks still run.",
    "PROBE_FAILED": "Probe exited nonzero; unsupported, unreadable or damaged media cannot be distinguished.",
    "PROBE_TIMEOUT": "Probe exceeded configured wall time; no integrity conclusion.",
    "PROBE_OUTPUT_LIMIT": "Probe exceeded bounded output; metadata cannot be assessed.",
    "PROBE_MALFORMED": "Probe response was not valid expected JSON.",
    "FS_READ": "Filesystem access or inspection failed; scan incomplete.",
    "FS_DEPTH": "Traversal exceeded safety depth 256; scan incomplete.",
    "FS_SYMLINK": "Link, cycle, junction or out-of-root target skipped by traversal policy.",
    "DRY_RUN": "Candidate enumerated; no metadata probe or companion audit performed.",
    "DECODE_RESULT": "Opt-in bounded audio/video decode result; cannot establish full integrity.",
}


def number(value):
    try:
        if isinstance(value, bool):
            return None
        result = float(value)
        return result if math.isfinite(result) else None
    except (ValueError, TypeError, OverflowError):
        return None


def rational(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d+/\d+", value):
        return None
    try:
        rate = Fraction(value)
        return rate if rate > 0 else None
    except (ValueError, ZeroDivisionError):
        return None


def metadata_checks(path, data, cfg):
    findings = []
    summary = {"streams": []}

    def malformed(actual, expected, origin):
        findings.append(finding("METADATA_MALFORMED", "warning", actual, expected,
                                origin, "Required metadata is missing or invalid; inspect this field with a media tool.", "verified"))

    fmt = data["format"]
    container = fmt.get("format_name")
    summary["container"] = container if isinstance(container, str) else None
    if not isinstance(container, str) or not container:
        malformed(container, "nonempty container format_name", "ffprobe.format.format_name")
    elif path.suffix.lower() in CONTAINERS and not set(container.split(",")) & CONTAINERS[path.suffix.lower()]:
        findings.append(finding("CONTAINER_EXTENSION", "warning", container, sorted(CONTAINERS[path.suffix.lower()]),
                                "ffprobe.format.format_name + filename suffix",
                                "Reported container family conflicts with the extension; verify before renaming.", "verified"))
    duration = number(fmt.get("duration"))
    summary["duration_seconds"] = duration
    if duration is None or duration <= 0:
        malformed(fmt.get("duration"), "positive finite duration", "ffprobe.format.duration")
    media_streams = [s for s in data["streams"] if s.get("codec_type") in ("video", "audio")]
    if not media_streams:
        findings.append(finding("STREAMS_MISSING", "inconclusive", len(media_streams), "at least one audio/video stream",
                                "ffprobe.streams", "No audio/video stream was described; inspect support and file contents.", "unavailable"))
    for idx, stream in enumerate(data["streams"]):
        kind = stream.get("codec_type")
        if not isinstance(kind, str) or not kind:
            malformed(kind, "stream codec_type", f"ffprobe.streams[{idx}].codec_type")
        if kind not in ("audio", "video"):
            continue
        item = {"type": kind, "index": idx, "codec": stream.get("codec_name")}
        codec = stream.get("codec_name")
        if not isinstance(codec, str) or not codec or codec == "unknown":
            malformed(codec, "known codec_name", f"ffprobe.streams[{idx}].codec_name")
        summary.setdefault(kind + "_codec", codec)
        if (path.suffix.lower() == ".webm" and isinstance(codec, str) and
                codec not in ({"vp8", "vp9", "av1"} if kind == "video" else {"vorbis", "opus"})):
            findings.append(finding("CONTAINER_CODEC", "warning", codec,
                                    ["vp8", "vp9", "av1"] if kind == "video" else ["vorbis", "opus"],
                                    f"filename .webm + ffprobe.streams[{idx}].codec_name",
                                    "Codec conflicts with the expected WebM profile; inspect intended container and extension."))
        fields = ("width", "height") if kind == "video" else ("sample_rate", "channels")
        for key in fields:
            value = number(stream.get(key))
            item[key] = value
            summary.setdefault(key, value)
            if value is None or value <= 0 or not value.is_integer():
                malformed(stream.get(key), "positive integer", f"ffprobe.streams[{idx}].{key}")
        if "duration" in stream and (number(stream["duration"]) is None or number(stream["duration"]) <= 0):
            malformed(stream["duration"], "positive finite duration when present", f"ffprobe.streams[{idx}].duration")
        if kind == "video":
            avg, nominal = (rational(stream.get(k)) for k in ("avg_frame_rate", "r_frame_rate"))
            item["avg_frame_rate"] = stream.get("avg_frame_rate")
            item["r_frame_rate"] = stream.get("r_frame_rate")
            if avg:
                summary.setdefault("fps", str(avg))
            if avg is None or nominal is None:
                malformed([stream.get("avg_frame_rate"), stream.get("r_frame_rate")],
                          "positive numerator/denominator rationals", f"ffprobe.streams[{idx}].frame_rate")
            if avg and not cfg["unusual_fps_min"] <= avg <= cfg["unusual_fps_max"]:
                findings.append(finding("FPS_UNUSUAL", "warning", str(avg),
                                        [cfg["unusual_fps_min"], cfg["unusual_fps_max"]],
                                        f"ffprobe.streams[{idx}].avg_frame_rate", "Unusual frame rate may be intentional; verify project settings."))
            if avg and nominal and abs(avg - nominal) / nominal > Fraction(1, 1000):
                findings.append(finding("VFR_INDICATION", "info", [str(avg), str(nominal)], "similar average and nominal rates",
                                        f"ffprobe.streams[{idx}].frame_rate", "Rates differ; packet/frame analysis is needed to establish VFR."))
        summary["streams"].append(item)
    return summary, findings


def timestamp_checks(path, data, cfg):
    ts = cfg["timestamps"]
    if not ts["enabled"]:
        return []
    findings, dates = [], []

    def add(value, origin, fmt=None, zone=None):
        try:
            if not isinstance(value, str):
                raise ValueError("not a timestamp string")
            date = datetime.strptime(value, fmt) if fmt else datetime.fromisoformat(value.replace("Z", "+00:00"))
            if date.tzinfo is None:
                if zone is None:
                    findings.append(finding("TIMESTAMP_NAIVE", "inconclusive", value, "explicit naive_timezone",
                                            origin, "Timezone is unspecified; configure it before comparing this date.", "unavailable"))
                    return
                date = date.replace(tzinfo=fixed_timezone(zone))
            dates.append((origin, date.astimezone(timezone.utc)))
        except (ValueError, TypeError, OverflowError):
            findings.append(finding("TIMESTAMP_MALFORMED", "warning", value, fmt or "ISO 8601 creation_time",
                                    origin, "Cannot parse the declared date; check its format and timezone.", "verified"))

    embedded_count = 0
    for origin, source in [("ffprobe.format.tags.creation_time", data["format"])] + [
            (f"ffprobe.streams[{i}].tags.creation_time", s) for i, s in enumerate(data["streams"])]:
        tags = source.get("tags", {})
        if not isinstance(tags, dict):
            findings.append(finding("TIMESTAMP_MALFORMED", "warning", tags, "tags object", origin,
                                    "Timestamp tags are malformed; inspect metadata.", "verified"))
        elif "creation_time" in tags:
            embedded_count += 1
            add(tags["creation_time"], origin, zone=ts["naive_timezone"])
    if not embedded_count:
        findings.append(finding("TIMESTAMP_MISSING", "info", None, "optional embedded creation_time",
                                "ffprobe tags", "No embedded creation date is available; absence does not indicate corruption.", "verified"))
    if ts["filename_regex"]:
        match = re.search(ts["filename_regex"], path.name)
        if match:
            add(match.group("date"), "configured filename date", ts["filename_format"], ts["filename_timezone"])
    if ts["filesystem"]:
        try:
            st = io_path(path).stat()
            for field in ts["filesystem"]:
                value = getattr(st, "st_" + field, None)
                if value is None:
                    findings.append(finding("TIMESTAMP_UNAVAILABLE", "unsupported", None, field, "filesystem",
                                            "This filesystem/Python does not expose birth time; ctime is not a substitute.", "unavailable"))
                else:
                    dates.append(("filesystem." + field, datetime.fromtimestamp(value, timezone.utc)))
        except (OSError, ValueError, OverflowError):
            findings.append(finding("FS_READ", "inconclusive", None, "filesystem dates", "filesystem",
                                    "Cannot read the requested filesystem dates.", "unavailable"))
    # Comparing the chronological endpoints detects the full observed spread in O(n).
    if len(dates) > 1:
        earliest, latest = min(dates, key=lambda d: d[1]), max(dates, key=lambda d: d[1])
        delta = (latest[1] - earliest[1]).total_seconds()
        if delta > ts["tolerance_seconds"]:
            findings.append(finding("TIMESTAMP_DIFFERENCE", "warning", {"difference_seconds": delta,
                                    "earliest": earliest[1].isoformat(), "latest": latest[1].isoformat()},
                                    {"max_difference_seconds": ts["tolerance_seconds"]},
                                    earliest[0] + " vs " + latest[0],
                                    "Dates disagree under configured assumptions; copying/exporting can explain this. Filesystem dates are not capture dates."))
    return findings


def companion_checks(path, cfg):
    findings = []
    for c in cfg["companions"]:
        target = path.parent / c["template"].format(stem=path.stem, name=path.name, suffix=path.suffix)
        try:
            base = resolved(path.parent)
            links = [target, *list(target.parents)[:len(target.parts) - len(path.parent.parts) - 1]]
            if (not resolved(target).is_relative_to(base) or
                    (not cfg["follow_symlinks"] and any(io_path(p).is_symlink() or
                     bool(getattr(io_path(p).lstat(), "st_file_attributes", 0) & 0x400)
                     for p in links if io_path(p).exists() or io_path(p).is_symlink()))):
                findings.append(finding("COMPANION_UNAVAILABLE", "inconclusive", c["template"], c["kind"],
                                        "filesystem", "Companion crosses a disallowed link; inspect it separately.", "unavailable"))
                continue
            try:
                st = io_path(target).stat()
            except FileNotFoundError:
                st = None
            present = st is not None and (stat.S_ISREG(st.st_mode) if c["kind"] == "file" else stat.S_ISDIR(st.st_mode))
            if not present:
                findings.append(finding("COMPANION_MISSING", "warning" if c["required"] else "info", c["template"],
                                        c["kind"], "configured companion + filesystem",
                                        "Declared companion is missing or has the wrong type; verify whether it is needed.", "verified"))
        except (OSError, ValueError, RuntimeError):
            findings.append(finding("COMPANION_UNAVAILABLE", "inconclusive", c["template"], c["kind"], "filesystem",
                                    "Cannot inspect the companion; check access permissions.", "unavailable"))
    return findings


def group_checks(path, summary, cfg, probe_file, root=None):
    g = cfg["grouping"]
    if g is None:
        return []
    pattern = re.compile(g["regex"])
    match = pattern.search(path.name)
    if not match or not match.group("group"):
        return []
    findings, count = [], 0

    def incomplete():
        return finding("GROUP_INCONCLUSIVE", "inconclusive", count, g["max_peers"], "configured filename group",
                       "Comparison is incomplete due to peer limit, access, probe failure or missing fields; narrow the group.", "unavailable")

    try:
        with os.scandir(io_path(path.parent)) as entries:
            for entry in entries:
                peer = display_path(entry.path)
                m = pattern.search(entry.name)
                if peer == path or not m or m.group("group") != match.group("group") or not selected(peer, root or path.parent, cfg):
                    continue
                if count >= g["max_peers"]:
                    findings.append(incomplete())
                    break
                count += 1
                if entry.is_symlink() or bool(getattr(entry.stat(follow_symlinks=False), "st_file_attributes", 0) & 0x400):
                    findings.append(incomplete())
                    continue
                if not entry.is_file(follow_symlinks=False):
                    continue
                result = probe_file(peer)
                if result["status"] != "ok":
                    findings.append(incomplete())
                    continue
                other, _ = metadata_checks(peer, result["data"], cfg)
                actual = {key: [summary.get(key), other.get(key)] for key in g["fields"]
                          if summary.get(key) is not None and other.get(key) is not None and summary[key] != other[key]}
                if any(summary.get(k) is None or other.get(k) is None for k in g["fields"]):
                    findings.append(incomplete())
                if actual:
                    findings.append(finding("GROUP_DIFFERENCE", "warning", actual, "equal configured fields",
                                            "ffprobe + configured filename group",
                                            "Related assets have different properties; variants may be intentional."))
    except OSError:
        findings.append(incomplete())
    return findings


# report.py
"""Streaming JSONL ingestion, JSON/CSV export, summaries and conservative privacy."""

import csv
import json
from collections import Counter
from pathlib import PurePosixPath, PureWindowsPath


MAX_LINE = 8388608
SEVERITIES = ("error", "warning", "info", "unsupported", "inconclusive")
SAFE_KEYS = {"container", "duration_seconds", "streams", "video_codec", "audio_codec", "width", "height",
             "fps", "sample_rate", "channels", "type", "index", "codec", "avg_frame_rate", "r_frame_rate",
             "difference_seconds", "earliest", "latest", "max_difference_seconds"}


class ReportError(ValueError):
    pass


def header(root, mode="absolute", dry_run=False):
    return {"type": "header", "schema_version": 1, "tool_version": __version__,
            "root": str(root) if mode == "absolute" and root is not None else None,
            "path_mode": mode, "dry_run": dry_run}


def _scrub(value):
    # Metadata strings may themselves contain private paths or user identifiers.
    # Numeric evidence is retained; arbitrary textual evidence is withheld.
    if isinstance(value, str):
        return "<redacted-text>"
    if isinstance(value, list):
        return [_scrub(v) for v in value]
    if isinstance(value, dict):
        return {k if k in SAFE_KEYS else f"redacted-key-{i}": _scrub(v)
                for i, (k, v) in enumerate(value.items())}
    return value


def privatize(item, root, mode, index, source_mode="absolute"):
    if mode == "absolute":
        return item
    item = dict(item)
    if mode == "redacted" or source_mode == "redacted":
        item["path"] = f"asset-{index:06d}"
    elif source_mode == "relative":
        # Reject malicious or platform-incompatible paths in imported reports.
        value = item["path"]
        if (PureWindowsPath(value).is_absolute() or PureWindowsPath(value).drive or
                ".." in PurePosixPath(value.replace("\\", "/")).parts):
            item["path"] = "<outside-root>"
    else:
        try:
            flavor = PureWindowsPath if PureWindowsPath(root).is_absolute() else PurePosixPath
            item["path"] = flavor(item["path"]).relative_to(flavor(root)).as_posix()
        except (ValueError, TypeError):
            item["path"] = "<outside-root>"
    item["metadata"] = _scrub(item["metadata"])
    item["findings"] = [{**f, "actual": _scrub(f["actual"]), "expected": _scrub(f["expected"]),
                         "provenance": "sanitized evidence", "explanation": RULES[f["rule_id"]]}
                        for f in item["findings"]]
    return item


def write_line(handle, item):
    handle.write(json.dumps(item, ensure_ascii=True, allow_nan=False) + "\n")
    handle.flush()


def read_records(path):
    try:
        with open(io_path(path), encoding="utf-8") as handle:
            first = handle.readline(MAX_LINE + 1)
            if len(first) > MAX_LINE:
                raise ReportError("report header exceeds 8 MiB")
            head = json.loads(first, parse_constant=reject_constant)
            if (not isinstance(head, dict) or head.get("type") != "header" or
                    type(head.get("schema_version")) is not int or head["schema_version"] != 1 or
                    head.get("path_mode") not in ("absolute", "relative", "redacted") or
                    type(head.get("dry_run")) is not bool or
                    (head.get("root") is not None and not isinstance(head["root"], str))):
                raise ReportError("expected a version 1 scan JSONL file from this tool; use the saved scan output")
            yield head
            count = 0
            complete = False
            while True:
                line = handle.readline(MAX_LINE + 1)
                if not line:
                    break
                if len(line) > MAX_LINE:
                    raise ReportError("report record exceeds 8 MiB")
                item = json.loads(line, parse_constant=reject_constant)
                if isinstance(item, dict) and item.get("type") == "complete":
                    if type(item.get("records")) is not int or item["records"] != count or handle.read(1):
                        raise ReportError("scan output has an invalid end marker or extra content after it")
                    complete = True
                    break
                if (not isinstance(item, dict) or item.get("type") not in ("file", "event") or
                        not isinstance(item.get("path"), str) or not isinstance(item.get("metadata"), dict) or
                        not isinstance(item.get("findings"), list)):
                    raise ReportError("invalid scan record")
                for f in item["findings"]:
                    if (not isinstance(f, dict) or not isinstance(f.get("rule_id"), str) or f["rule_id"] not in RULES or
                            f.get("severity") not in SEVERITIES or f.get("evidence") not in ("verified", "heuristic", "unavailable") or
                            set(f) != {"rule_id", "severity", "evidence", "actual", "expected", "provenance", "explanation"} or
                            not isinstance(f["provenance"], str) or not isinstance(f["explanation"], str)):
                        raise ReportError("invalid finding")
                count += 1
                yield {k: item[k] for k in ("type", "path", "metadata", "findings")}
            if not complete:
                raise ReportError("scan output is incomplete: its end marker is missing; finish a new scan before exporting it")
    except (OSError, ValueError, TypeError, RecursionError) as exc:
        raise ReportError(f"cannot read scan report: {exc}") from exc


class Summary:
    def __init__(self, fail_on="warning"):
        self.files = 0
        self.events = 0
        self.counts = Counter()
        self.fail_on = fail_on

    def add(self, item):
        self.files += item["type"] == "file"
        self.events += item["type"] == "event"
        self.counts.update(f["severity"] for f in item["findings"])

    def exit_code(self):
        if self.counts["unsupported"] or self.counts["inconclusive"]:
            return 3
        levels = {"error": {"error"}, "warning": {"error", "warning"},
                  "info": {"error", "warning", "info"}, "none": set()}
        return int(any(self.counts[s] for s in levels[self.fail_on]))

    def text(self):
        counts = ", ".join(f"{s}={self.counts[s]}" for s in SEVERITIES)
        return (f"Scanned {self.files} file(s); {self.events} file-access notice(s). {counts}.\n"
                "These checks cannot prove that every part of a media file is intact.")


def open_new(path):
    return open(io_path(path), "x", encoding="utf-8", newline="")


def export(source, json_handle=None, csv_handle=None, mode="redacted", fail_on="warning"):
    records = read_records(source)
    head = next(records)
    # A sanitized report cannot be expanded back into an absolute/private report.
    effective = "redacted" if head["path_mode"] == "redacted" else mode
    if head["path_mode"] == "relative" and mode == "absolute":
        effective = "relative"
    out_head = header(head.get("root"), effective, head.get("dry_run", False))
    summary = Summary(fail_on)
    writer = None
    if json_handle:
        json_handle.write('{"header":' + json.dumps(out_head) + ',"records":[')
    if csv_handle:
        writer = csv.writer(csv_handle)
        writer.writerow(["path", "type", "rule_id", "severity", "evidence", "actual", "expected", "provenance", "explanation"])
    for i, item in enumerate(records, 1):
        summary.add(item)
        item = privatize(item, head.get("root"), effective, i, head["path_mode"])
        if json_handle:
            if i > 1:
                json_handle.write(",")
            json.dump(item, json_handle, ensure_ascii=True, allow_nan=False)
        if writer:
            for f in item["findings"] or [None]:
                # Neutralize formula injection when CSV is opened by a spreadsheet.
                cells = [item["path"], item["type"]] + ([f["rule_id"], f["severity"], f["evidence"],
                         json.dumps(f["actual"], ensure_ascii=True), json.dumps(f["expected"], ensure_ascii=True),
                         f["provenance"], f["explanation"]] if f else [""] * 7)
                writer.writerow(["'" + str(c) if str(c).lstrip().startswith(("=", "+", "-", "@"))
                                 or str(c).startswith(("\t", "\r", "\n")) else c for c in cells])
    if json_handle:
        json_handle.write('],"summary":' + json.dumps({"files": summary.files, "events": summary.events,
                                                     "findings": dict(summary.counts)}) + "}\n")
    return summary


# cli.py
"""Command-line orchestration; all media access is read-only."""

import argparse
import json
import sys
from contextlib import ExitStack
from pathlib import Path


FAILURES = {
    "missing": ("PROBE_UNAVAILABLE", "unsupported", "ffprobe is not installed/discoverable; install it manually for metadata checks."),
    "launch_error": ("PROBE_UNAVAILABLE", "unsupported", "Cannot launch ffprobe; check the executable and permissions."),
    "nonzero": ("PROBE_FAILED", "inconclusive", "Probe failed; unsupported, unreadable or damaged media are possible. Inspect locally."),
    "diagnostic": ("PROBE_FAILED", "inconclusive", "Probe emitted error diagnostics despite returning zero; inspect the media locally."),
    "timeout": ("PROBE_TIMEOUT", "inconclusive", "Probe exceeded its time budget; inspect locally or explicitly increase the timeout."),
    "output_limit": ("PROBE_OUTPUT_LIMIT", "inconclusive", "Probe output exceeded the byte cap; inspect locally or raise the configured limit."),
    "malformed_json": ("PROBE_MALFORMED", "inconclusive", "Probe returned malformed metadata; verify the executable and inspect locally."),
}


def parser():
    p = argparse.ArgumentParser(
        prog="media-metadata-checker",
        description="Check local media metadata and companion files without changing your media.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples (use .\\ before BAT commands in PowerShell):
  media-metadata-checker.bat scan "./media" --dry-run
  media-metadata-checker.bat scan "./media" --path-mode redacted --output "../audit.jsonl"
  media-metadata-checker.bat report "../audit.jsonl" --json "audit.json" --csv "audit.csv"
  media-metadata-checker.bat help scan

Python 3.11+ is required. Metadata checks need trusted ffprobe on PATH;
deep-decode needs ffmpeg. Dry runs need neither. Nothing downloads itself.
Media is unchanged; existing output files are never overwritten. Review findings
and paths before sharing reports. No telemetry or uploads.
Exit codes: 0 success/dry run; 1 threshold findings; 2 input/output error;
3 incomplete checks (takes precedence over 1); 130 interrupted.""")
    p.add_argument("--version", action="version", version=__version__)
    commands = p.add_subparsers(dest="command", required=True)
    for name in ("scan", "deep-decode"):
        deep = name == "deep-decode"
        s = commands.add_parser(
            name,
            help="check media metadata and companion files" if not deep else "check audio/video by decoding it; can be slow",
            description="Read audio/video with ffmpeg to check decoding; media files are not changed." if deep else "Check a media file or folder with ffprobe; media files are not changed.",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=("Requires trusted ffmpeg on PATH and --acknowledge-cost (except --dry-run).\n"
                    "Decoding can use substantial CPU and disk activity; success is not proof of full integrity.\n"
                    'Example: media-metadata-checker.bat deep-decode "./media" --acknowledge-cost\n') if deep else
                   ('Example: media-metadata-checker.bat scan "./media" --dry-run\n'
                    'Use --path-mode redacted to hide source paths and filenames.\n'
                    'Requires trusted ffprobe on PATH for metadata checks; --dry-run needs no external tools.\n'))
        s.add_argument("path", type=Path, help="media file or folder to check")
        s.add_argument("--config", type=Path, help="JSON settings file; use rules --defaults for a template")
        s.add_argument("--output", type=Path, help="new JSONL file outside the scan folder; default: console output")
        s.add_argument("--include", action="append", help="case-sensitive filename pattern relative to the scan folder, e.g. *.mp4; repeat to replace configured includes")
        s.add_argument("--exclude", action="append", help="case-sensitive relative filename pattern to exclude; repeat to add exclusions")
        s.add_argument("--extensions", help="comma-separated file extensions including dots, e.g. .mp4,.wav")
        s.add_argument("--follow-symlinks", action="store_true", default=None, help="follow links within the scan folder only; links are skipped unless enabled here or in settings")
        s.add_argument("--dry-run", action="store_true", help="list candidates without checking metadata, companions or decoding")
        s.add_argument("--path-mode", choices=("absolute", "relative", "redacted"), default="absolute", help="how source paths appear in results; default: absolute (redacted hides names)")
        s.add_argument("--fail-on", choices=("error", "warning", "info", "none"), help="lowest finding severity that returns exit 1; default: warning unless configured; none disables the threshold")
        s.add_argument("--timeout", type=float, help="seconds allowed per file, 0.1-3600; default: 120 for decoding" if deep else "seconds allowed per metadata check, 0.1-3600; default: 20 unless configured")
        if name == "deep-decode":
            s.add_argument("--acknowledge-cost", action="store_true", help="allow CPU- and disk-intensive decoding for this run")
    r = commands.add_parser("report", help="convert saved scan results to JSON/CSV", description="Read completed scan JSONL and export a report. Source media is not opened.", formatter_class=argparse.RawDescriptionHelpFormatter,
                            epilog='Example: media-metadata-checker.bat report "../audit.jsonl" --json "audit.json"\nExisting output files are never overwritten. Review exported paths before sharing.')
    r.add_argument("input", type=Path, help="completed JSONL file from scan or deep-decode")
    r.add_argument("--json", type=Path, help="new JSON report file")
    r.add_argument("--csv", type=Path, help="new CSV report file")
    r.add_argument("--path-mode", choices=("absolute", "relative", "redacted"), default="redacted", help="how paths appear in exports; default: redacted; hidden paths cannot be restored")
    r.add_argument("--fail-on", choices=("error", "warning", "info", "none"), default="warning", help="lowest finding severity that returns exit 1; default: warning; none disables the threshold")
    r = commands.add_parser("rules", help="explain findings or print default settings", description="Explain report findings or print a JSON settings template.")
    r.add_argument("--defaults", action="store_true", help="print default JSON settings instead of rule descriptions")
    h = commands.add_parser("help", help="show general or command-specific help")
    h.add_argument("topic", nargs="?", choices=("scan", "report", "rules", "deep-decode"), help="command to explain; omit for general help")
    return p


def _scan(args):
    cfg = load(args.config)
    for key in ("include", "extensions", "follow_symlinks", "fail_on"):
        value = getattr(args, key)
        if value is not None:
            cfg[key] = value.split(",") if key == "extensions" else value
    if args.exclude:
        cfg["exclude"].extend(args.exclude)
    if args.timeout is not None:
        cfg["probe_timeout"] = args.timeout
    cfg = validate(cfg)
    deep = args.command == "deep-decode"
    if deep and not args.dry_run and not args.acknowledge_cost:
        raise ConfigError("deep-decode requires --acknowledge-cost because it can use substantial CPU and disk activity; use --dry-run to list files first")
    target = absolute(args.path)
    root = target if io_path(target).is_dir() else target.parent
    if args.output:
        destination = resolved(args.output)
        if destination == resolved(target) or (io_path(target).is_dir() and destination.is_relative_to(resolved(root))):
            raise ConfigError("write scan reports outside the source directory; source files must remain unchanged")
    executable = discover("ffmpeg" if deep else "ffprobe")
    summary = Summary(cfg["fail_on"])
    if deep and not args.dry_run:
        print("Checking audio/video one file at a time. This can use substantial CPU and disk activity; each file has a time limit.\n"
              "Only audio/video content is checked; success does not prove the entire file is intact.", file=sys.stderr)
    probe_file = lambda path: probe(path, executable, cfg["probe_timeout"], cfg["probe_output_limit"])
    with ExitStack() as stack:
        handle = stack.enter_context(open_new(args.output)) if args.output else sys.stdout
        write_line(handle, header(root, args.path_mode, args.dry_run))
        index = 0
        for index, (path, event) in enumerate(walk(target, cfg), 1):
            if event:
                item = event
            elif args.dry_run:
                item = record(path, [finding("DRY_RUN", "info", None, None, "discovery",
                                            "Candidate only; metadata and companions were not checked.", "unavailable")])
            elif deep:
                result = decode(path, executable, args.timeout or 120, cfg["probe_output_limit"])
                status = result["status"]
                severity = "info" if status == "ok" else "unsupported" if status in ("missing", "launch_error") else "inconclusive"
                item = record(path, [finding("DECODE_RESULT", severity, status, "ok", "ffmpeg audio/video decode",
                                            "Bounded decode finished or stopped. Review failure locally; success does not establish full integrity.",
                                            "verified" if status == "ok" else "unavailable")])
            else:
                findings = companion_checks(path, cfg)
                result = probe_file(path)
                metadata = {}
                if result["status"] == "ok":
                    metadata, observed = metadata_checks(path, result["data"], cfg)
                    findings.extend(observed)
                    findings.extend(timestamp_checks(path, result["data"], cfg))
                    findings.extend(group_checks(path, metadata, cfg, probe_file, root=root))
                else:
                    rule, severity, explanation = FAILURES[result["status"]]
                    findings.append(finding(rule, severity, result["status"], "successful local probe", "ffprobe",
                                            explanation, "unavailable"))
                item = record(path, findings, metadata)
            summary.add(item)
            write_line(handle, privatize(item, root, args.path_mode, index))
        write_line(handle, {"type": "complete", "records": index})
    print(summary.text(), file=sys.stderr)
    if args.dry_run:
        print("Dry run only: files were listed, but metadata and companion files were not checked.", file=sys.stderr)
    return summary.exit_code()


def main(argv=None):
    if sys.version_info < (3, 11):
        print("ERROR: Python 3.11 or newer is required.", file=sys.stderr)
        return 2
    p = parser()
    # Opening the entry point explains how to start. Incomplete commands still fail.
    arguments = sys.argv[1:] if argv is None else argv
    args = p.parse_args(arguments or ["help"])
    try:
        if args.command == "help":
            if args.topic:
                # Use the same parser, so help cannot drift from executable options.
                p.parse_args([args.topic, "--help"])
            else:
                p.print_help()

            return 0
        if args.command == "rules":
            if args.defaults:
                print(json.dumps(DEFAULTS, indent=2))
            else:
                for rule, description in RULES.items():
                    print(f"{rule}: {description}")
            return 0
        if args.command in ("scan", "deep-decode"):
            return _scan(args)
        with ExitStack() as stack:
            json_handle = stack.enter_context(open_new(args.json)) if args.json else None
            csv_handle = stack.enter_context(open_new(args.csv)) if args.csv else None
            summary = export(args.input, json_handle, csv_handle, args.path_mode, args.fail_on)
        print(summary.text())
        return summary.exit_code()
    except (ConfigError, ReportError, OSError, ValueError, RecursionError) as exc:
        # Do not echo raw probe stderr (it can contain private paths and metadata).
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Interrupted; any report is partial.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
