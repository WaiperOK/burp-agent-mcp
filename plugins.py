"""Burp extensions written by the model: source checks, compilation, and a record of what was compiled.

The model may write a Burp extension (Montoya API) and compile it. Nothing here loads it into Burp: Burp only
loads a jar that a person adds in Extensions. Compiling runs javac and jar with fixed arguments and never runs
the extension's code.

The checks below are a review aid, not a sandbox. The control is the person who reads the source before loading
the jar. Each compiled jar records the hash of the source it was built from, so a jar that no longer matches its
source is visible.
"""

import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

NAME_RE = re.compile(r"^[a-z][a-z0-9_]{2,39}$")
MAX_SOURCE_BYTES = 40_000
MAX_OUTPUT_CHARS = 2000
COMPILE_TIMEOUT_S = 60
ENTRY_RE = re.compile(r"public\s+class\s+Plugin\s+implements\s+BurpExtension\b")
PACKAGE_RE = re.compile(r"^\s*package\s", re.MULTILINE)
INIT_RE = re.compile(r"\binitialize\s*\(\s*MontoyaApi\b")

# Refused. Traffic from a plugin must go through Burp's own API, where it is visible in Burp. A raw socket or a
# started process would bypass the gateway's scope and audit, so neither is allowed.
DENIED = (
    (re.compile(r"\bProcessBuilder\b|\bRuntime\s*\.\s*getRuntime\b"), "starts processes"),
    (re.compile(r"\bjava\.net\.(Socket|ServerSocket|HttpURLConnection|URLConnection|DatagramSocket)\b"
                r"|\bnew\s+(Socket|ServerSocket|HttpURLConnection)\s*\("), "opens raw network connections"),
    (re.compile(r"\bjava\.lang\.reflect\b|\bClassLoader\b|\bMethodHandles\b"), "loads or calls code dynamically"),
    (re.compile(r"\bSystem\s*\.\s*exit\b"), "stops Burp"),
)

# Reported for review, not refused: file, environment and network-class use is normal in some plugins.
REVIEW = (
    (re.compile(r"\bjava\.io\.File\b|\bjava\.nio\.file\.Files\b|\bFileWriter\b|\bFileOutputStream\b"), "touches files"),
    (re.compile(r"\bgetenv\b|\bgetProperty\b"), "reads environment or system properties"),
    (re.compile(r"\bjava\.net\.(HttpClient|URL)\b"), "uses network classes"),
)


def valid_name(name: str) -> bool:
    return bool(NAME_RE.fullmatch(name or ""))


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def check_source(source: str) -> dict:
    """Returns {"errors": [...], "warnings": [...]}. Errors refuse the source; warnings are shown for review."""
    errors, warnings = [], []
    if len(source.encode("utf-8")) > MAX_SOURCE_BYTES:
        errors.append(f"source is larger than {MAX_SOURCE_BYTES} bytes")
    if not ENTRY_RE.search(source):
        errors.append("the source needs `public class Plugin implements BurpExtension`")
    if not INIT_RE.search(source):
        errors.append("the source needs `initialize(MontoyaApi api)`")
    if PACKAGE_RE.search(source):
        errors.append("no package statement: the plugin must be in the default package")
    for pattern, reason in DENIED:
        if pattern.search(source):
            errors.append(f"refused: the plugin {reason}")
    for pattern, reason in REVIEW:
        if pattern.search(source):
            warnings.append(f"review: the plugin {reason}")
    return {"errors": errors, "warnings": warnings}


def plugin_dir(root: Path, name: str) -> Path:
    """The folder of one plugin. The name is checked here, so no name can point outside the plugins folder."""
    if not valid_name(name):
        raise ValueError("plugin name must be 3-40 characters: lower-case letters, digits, underscore")
    return root / name


def write_source(root: Path, name: str, source: str) -> dict:
    """Writes Plugin.java for the plugin. An earlier compiled jar is removed, so only a fresh build can be loaded."""
    checked = check_source(source)
    if checked["errors"]:
        return {"error": "; ".join(checked["errors"])}
    folder = plugin_dir(root, name)
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "Plugin.java").write_text(source, encoding="utf-8")
    for stale in (folder / f"{name}.jar", folder / "build.json"):
        stale.unlink(missing_ok=True)
    shutil.rmtree(folder / "build", ignore_errors=True)
    return {"name": name, "source_sha256": sha256_text(source), "warnings": checked["warnings"],
            "compiled": False}


def compile_plugin(root: Path, name: str, burp_jar: Path) -> dict:
    """Compiles the source against Burp's jar into <name>.jar. Runs javac and jar only; the plugin is not executed."""
    folder = plugin_dir(root, name)
    source_path = folder / "Plugin.java"
    if not source_path.is_file():
        return {"error": "no source for this plugin: write it with plugin_write first"}
    if not burp_jar.is_file():
        return {"error": f"Burp jar not found at {burp_jar}: set BURP_JAR to the path of burpsuite.jar"}
    source = source_path.read_text(encoding="utf-8")
    checked = check_source(source)  # the file may have been edited by hand since it was written
    if checked["errors"]:
        return {"error": "; ".join(checked["errors"])}

    build = folder / "build"
    shutil.rmtree(build, ignore_errors=True)
    build.mkdir()
    # -implicit:none and an empty -sourcepath: Burp's jar contains API sources, and without these flags javac
    # would also write their classes into the plugin's build
    javac = _run(["javac", "-proc:none", "-nowarn", "-implicit:none", "-sourcepath", "",
                  "-cp", str(burp_jar), "-d", str(build), str(source_path)])
    if javac.returncode != 0:
        return {"error": "compilation failed", "output": _clip(javac.stdout + javac.stderr)}
    extra = [p.name for p in build.rglob("*.class") if not p.name.startswith("Plugin")]
    if extra:  # the jar must contain the plugin only, never another library's classes
        shutil.rmtree(build, ignore_errors=True)
        return {"error": "refused: the build contains classes other than the plugin", "output": _clip(", ".join(extra))}
    jar_path = folder / f"{name}.jar"
    jar = _run(["jar", "cf", str(jar_path), "-C", str(build), "."])
    if jar.returncode != 0:
        return {"error": "packaging failed", "output": _clip(jar.stdout + jar.stderr)}
    shutil.rmtree(build, ignore_errors=True)

    jar_sha = hashlib.sha256(jar_path.read_bytes()).hexdigest()
    source_sha = sha256_text(source)
    (folder / "build.json").write_text(json.dumps({"source_sha256": source_sha, "jar_sha256": jar_sha}),
                                       encoding="utf-8")
    return {"name": name, "jar": str(jar_path), "source_sha256": source_sha, "jar_sha256": jar_sha,
            "warnings": checked["warnings"], "compiled": True}


def status(root: Path, name: str) -> dict:
    """Source and jar state. up_to_date is True only when the jar was built from the current source."""
    folder = plugin_dir(root, name)
    source_path = folder / "Plugin.java"
    if not source_path.is_file():
        return {"name": name, "source": False, "compiled": False, "up_to_date": False}
    source_sha = sha256_text(source_path.read_text(encoding="utf-8"))
    jar_path = folder / f"{name}.jar"
    recorded = {}
    if (folder / "build.json").is_file():
        recorded = json.loads((folder / "build.json").read_text(encoding="utf-8"))
    compiled = jar_path.is_file() and recorded.get("source_sha256") == source_sha
    return {"name": name, "source": True, "source_sha256": source_sha, "compiled": jar_path.is_file(),
            "up_to_date": compiled, "jar": str(jar_path) if jar_path.is_file() else None}


def list_plugins(root: Path) -> list[dict]:
    if not root.is_dir():
        return []
    return [status(root, p.name) for p in sorted(root.iterdir()) if p.is_dir() and valid_name(p.name)]


def _run(argv: list[str]) -> subprocess.CompletedProcess:
    # fixed program and arguments, no shell: the model supplies only the source text, never a command
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=COMPILE_TIMEOUT_S, check=False)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(argv, 1, "", f"timed out after {COMPILE_TIMEOUT_S} s")
    except OSError as ex:  # for example, javac or jar is not installed
        return subprocess.CompletedProcess(argv, 1, "", f"cannot run {argv[0]}: {ex}")


def _clip(text: str) -> str:
    return text[:MAX_OUTPUT_CHARS]
