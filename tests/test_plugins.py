"""Tests for plugins.py: source checks, writing, compiling against a stub Burp jar, and the up-to-date check.

The compile tests build a small stub of Burp's Montoya interfaces, so they need javac and jar but not Burp.
Run: python tests/test_plugins.py
"""

import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import plugins  # noqa: E402

HAS_JDK = bool(shutil.which("javac") and shutil.which("jar"))

VALID = """import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public class Plugin implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
    }
}
"""


def with_body(line: str) -> str:
    """VALID with one statement inside initialize()."""
    return VALID.replace("    public void initialize(MontoyaApi api) {\n    }",
                         "    public void initialize(MontoyaApi api) {\n        " + line + "\n    }")

STUB = {
    "burp/api/montoya/MontoyaApi.java": "package burp.api.montoya;\npublic interface MontoyaApi {}\n",
    "burp/api/montoya/BurpExtension.java":
        "package burp.api.montoya;\npublic interface BurpExtension { void initialize(MontoyaApi api); }\n",
}


def make_stub_jar(tmp: Path) -> Path:
    """Builds a jar with Burp's interface names, so the plugin compiles against it."""
    src, classes = tmp / "stub-src", tmp / "stub-classes"
    for rel, text in STUB.items():
        (src / rel).parent.mkdir(parents=True, exist_ok=True)
        (src / rel).write_text(text, encoding="utf-8")
    classes.mkdir()
    files = [str(src / rel) for rel in STUB]
    subprocess.run(["javac", "-d", str(classes), *files], check=True, capture_output=True)
    jar = tmp / "burpsuite-stub.jar"
    # like the real burpsuite.jar, the stub also carries its sources: javac must not compile them into the plugin
    subprocess.run(["jar", "cf", str(jar), "-C", str(classes), ".", "-C", str(src), "."],
                   check=True, capture_output=True)
    return jar


class CheckSourceTests(unittest.TestCase):
    def test_valid_source_passes(self):
        self.assertEqual(plugins.check_source(VALID), {"errors": [], "warnings": []})

    def test_entry_point_and_init_are_required(self):
        self.assertTrue(plugins.check_source("class Other {}")["errors"])
        no_init = VALID.replace("initialize(MontoyaApi api)", "start(MontoyaApi api)")
        self.assertTrue(any("initialize" in e for e in plugins.check_source(no_init)["errors"]))

    def test_package_statement_is_refused(self):
        errors = plugins.check_source("package x;\n" + VALID)["errors"]
        self.assertTrue(any("default package" in e for e in errors))

    def test_process_and_raw_socket_are_refused(self):
        for line in ("Runtime.getRuntime().exec(\"id\");", "new ProcessBuilder(\"id\");",
                     "java.net.Socket s = null;", "new Socket(\"h\", 1);"):
            with self.subTest(line=line):
                self.assertTrue(plugins.check_source(with_body(line))["errors"])

    def test_dynamic_loading_is_refused(self):
        errors = plugins.check_source(VALID.replace("import burp.api.montoya.MontoyaApi;",
                                                    "import burp.api.montoya.MontoyaApi;\nimport java.lang.reflect.Method;"))["errors"]
        self.assertTrue(any("dynamically" in e for e in errors))

    def test_file_and_environment_use_is_only_reported(self):
        out = plugins.check_source(VALID.replace("import burp.api.montoya.MontoyaApi;",
                                                 "import burp.api.montoya.MontoyaApi;\nimport java.io.File;"))
        self.assertEqual(out["errors"], [])
        self.assertTrue(any("files" in w for w in out["warnings"]))

    def test_oversized_source_is_refused(self):
        self.assertTrue(plugins.check_source(VALID + "// " + "x" * plugins.MAX_SOURCE_BYTES)["errors"])


class NameTests(unittest.TestCase):
    def test_path_like_names_are_refused(self):
        root = Path("/tmp/does-not-matter")
        for bad in ("../escape", "a/b", "AB", "x", "name with space", ""):
            with self.subTest(name=bad):
                self.assertFalse(plugins.valid_name(bad))
                with self.assertRaises(ValueError):
                    plugins.plugin_dir(root, bad)


class WriteAndStatusTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name) / "plugins"

    def tearDown(self):
        self._tmp.cleanup()

    def test_write_creates_source_and_hash(self):
        out = plugins.write_source(self.root, "my_plugin", VALID)
        self.assertEqual(out["source_sha256"], plugins.sha256_text(VALID))
        self.assertTrue((self.root / "my_plugin" / "Plugin.java").is_file())
        self.assertFalse(out["compiled"])

    def test_refused_source_is_not_written(self):
        out = plugins.write_source(self.root, "my_plugin", "class Bad {}")
        self.assertIn("error", out)
        self.assertFalse((self.root / "my_plugin").exists())

    def test_list_skips_folders_with_invalid_names(self):
        plugins.write_source(self.root, "good_one", VALID)
        (self.root / "Bad Name").mkdir()
        self.assertEqual([p["name"] for p in plugins.list_plugins(self.root)], ["good_one"])

    @unittest.skipUnless(HAS_JDK, "needs javac and jar")
    def test_rewriting_removes_the_old_jar(self):
        jar = make_stub_jar(Path(self._tmp.name))
        plugins.write_source(self.root, "my_plugin", VALID)
        plugins.compile_plugin(self.root, "my_plugin", jar)
        self.assertTrue((self.root / "my_plugin" / "my_plugin.jar").is_file())
        plugins.write_source(self.root, "my_plugin", VALID + "// second version\n")
        self.assertFalse((self.root / "my_plugin" / "my_plugin.jar").exists())


@unittest.skipUnless(HAS_JDK, "needs javac and jar")
class CompileTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.root = self.tmp / "plugins"
        self.jar = make_stub_jar(self.tmp)

    def tearDown(self):
        self._tmp.cleanup()

    def test_valid_plugin_compiles_and_is_up_to_date(self):
        plugins.write_source(self.root, "my_plugin", VALID)
        out = plugins.compile_plugin(self.root, "my_plugin", self.jar)
        self.assertTrue(out["compiled"], out)
        self.assertTrue(Path(out["jar"]).is_file())
        entries = zipfile.ZipFile(out["jar"]).namelist()
        self.assertEqual([n for n in entries if n.endswith(".class")], ["Plugin.class"])  # no Burp classes inside
        self.assertFalse((self.root / "my_plugin" / "build").exists())  # intermediate files are removed
        st = plugins.status(self.root, "my_plugin")
        self.assertTrue(st["up_to_date"])

    def test_editing_the_source_after_compiling_marks_the_jar_stale(self):
        plugins.write_source(self.root, "my_plugin", VALID)
        plugins.compile_plugin(self.root, "my_plugin", self.jar)
        (self.root / "my_plugin" / "Plugin.java").write_text(VALID + "\n// changed\n", encoding="utf-8")
        st = plugins.status(self.root, "my_plugin")
        self.assertTrue(st["compiled"])
        self.assertFalse(st["up_to_date"])

    def test_compile_error_is_reported_with_javac_output(self):
        plugins.write_source(self.root, "my_plugin", VALID.replace("api) {", "api) { int x = \"no\";"))
        out = plugins.compile_plugin(self.root, "my_plugin", self.jar)
        self.assertEqual(out["error"], "compilation failed")
        self.assertIn("incompatible types", out["output"])

    def test_source_edited_by_hand_to_refused_code_is_not_compiled(self):
        plugins.write_source(self.root, "my_plugin", VALID)
        (self.root / "my_plugin" / "Plugin.java").write_text(with_body('new ProcessBuilder("id");'), encoding="utf-8")
        out = plugins.compile_plugin(self.root, "my_plugin", self.jar)
        self.assertIn("error", out)
        self.assertFalse((self.root / "my_plugin" / "my_plugin.jar").exists())

    def test_missing_burp_jar_is_reported(self):
        plugins.write_source(self.root, "my_plugin", VALID)
        out = plugins.compile_plugin(self.root, "my_plugin", self.tmp / "absent.jar")
        self.assertIn("Burp jar not found", out["error"])

    def test_no_source_means_nothing_to_compile(self):
        self.assertIn("plugin_write", plugins.compile_plugin(self.root, "ghost_one", self.jar)["error"])


if __name__ == "__main__":
    unittest.main()
