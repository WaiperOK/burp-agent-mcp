"""Tests for the harness's model settings: which key, address and model it uses. Run: python tests/test_harness.py"""

import os
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from deepseek_agent import DEEPSEEK_URL, load_llm_settings  # noqa: E402


class LlmSettingsTests(unittest.TestCase):
    def test_deepseek_names_still_work_with_deepseek_defaults(self):
        self.assertEqual(load_llm_settings({"DEEPSEEK_API_KEY": "k"}), ("k", DEEPSEEK_URL, "deepseek-chat"))

    def test_llm_names_win_over_deepseek_names(self):
        env = {"LLM_API_KEY": "a", "DEEPSEEK_API_KEY": "b", "LLM_MODEL": "m", "DEEPSEEK_MODEL": "x"}
        self.assertEqual(load_llm_settings(env), ("a", DEEPSEEK_URL, "m"))

    def test_local_server_needs_its_own_model_name(self):
        # a local Ollama or LM Studio must not get the DeepSeek model name by default
        key, base, model = load_llm_settings({"LLM_API_KEY": "k", "LLM_BASE_URL": "http://localhost:11434/v1"})
        self.assertEqual((key, base, model), ("k", "http://localhost:11434/v1", ""))

    def test_trailing_slash_on_the_deepseek_address_keeps_the_default_model(self):
        self.assertEqual(load_llm_settings({"LLM_BASE_URL": DEEPSEEK_URL + "/"})[2], "deepseek-chat")

    def test_nothing_set_gives_no_key(self):
        self.assertEqual(load_llm_settings({})[0], "")


class StartupTests(unittest.TestCase):
    """The harness refuses to start without its settings, and says which one is missing. No model is called."""

    HARNESS = Path(__file__).resolve().parent.parent / "deepseek_agent.py"

    def _run(self, **env):
        clean = {"PATH": os.environ.get("PATH", "")}  # no key, model or policy from the machine running the tests
        return subprocess.run([sys.executable, str(self.HARNESS)], env={**clean, **env},
                              capture_output=True, text=True, timeout=60)

    def test_missing_key_is_reported(self):
        out = self._run(BURP_AGENT_POLICY="/nonexistent.json")
        self.assertEqual(out.returncode, 1)
        self.assertIn("LLM_API_KEY is not set", out.stderr)

    def test_other_address_without_a_model_is_reported(self):
        out = self._run(LLM_API_KEY="k", LLM_BASE_URL="http://localhost:11434/v1", BURP_AGENT_POLICY="/nonexistent.json")
        self.assertEqual(out.returncode, 1)
        self.assertIn("LLM_MODEL is not set", out.stderr)

    def test_missing_policy_is_reported(self):
        out = self._run(LLM_API_KEY="k")
        self.assertEqual(out.returncode, 1)
        self.assertIn("BURP_AGENT_POLICY is not set", out.stderr)


if __name__ == "__main__":
    unittest.main()
