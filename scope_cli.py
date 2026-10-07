"""Setting the scope and environment as the owner, from the terminal, not through the AI.

The model cannot widen the scope: you run these commands. Before writing, the policy is validated
by the loader; if it would become invalid, the file is not changed. After an edit restart the session:
the gateway picks up the new policy only at startup, and until then active actions are refused.

  python scope_cli.py show
  python scope_cli.py env test            # test | stage | staging | lab
  python scope_cli.py add-host ehealth.example.test
  python scope_cli.py add-url https://ehealth.example.test/
  python scope_cli.py remove-url https://ehealth.example.test/
  python scope_cli.py add-spec ~/specs/swagger.json
  python scope_cli.py set max_active_requests_total 2000
  python scope_cli.py set allowed_methods GET,HEAD,OPTIONS
"""

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from policy import ENVIRONMENTS, Policy, PolicyError  # noqa: E402

# Keys that `set` may change. Anything else must be edited by hand, on purpose.
SETTABLE = {
    "max_active_requests_total": int,
    "max_requests_per_minute": int,
    "scan_max_requests": int,
    "scan_min_delay_ms": int,
    "intruder_max_requests": int,
    "intruder_min_delay_ms": int,
    "allowed_methods": "methods",
}


def policy_path() -> Path:
    return Path(os.environ.get("BURP_AGENT_POLICY", Path(__file__).with_name("policy.json"))).expanduser()


def load_raw(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def save_checked(path: Path, data: dict) -> None:
    """Writes only if the policy still passes the loader after the write. Atomic file replacement."""
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False, suffix=".tmp") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
        tmp = Path(fh.name)
    try:
        Policy.load(str(tmp))
    except PolicyError as ex:
        tmp.unlink(missing_ok=True)
        sys.exit(f"not written: the policy would become invalid: {ex}")
    os.replace(tmp, path)
    os.chmod(path, 0o600)  # policy: owner only
    print(f"written: {path}")
    print("restart the session (new chat) so the gateway applies the changes")


def main() -> None:
    parser = argparse.ArgumentParser(description="Scope and environment for the burp-agent gateway")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("show")
    p_env = sub.add_parser("env")
    p_env.add_argument("value", choices=ENVIRONMENTS)
    p_host = sub.add_parser("add-host")
    p_host.add_argument("host")
    for name in ("add-url", "remove-url"):
        p = sub.add_parser(name)
        p.add_argument("url")
    p_spec = sub.add_parser("add-spec")
    p_spec.add_argument("file")
    p_set = sub.add_parser("set")
    p_set.add_argument("key", choices=sorted(SETTABLE))
    p_set.add_argument("value")
    args = parser.parse_args()

    path = policy_path()
    if not path.is_file():
        sys.exit(f"policy not found: {path}")
    data = load_raw(path)

    if args.cmd == "show":
        keys = ("mode", "environment", "authorized_hosts", "scope_urls", "allowed_methods",
                "allowed_paths", "openapi_files", "scan_max_requests")
        print(json.dumps({k: data.get(k) for k in keys}, ensure_ascii=False, indent=2))
        return
    if args.cmd == "env":
        data["environment"] = args.value
    elif args.cmd == "add-host":
        hosts = list(data.get("authorized_hosts", []))
        if args.host.lower() not in hosts:
            hosts.append(args.host.lower())
        data["authorized_hosts"] = hosts
    elif args.cmd == "add-url":
        urls = list(data.get("scope_urls", []))
        if args.url not in urls:
            urls.append(args.url)
        data["scope_urls"] = urls
    elif args.cmd == "remove-url":
        data["scope_urls"] = [u for u in data.get("scope_urls", []) if u != args.url]
    elif args.cmd == "set":
        kind = SETTABLE[args.key]
        if kind == "methods":
            value = [m.strip().upper() for m in args.value.split(",") if m.strip()]
        else:
            try:
                value = kind(args.value)
            except ValueError:
                sys.exit(f"{args.key} expects a {kind.__name__}, got {args.value!r}")
        data[args.key] = value
    elif args.cmd == "add-spec":
        spec = str(Path(args.file).expanduser())
        files = list(data.get("openapi_files", []))
        if spec not in files:
            files.append(spec)
        data["openapi_files"] = files
    save_checked(path, data)


if __name__ == "__main__":
    main()
