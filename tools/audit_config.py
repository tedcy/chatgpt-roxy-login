"""Audit production configuration reads against the complete UI inventory."""
import ast
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from roxy_demo.settings import SCHEMA, FIXED_CONFIG


def audit():
    known = set(SCHEMA).union(*(set(values) for values in FIXED_CONFIG.values()))
    reads = {}
    for path in (ROOT / "upstream/core").rglob("*.py"):
        if "vendor" in path.parts:
            continue
        source = path.read_text(encoding="utf-8-sig")
        tree = ast.parse(source)
        wrapper = next((node for node in tree.body if isinstance(node, ast.Assign)
            and any(isinstance(item, ast.Name) and item.id == "_SOURCE" for item in node.targets)), None)
        if wrapper:
            tree = ast.parse(ast.literal_eval(wrapper.value.args[0]))
        aliases = {"_cfg", "roxy_cfg", "browser_cfg", "_browser_cfg", "_twofa_cfg", "roxy_config", "_humanize_cfg"}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "config":
                aliases.update(item.asname or item.name for item in node.names)
        for node in ast.walk(tree):
            key = None
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id in aliases:
                key = node.attr
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id == "getattr" and len(node.args) >= 2 and isinstance(node.args[0], ast.Name) and node.args[0].id in aliases:
                    key = node.args[1].value if isinstance(node.args[1], ast.Constant) else None
                elif node.func.id == "_cfg_get" and node.args and isinstance(node.args[0], ast.Constant):
                    key = node.args[0].value
            if isinstance(key, str) and key.isupper():
                reads.setdefault(key, set()).add(path.relative_to(ROOT).as_posix())
    missing = sorted(set(reads) - known)
    if missing:
        raise RuntimeError("Configuration missing from UI: " + ", ".join(missing))
    return {key: {"display": "editable" if key in SCHEMA else "fixed", "files": sorted(files)} for key, files in sorted(reads.items())}


if __name__ == "__main__":
    result = audit()
    if "--write" in sys.argv:
        (ROOT / "CONFIG_READS.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Configuration reads covered by UI: {len(result)}; missing: 0")
