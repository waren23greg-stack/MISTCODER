"""
MISTCODER -- MOD-01 Ingestion Engine
Multi-Language AST Parser

Version: 0.2.0
Changes from 0.1.0:
    GAP-01 fixed -- JS secret pattern detection added
    GAP-02 fixed -- JS function-to-call edge graph added
"""

import ast
import os
import re
import json
import hashlib
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SUPPORTED_LANGUAGES = {
    ".py":   "python",
    ".js":   "javascript",
    ".ts":   "typescript",
    ".jsx":  "javascript",
    ".tsx":  "typescript",
}

DANGEROUS_CALLS_PYTHON = {
    "eval", "exec", "compile", "open", "subprocess",
    "os.system", "os.popen", "pickle.loads", "yaml.load",
    "__import__"
}

DANGEROUS_CALLS_JS = {
    "eval", "Function", "setTimeout", "setInterval",
    "innerHTML", "document.write", "execSync", "exec"
}

SECRET_KEYWORDS = {
    "password", "secret", "token", "key", "credential",
    "apikey", "api_key", "auth", "passwd", "private"
}


# ---------------------------------------------------------------------------
# Node and Edge records
# ---------------------------------------------------------------------------

def make_node(node_id, node_type, name, line, props=None):
    return {
        "id":    node_id,
        "type":  node_type,
        "name":  name,
        "line":  line,
        "props": props or {}
    }

def make_edge(src, dst, edge_type):
    return {
        "src":  src,
        "dst":  dst,
        "type": edge_type
    }


# ---------------------------------------------------------------------------
# Python parser
# ---------------------------------------------------------------------------

class PythonParser:

    def __init__(self, source, filepath):
        self.source   = source
        self.filepath = filepath
        self.nodes    = []
        self.edges    = []
        self._id      = 0

    def _next_id(self, prefix="N"):
        self._id += 1
        return f"{prefix}{self._id:04d}"

    def parse(self):
        try:
            tree = ast.parse(self.source, filename=self.filepath)
        except SyntaxError as e:
            return self._error_result(str(e))

        self._walk(tree, parent_id=None)
        return self._build_result()

    def _walk(self, node, parent_id):
        node_id   = None
        node_type = type(node).__name__

        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            node_id = self._next_id("FN")
            props = {
                "async":      isinstance(node, ast.AsyncFunctionDef),
                "args":       [a.arg for a in node.args.args],
                "decorators": [ast.unparse(d) for d in node.decorator_list],
                "dangerous":  False
            }
            self.nodes.append(make_node(node_id, "function", node.name, node.lineno, props))

        elif isinstance(node, ast.ClassDef):
            node_id = self._next_id("CL")
            self.nodes.append(make_node(node_id, "class", node.name, node.lineno))

        elif isinstance(node, ast.Import):
            for alias in node.names:
                nid = self._next_id("IM")
                self.nodes.append(make_node(nid, "import", alias.name, node.lineno))
                if parent_id:
                    self.edges.append(make_edge(parent_id, nid, "imports"))

        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                nid  = self._next_id("IM")
                name = f"{module}.{alias.name}"
                self.nodes.append(make_node(nid, "import", name, node.lineno))
                if parent_id:
                    self.edges.append(make_edge(parent_id, nid, "imports"))

        elif isinstance(node, ast.Call):
            call_name = self._resolve_call_name(node)
            if call_name:
                node_id   = self._next_id("CA")
                dangerous = call_name in DANGEROUS_CALLS_PYTHON or \
                            any(call_name.startswith(d) for d in DANGEROUS_CALLS_PYTHON)
                props = {"dangerous": dangerous}
                self.nodes.append(make_node(node_id, "call", call_name, node.lineno, props))
                if parent_id:
                    self.edges.append(make_edge(parent_id, node_id, "calls"))

        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    name_lower = target.id.lower()
                    if any(k in name_lower for k in SECRET_KEYWORDS):
                        nid = self._next_id("SE")
                        props = {"pattern": "potential_secret_assignment"}
                        self.nodes.append(make_node(nid, "secret_flag", target.id, node.lineno, props))
                        if parent_id:
                            self.edges.append(make_edge(parent_id, nid, "contains"))

        current_parent = node_id if node_id else parent_id
        for child in ast.iter_child_nodes(node):
            self._walk(child, current_parent)

    def _resolve_call_name(self, node):
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            try:
                return ast.unparse(node.func)
            except Exception:
                return None
        return None

    def _build_result(self):
        dangerous_nodes = [n for n in self.nodes if n.get("props", {}).get("dangerous")]
        secret_flags    = [n for n in self.nodes if n["type"] == "secret_flag"]
        return {
            "file":     self.filepath,
            "language": "python",
            "nodes":    self.nodes,
            "edges":    self.edges,
            "metadata": {
                "node_count":      len(self.nodes),
                "edge_count":      len(self.edges),
                "dangerous_calls": len(dangerous_nodes),
                "secret_flags":    len(secret_flags),
                "parser":          "PythonParser v0.2.0"
            }
        }

    def _error_result(self, error):
        return {
            "file":     self.filepath,
            "language": "python",
            "nodes":    [],
            "edges":    [],
            "metadata": {"error": error, "parser": "PythonParser v0.2.0"}
        }


# ---------------------------------------------------------------------------
# JavaScript / TypeScript parser (structural) -- v0.2.0
# GAP-01 fix: secret pattern detection
# GAP-02 fix: function-to-call edge graph via brace depth tracking
# ---------------------------------------------------------------------------

class JavaScriptParser:

    FUNC_PATTERN   = re.compile(
        r'(?:async\s+)?function\s+(\w+)\s*\(|'
        r'(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\(.*?\)\s*=>'
    )
    CLASS_PATTERN  = re.compile(r'class\s+(\w+)')
    IMPORT_PATTERN = re.compile(
        r'(?:import\s+[\w\s{},*]+from\s+["\']([^"\' ]+)["\']'
        r'|import\s+["\']([^"\' ]+)["\']'
        r'|require\s*\(\s*["\']([^"\' ]+)["\']\s*\))',
        re.IGNORECASE
    )
    CALL_PATTERN   = re.compile(r'\b(\w+)\s*\(')
    SECRET_PATTERN = re.compile(
        r'(?:const|let|var)\s+(\w+)\s*=\s*["\'](.+?)["\']'
    )

    def __init__(self, source, filepath, language="javascript"):
        self.source   = source
        self.filepath = filepath
        self.language = language
        self.nodes    = []
        self.edges    = []
        self._id      = 0

    def _next_id(self, prefix="N"):
        self._id += 1
        return f"{prefix}{self._id:04d}"

    def parse(self):
        lines = self.source.splitlines()

        # GAP-02: track function context via brace depth
        # Stack entries: {"id": node_id, "depth": brace_depth_at_open}
        func_stack  = []
        brace_depth = 0

        for lineno, line in enumerate(lines, start=1):

            # update brace depth for this line
            brace_depth += line.count("{") - line.count("}")

            # -- GAP-01: secret detection
            for m in self.SECRET_PATTERN.finditer(line):
                var_name   = m.group(1)
                name_lower = var_name.lower()
                if any(k in name_lower for k in SECRET_KEYWORDS):
                    nid = self._next_id("SE")
                    props = {"pattern": "potential_secret_assignment"}
                    self.nodes.append(make_node(nid, "secret_flag", var_name, lineno, props))

            # -- function definitions
            for m in self.FUNC_PATTERN.finditer(line):
                name = m.group(1) or m.group(2)
                if name:
                    nid = self._next_id("FN")
                    self.nodes.append(make_node(nid, "function", name, lineno))
                    # push onto stack with current brace depth
                    func_stack.append({"id": nid, "depth": brace_depth})

            # -- pop functions whose scope has closed
            func_stack = [f for f in func_stack if f["depth"] <= brace_depth + 1]

            # -- classes
            for m in self.CLASS_PATTERN.finditer(line):
                nid = self._next_id("CL")
                self.nodes.append(make_node(nid, "class", m.group(1), lineno))

            # -- imports
            for m in self.IMPORT_PATTERN.finditer(line):
                nid = self._next_id("IM")
                self.nodes.append(make_node(nid, "import", m.group(1), lineno))

            # -- dangerous calls + GAP-02: link to enclosing function
            # Detect dangerous property assignments (innerHTML etc)
            for danger in ["innerHTML", "outerHTML", "document.write"]:
                if danger.lower() in line.lower() and "=" in line:
                    nid = self._next_id("CA")
                    props = {"dangerous": True}
                    self.nodes.append(make_node(nid, "call", danger, lineno, props))
                    break
            for m in self.CALL_PATTERN.finditer(line):
                name = m.group(1)
                if name in DANGEROUS_CALLS_JS:
                    nid   = self._next_id("CA")
                    props = {"dangerous": True}
                    self.nodes.append(make_node(nid, "call", name, lineno, props))
                    # link to nearest enclosing function if one exists
                    if func_stack:
                        self.edges.append(make_edge(func_stack[-1]["id"], nid, "calls"))

        dangerous = [n for n in self.nodes if n.get("props", {}).get("dangerous")]
        secrets   = [n for n in self.nodes if n["type"] == "secret_flag"]

        return {
            "file":     self.filepath,
            "language": self.language,
            "nodes":    self.nodes,
            "edges":    self.edges,
            "metadata": {
                "node_count":      len(self.nodes),
                "edge_count":      len(self.edges),
                "dangerous_calls": len(dangerous),
                "secret_flags":    len(secrets),
                "parser":          "JavaScriptParser v0.2.0"
            }
        }


# ---------------------------------------------------------------------------
# Ingestion engine -- entry point
# ---------------------------------------------------------------------------

class IngestionEngine:

    def __init__(self):
        self.results = []

    def ingest_file(self, filepath):
        if not os.path.isfile(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")

        ext      = os.path.splitext(filepath)[1].lower()
        language = SUPPORTED_LANGUAGES.get(ext, "unknown")

        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            source = f.read()

        file_hash = hashlib.sha256(source.encode()).hexdigest()

        if language == "python":
            parser = PythonParser(source, filepath)
        elif language in ("javascript", "typescript"):
            parser = JavaScriptParser(source, filepath, language)
        else:
            lines = source.splitlines()
            return {
                "file":     filepath,
                "language": "unknown",
                "nodes":    [],
                "edges":    [],
                "metadata": {
                    "line_count": len(lines),
                    "note":       "Language not supported in Phase 1. Raw line count only.",
                    "parser":     "FallbackParser v0.2.0"
                }
            }

        ir             = parser.parse()
        ir["hash"]     = file_hash
        ir["parsed_at"] = datetime.now(timezone.utc).isoformat()
        self.results.append(ir)
        return ir

    def ingest_directory(self, dirpath, recursive=True):
        results = []
        walk    = os.walk(dirpath) if recursive else [(dirpath, [], os.listdir(dirpath))]
        for root, _, files in walk:
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                if ext in SUPPORTED_LANGUAGES:
                    full_path = os.path.join(root, fname)
                    try:
                        ir = self.ingest_file(full_path)
                        results.append(ir)
                    except Exception as e:
                        results.append({"file": full_path, "error": str(e)})
        return results

    def export_json(self, ir, output_path):
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(ir, f, indent=2)
        print(f"[MOD-01] IR exported to {output_path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python parser.py <filepath_or_directory>")
        print("       python parser.py <filepath> --export output.json")
        sys.exit(1)

    target = sys.argv[1]
    export = sys.argv[3] if len(sys.argv) >= 4 and sys.argv[2] == "--export" else None
    engine = IngestionEngine()

    print(f"\n[MOD-01] MISTCODER Ingestion Engine v0.2.0")
    print(f"[MOD-01] Target: {target}")
    print("-" * 60)

    if os.path.isdir(target):
        results = engine.ingest_directory(target)
        for r in results:
            if "error" in r:
                print(f"  [ERROR]  {r['file']} -- {r['error']}")
            else:
                m = r.get("metadata", {})
                print(f"  [OK]     {r['file']}")
                print(f"           language={r['language']}  "
                      f"nodes={m.get('node_count', 0)}  "
                      f"edges={m.get('edge_count', 0)}  "
                      f"dangerous={m.get('dangerous_calls', 0)}  "
                      f"secrets={m.get('secret_flags', 0)}")
        if export:
            engine.export_json(results, export)
    else:
        ir = engine.ingest_file(target)
        m  = ir.get("metadata", {})
        print(f"  language       : {ir['language']}")
        print(f"  nodes          : {m.get('node_count', 0)}")
        print(f"  edges          : {m.get('edge_count', 0)}")
        print(f"  dangerous calls: {m.get('dangerous_calls', 0)}")
        print(f"  secret flags   : {m.get('secret_flags', 0)}")
        print(f"  sha256         : {ir.get('hash', 'n/a')[:16]}...")
        print(f"  parsed at      : {ir.get('parsed_at', 'n/a')}")
        if export:
            engine.export_json(ir, export)

    print("-" * 60)
    print("[MOD-01] Ingestion complete.")
