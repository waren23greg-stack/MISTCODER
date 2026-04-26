"""
MISTCODER — ORACLE Engine
modules/ingestion/src/taint_model.py

Data model for taint analysis results.
Sources, sinks, sanitizers, and taint flows — the vocabulary
that feeds the Threat Knowledge Graph.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class SourceKind(str, Enum):
    HTTP_PARAM        = "http_param"       # request.args, request.form
    HTTP_HEADER       = "http_header"      # request.headers
    HTTP_BODY         = "http_body"        # request.data / request.json
    HTTP_COOKIE       = "http_cookie"      # request.cookies
    CLI_ARG           = "cli_arg"          # sys.argv, argparse
    ENV_VAR           = "env_var"          # os.environ, os.getenv
    FILE_READ         = "file_read"        # open(), read()
    DB_RESULT         = "db_result"        # second-order: cursor.fetchall()
    SOCKET_RECV       = "socket_recv"      # socket.recv()
    DESERIALIZATION   = "deserialization"  # pickle.loads, json.loads on ext input
    USER_INPUT        = "user_input"       # input()


class SinkKind(str, Enum):
    SQL_QUERY         = "sql_query"        # execute(), raw(), cursor.execute()
    OS_COMMAND        = "os_command"       # os.system, subprocess, exec
    FILE_WRITE        = "file_write"       # open(x, 'w'), write()
    FILE_PATH         = "file_path"        # open(attacker_controlled_path)
    TEMPLATE_RENDER   = "template_render"  # render_template_string, Jinja2
    EVAL_EXEC         = "eval_exec"        # eval(), exec(), compile()
    HTML_OUTPUT       = "html_output"      # Response with unescaped content
    PICKLE_LOAD       = "pickle_load"      # pickle.loads / pickle.load
    LDAP_QUERY        = "ldap_query"       # ldap search with user input
    XML_PARSE         = "xml_parse"        # lxml/ElementTree with ext data (XXE)
    REDIRECT          = "redirect"         # redirect(user_input) — open redirect
    DESERIALIZE       = "deserialize"      # yaml.load, marshal


class CryptoIssueKind(str, Enum):
    WEAK_HASH          = "weak_hash"        # MD5, SHA1 in security context
    WEAK_CIPHER        = "weak_cipher"      # DES, RC4, ECB mode
    HARDCODED_KEY      = "hardcoded_key"    # key = "abc123" literal
    STATIC_IV          = "static_iv"        # iv = b'\x00' * 16
    INSECURE_RANDOM    = "insecure_random"  # random.random() for secrets
    WEAK_KDF           = "weak_kdf"         # hashlib.md5(password)
    NO_CERT_VERIFY     = "no_cert_verify"   # verify=False in requests


class SecretKind(str, Enum):
    API_KEY            = "api_key"
    PRIVATE_KEY        = "private_key"
    PASSWORD           = "password"
    CONNECTION_STRING  = "connection_string"
    JWT_SECRET         = "jwt_secret"
    OAUTH_SECRET       = "oauth_secret"
    GENERIC_HIGH_ENTROPY = "high_entropy_string"


@dataclass
class SourceLocation:
    file:   str
    line:   int
    col:    int = 0

    def __str__(self) -> str:
        return f"{self.file}:{self.line}"


@dataclass
class TaintSource:
    kind:      SourceKind
    name:      str            # variable name or expression
    location:  SourceLocation
    framework: str = ""       # "flask" | "django" | "fastapi" | ""
    confidence: float = 1.0


@dataclass
class TaintSink:
    kind:       SinkKind
    expression: str           # the sink call / expression text
    location:   SourceLocation
    confidence: float = 1.0


@dataclass
class TaintFlow:
    """A confirmed source → sink path with no sanitizer in between."""
    source:       TaintSource
    sink:         TaintSink
    intermediate: list[str] = field(default_factory=list)  # variable hops
    sanitized:    bool = False
    severity:     str  = "HIGH"   # CRITICAL | HIGH | MEDIUM | LOW
    confidence:   float = 0.8

    def title(self) -> str:
        return f"{self.source.kind.value} → {self.sink.kind.value}"

    def cwe(self) -> str:
        _map = {
            SinkKind.SQL_QUERY:       "CWE-89",
            SinkKind.OS_COMMAND:      "CWE-78",
            SinkKind.FILE_WRITE:      "CWE-73",
            SinkKind.FILE_PATH:       "CWE-22",
            SinkKind.TEMPLATE_RENDER: "CWE-94",
            SinkKind.EVAL_EXEC:       "CWE-94",
            SinkKind.HTML_OUTPUT:     "CWE-79",
            SinkKind.PICKLE_LOAD:     "CWE-502",
            SinkKind.REDIRECT:        "CWE-601",
            SinkKind.DESERIALIZE:     "CWE-502",
        }
        return _map.get(self.sink.kind, "CWE-20")


@dataclass
class CryptoFinding:
    kind:       CryptoIssueKind
    expression: str
    location:   SourceLocation
    detail:     str = ""
    severity:   str = "MEDIUM"
    cve_hint:   str = ""


@dataclass
class SecretFinding:
    kind:     SecretKind
    value:    str            # redacted in output — store raw internally only
    location: SourceLocation
    entropy:  float = 0.0
    pattern:  str   = ""
    severity: str   = "HIGH"


@dataclass
class FileAnalysisResult:
    """Everything ORACLE found in a single file."""
    path:          str
    language:      str = "python"
    functions:     list[str]        = field(default_factory=list)
    sources:       list[TaintSource] = field(default_factory=list)
    sinks:         list[TaintSink]   = field(default_factory=list)
    flows:         list[TaintFlow]   = field(default_factory=list)
    crypto:        list[CryptoFinding] = field(default_factory=list)
    secrets:       list[SecretFinding] = field(default_factory=list)
    parse_error:   Optional[str]     = None

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.flows if f.severity == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.flows if f.severity == "HIGH")

    @property
    def finding_count(self) -> int:
        return len(self.flows) + len(self.crypto) + len(self.secrets)
