"""Per-language tree-sitter node type mappings for cross-language AST checks.

Maps abstract analysis concepts (imports, functions, catch blocks, etc.) to
concrete tree-sitter node types for each supported language.

Called by: semantic/core.py, semantic/checks.py, detector.py, taint.py, nullsafety.py, resource.py, types.py
Calls into: nothing (pure config data)
Data in → Data out: language string → LanguageConfig
"""

from dataclasses import dataclass, field

from ..sanitizers import PYTHON_SANITIZER_PATTERNS


@dataclass
class LanguageConfig:
    """Maps abstract check concepts to concrete tree-sitter node types."""

    ts_language_name: str
    import_node_types: list[str] = field(default_factory=list)
    function_node_types: list[str] = field(default_factory=list)
    catch_node_types: list[str] = field(default_factory=list)
    catch_body_field: str = ""
    return_node_types: list[str] = field(default_factory=list)
    break_node_types: list[str] = field(default_factory=list)
    continue_node_types: list[str] = field(default_factory=list)
    throw_node_types: list[str] = field(default_factory=list)
    builtin_names: set[str] = field(default_factory=set)
    default_value_node_types: list[str] = field(default_factory=list)
    parameter_node_types: list[str] = field(default_factory=list)
    block_node_types: list[str] = field(default_factory=list)
    branch_node_types: list[str] = field(default_factory=list)
    # Pass/empty body markers (e.g. pass_statement in Python)
    pass_node_types: list[str] = field(default_factory=list)
    # Comment node types (to ignore when checking empty catch bodies)
    comment_node_types: list[str] = field(default_factory=list)

    # ── Semantic extraction (v0.8.0) ──────────────────────────────────
    assignment_node_types: list[str] = field(default_factory=list)
    call_node_types: list[str] = field(default_factory=list)
    class_node_types: list[str] = field(default_factory=list)
    scope_boundary_types: list[str] = field(default_factory=list)
    attribute_access_types: list[str] = field(default_factory=list)
    block_scoped: bool = True  # True for JS/Go/Rust/Java/C#, False for Python

    # ── Taint analysis ────────────────────────────────────────────────
    taint_source_patterns: list[tuple[str, str]] = field(default_factory=list)
    taint_sink_patterns: list[tuple[str, str]] = field(default_factory=list)
    taint_sanitizer_patterns: list[str] = field(default_factory=list)

    # ── CFG control flow (v0.9.0) ──────────────────────────────────────
    cfg_if_node_types: list[str] = field(default_factory=list)
    cfg_else_node_types: list[str] = field(default_factory=list)
    cfg_for_node_types: list[str] = field(default_factory=list)
    cfg_while_node_types: list[str] = field(default_factory=list)
    cfg_try_node_types: list[str] = field(default_factory=list)
    cfg_switch_node_types: list[str] = field(default_factory=list)

    # ── Resource tracking (v0.9.0) ──────────────────────────────────
    # Each tuple: (open_pattern, close_pattern, has_context_manager, kind)
    resource_patterns: list[tuple[str, str, bool, str]] = field(default_factory=list)

    # ── Type inference (v0.10.0) ────────────────────────────────────
    literal_type_map: dict[str, str] = field(default_factory=dict)
    nullable_return_patterns: list[str] = field(default_factory=list)

    # ── Class analysis ────────────────────────────────────────────────
    self_keyword: str = ""


LANGUAGE_CONFIGS: dict[str, LanguageConfig] = {
    "python": LanguageConfig(
        ts_language_name="python",
        import_node_types=["import_statement", "import_from_statement"],
        function_node_types=["function_definition"],
        catch_node_types=["except_clause"],
        catch_body_field="",  # children after the colon
        return_node_types=["return_statement"],
        break_node_types=["break_statement"],
        continue_node_types=["continue_statement"],
        throw_node_types=["raise_statement"],
        builtin_names={
            "print",
            "len",
            "range",
            "type",
            "int",
            "float",
            "str",
            "bool",
            "list",
            "dict",
            "set",
            "tuple",
            "open",
            "input",
            "sum",
            "min",
            "max",
            "sorted",
            "next",
            "id",
            "map",
            "filter",
            "zip",
            "hash",
            "iter",
            "bytes",
            "complex",
            "frozenset",
            "object",
            "super",
        },
        default_value_node_types=["list", "dictionary", "set"],
        parameter_node_types=["parameters"],
        block_node_types=["block"],
        branch_node_types=[
            "if_statement",
            "elif_clause",
            "for_statement",
            "while_statement",
            "try_statement",
            "except_clause",
            "with_statement",
            "boolean_operator",
        ],
        pass_node_types=["pass_statement"],
        comment_node_types=["comment"],
        # Semantic extraction
        assignment_node_types=["assignment", "augmented_assignment"],
        call_node_types=["call"],
        class_node_types=["class_definition"],
        scope_boundary_types=["function_definition", "class_definition"],
        attribute_access_types=["attribute"],
        block_scoped=False,
        # Taint analysis
        taint_source_patterns=[
            ("input", "user_input"),
            # Flask
            ("request.form", "user_input"),
            ("request.args", "user_input"),
            ("request.json", "user_input"),
            ("request.data", "user_input"),
            ("request.values", "user_input"),
            ("request.files", "user_input"),
            ("request.headers", "user_input"),
            ("request.cookies", "user_input"),
            # Django
            ("request.GET", "user_input"),
            ("request.POST", "user_input"),
            ("request.FILES", "user_input"),
            ("request.body", "user_input"),
            ("request.META", "user_input"),
            ("request.COOKIES", "user_input"),
            ("request.content_type", "user_input"),
            ("request.path", "user_input"),
            ("request.path_info", "user_input"),
            ("request.get_full_path", "user_input"),
            # FastAPI (path/query params come via function args, but request object too)
            ("request.query_params", "user_input"),
            # Environment
            ("os.environ.get", "env_var"),
            ("os.environ", "env_var"),
            ("os.getenv", "env_var"),
            ("sys.argv", "user_input"),
            (".read", "file_read"),
            # Database results (second-order injection)
            ("cursor.fetchone", "db_input"),
            ("cursor.fetchall", "db_input"),
            ("cursor.fetchmany", "db_input"),
            # LLM response outputs — tainted because model output is untrusted
            ("response.choices", "llm_output"),
            ("completion.choices", "llm_output"),
            ("response.content", "llm_output"),
            ("message.content", "llm_output"),
            ("completion.text", "llm_output"),
            ("response.text", "llm_output"),
            (".invoke", "llm_output"),
            (".run", "llm_output"),
            (".predict", "llm_output"),
        ],
        taint_sink_patterns=[
            # SQL — generic
            ("cursor.execute", "sql_query"),
            ("session.execute", "sql_query"),
            ("session.exec", "sql_query"),
            ("conn.execute", "sql_query"),
            ("connection.execute", "sql_query"),
            ("db.execute", "sql_query"),
            ("engine.execute", "sql_query"),
            # SQL — Django raw queries (bypass ORM safety)
            (".raw", "sql_query"),
            (".extra", "sql_query"),
            ("RawSQL", "sql_query"),
            ("connection.cursor", "sql_query"),
            # SQL — SQLAlchemy raw text (bypass parameterization)
            ("text", "sql_query"),
            # Eval/exec
            ("eval", "eval"),
            ("exec", "eval"),
            ("compile", "eval"),
            # OS command injection
            ("os.system", "system_cmd"),
            ("os.popen", "system_cmd"),
            ("subprocess.run", "system_cmd"),
            ("subprocess.call", "system_cmd"),
            ("subprocess.Popen", "system_cmd"),
            ("subprocess.check_output", "system_cmd"),
            ("subprocess.check_call", "system_cmd"),
            # SSRF
            ("requests.get", "ssrf"),
            ("requests.post", "ssrf"),
            ("requests.put", "ssrf"),
            ("requests.delete", "ssrf"),
            ("requests.patch", "ssrf"),
            ("requests.head", "ssrf"),
            ("urllib.request.urlopen", "ssrf"),
            ("httpx.get", "ssrf"),
            ("httpx.post", "ssrf"),
            ("httpx.AsyncClient", "ssrf"),
            ("aiohttp.ClientSession", "ssrf"),
            # SSTI
            ("Template", "ssti"),
            ("render_template_string", "ssti"),
            ("from_string", "ssti"),
            ("Jinja2Templates", "ssti"),
            # Path traversal
            ("=open", "path_traversal"),
            ("os.open", "path_traversal"),
            ("io.open", "path_traversal"),
            ("send_file", "path_traversal"),
            ("shutil.copy", "path_traversal"),
            ("shutil.move", "path_traversal"),
            ("pathlib.Path", "path_traversal"),
            # Deserialization
            ("pickle.loads", "deserialization"),
            ("pickle.load", "deserialization"),
            ("yaml.load", "deserialization"),
            ("yaml.unsafe_load", "deserialization"),
            ("marshal.loads", "deserialization"),
            ("shelve.open", "deserialization"),
            # XSS — Django
            ("mark_safe", "html_output"),
            ("SafeString", "html_output"),
            # LLM API calls — user input flowing here is prompt injection
            ("client.chat.completions.create", "llm_input"),
            ("openai.ChatCompletion.create", "llm_input"),
            ("client.completions.create", "llm_input"),
            ("client.messages.create", "llm_input"),
            ("anthropic.messages.create", "llm_input"),
            ("litellm.completion", "llm_input"),
            ("litellm.acompletion", "llm_input"),
            ("cohere.Client.generate", "llm_input"),
            ("cohere.Client.chat", "llm_input"),
            ("co.generate", "llm_input"),
            ("co.chat", "llm_input"),
            ("genai.GenerativeModel", "llm_input"),
            ("model.generate_content", "llm_input"),
            ("chain.invoke", "llm_input"),
            ("chain.run", "llm_input"),
            ("llm.invoke", "llm_input"),
            ("llm.predict", "llm_input"),
            ("chat.invoke", "llm_input"),
        ],
        taint_sanitizer_patterns=PYTHON_SANITIZER_PATTERNS,
        # CFG control flow
        cfg_if_node_types=["if_statement"],
        cfg_else_node_types=["elif_clause", "else_clause"],
        cfg_for_node_types=["for_statement"],
        cfg_while_node_types=["while_statement"],
        cfg_try_node_types=["try_statement"],
        cfg_switch_node_types=[],
        # Resource tracking
        resource_patterns=[
            ("open", "close", True, "file"),
            ("connect", "close", True, "connection"),
            ("cursor", "close", True, "cursor"),
            ("socket", "close", True, "socket"),
            # Note: Lock/RLock/Semaphore/Event are synchronization primitives,
            # not resources that leak. acquire/release imbalance is a deadlock
            # issue requiring different analysis.
        ],
        # Type inference
        literal_type_map={
            "integer": "INT",
            "float": "FLOAT",
            "string": "STRING",
            "true": "BOOL",
            "false": "BOOL",
            "none": "NONE",
            "list": "LIST",
            "dictionary": "DICT",
            "set": "SET",
        },
        nullable_return_patterns=[
            "dict.get",
            "re.search",
            "re.match",
            "re.fullmatch",
            ".get",
            "os.environ.get",
            "os.getenv",
        ],
        # Class analysis
        self_keyword="self",
    ),
}

# JS and TS share identical config except for ts_language_name
_JS_BASE = dict(
    import_node_types=["import_statement"],
    function_node_types=[
        "function_declaration",
        "arrow_function",
        "method_definition",
        "function",
    ],
    catch_node_types=["catch_clause"],
    catch_body_field="body",
    return_node_types=["return_statement"],
    break_node_types=["break_statement"],
    continue_node_types=["continue_statement"],
    throw_node_types=["throw_statement"],
    builtin_names={
        "console",
        "undefined",
        "NaN",
        "Infinity",
        "eval",
        "parseInt",
        "parseFloat",
        "isNaN",
        "isFinite",
        "encodeURI",
        "decodeURI",
        "encodeURIComponent",
        "decodeURIComponent",
        "Object",
        "Array",
        "String",
        "Number",
        "Boolean",
        "Symbol",
        "Map",
        "Set",
        "Promise",
    },
    default_value_node_types=["array", "object"],
    parameter_node_types=["formal_parameters"],
    block_node_types=["statement_block"],
    branch_node_types=[
        "if_statement",
        "else_clause",
        "for_statement",
        "for_in_statement",
        "while_statement",
        "do_statement",
        "switch_case",
        "catch_clause",
        "ternary_expression",
        "binary_expression",
    ],
    pass_node_types=[],
    comment_node_types=["comment"],
    assignment_node_types=["variable_declarator", "assignment_expression", "augmented_assignment_expression"],
    call_node_types=["call_expression"],
    class_node_types=["class_declaration"],
    scope_boundary_types=[
        "function_declaration",
        "arrow_function",
        "method_definition",
        "function",
        "class_declaration",
    ],
    attribute_access_types=["member_expression"],
    block_scoped=True,
    taint_source_patterns=[
        # Express
        ("req.body", "user_input"),
        ("req.params", "user_input"),
        ("req.query", "user_input"),
        ("req.headers", "user_input"),
        ("req.cookies", "user_input"),
        ("req.file", "user_input"),
        ("req.files", "user_input"),
        ("req.hostname", "user_input"),
        ("req.ip", "user_input"),
        ("req.path", "user_input"),
        ("req.url", "user_input"),
        # Koa
        ("ctx.request.body", "user_input"),
        ("ctx.params", "user_input"),
        ("ctx.query", "user_input"),
        ("ctx.request.files", "user_input"),
        # Fastify / Hapi (request.* patterns)
        ("request.body", "user_input"),
        ("request.params", "user_input"),
        ("request.query", "user_input"),
        ("request.headers", "user_input"),
        # Hapi-specific
        ("request.payload", "user_input"),
        # Browser
        ("document.getElementById", "user_input"),
        ("window.location", "user_input"),
        ("location.search", "user_input"),
        ("location.hash", "user_input"),
        ("location.href", "user_input"),
        ("document.referrer", "user_input"),
        ("document.cookie", "user_input"),
        ("postMessage", "user_input"),
        # URL API
        ("URL.searchParams", "user_input"),
        ("URLSearchParams", "user_input"),
        # Environment
        ("process.env", "env_var"),
        # Database results (second-order injection)
        (".findOne", "db_input"),
        (".findById", "db_input"),
        # LLM response outputs — tainted because model output is untrusted
        ("response.choices", "llm_output"),
        ("completion.choices", "llm_output"),
        ("message.content", "llm_output"),
        ("response.data.choices", "llm_output"),
        (".invoke", "llm_output"),
    ],
    taint_sink_patterns=[
        ("eval", "eval"),
        ("Function", "eval"),
        ("setTimeout", "eval"),
        ("setInterval", "eval"),
        # XSS — DOM
        (".innerHTML", "html_output"),
        (".outerHTML", "html_output"),
        ("document.write", "html_output"),
        ("document.writeln", "html_output"),
        ("$.html", "html_output"),
        # XSS — Express response
        ("res.send", "html_output"),
        ("res.render", "html_output"),
        ("res.write", "html_output"),
        # Command injection
        ("child_process.exec", "system_cmd"),
        ("child_process.execSync", "system_cmd"),
        ("child_process.spawn", "system_cmd"),
        ("child_process.execFile", "system_cmd"),
        ("execSync", "system_cmd"),
        ("spawnSync", "system_cmd"),
        # SQL — raw queries
        ("sql.raw", "sql_query"),
        (".raw", "sql_query"),
        ("sequelize.query", "sql_query"),
        ("knex.raw", "sql_query"),
        ("pool.query", "sql_query"),
        ("client.query", "sql_query"),
        ("connection.query", "sql_query"),
        ("mysql.query", "sql_query"),
        ("pg.query", "sql_query"),
        ("$queryRaw", "sql_query"),
        ("$executeRaw", "sql_query"),
        # SSRF
        ("fetch", "ssrf"),
        ("axios.get", "ssrf"),
        ("axios.post", "ssrf"),
        ("axios.put", "ssrf"),
        ("axios.delete", "ssrf"),
        ("axios.request", "ssrf"),
        ("http.get", "ssrf"),
        ("http.request", "ssrf"),
        ("https.get", "ssrf"),
        ("https.request", "ssrf"),
        ("got", "ssrf"),
        ("needle", "ssrf"),
        ("superagent", "ssrf"),
        # Path traversal
        ("fs.readFile", "path_traversal"),
        ("fs.readFileSync", "path_traversal"),
        ("fs.writeFile", "path_traversal"),
        ("fs.writeFileSync", "path_traversal"),
        ("fs.createReadStream", "path_traversal"),
        ("fs.createWriteStream", "path_traversal"),
        ("fs.access", "path_traversal"),
        ("fs.stat", "path_traversal"),
        ("fs.unlink", "path_traversal"),
        ("path.join", "path_traversal"),
        ("path.resolve", "path_traversal"),
        # Deserialization
        ("JSON.parse", "deserialization"),
        ("vm.runInNewContext", "eval"),
        ("vm.runInThisContext", "eval"),
        # Open redirect
        ("res.redirect", "open_redirect"),
        # Header injection
        ("res.setHeader", "http_header"),
        # LLM API calls — user input flowing here is prompt injection
        ("openai.chat.completions.create", "llm_input"),
        ("openai.completions.create", "llm_input"),
        ("anthropic.messages.create", "llm_input"),
        ("cohere.generate", "llm_input"),
        ("cohere.chat", "llm_input"),
    ],
    taint_sanitizer_patterns=[
        "DOMPurify.sanitize",
        "escapeHtml",
        "sanitizeHtml",
        "encodeURIComponent",
        "encodeURI",
        "parseInt",
        "Number",
        "validator.escape",
        "validator.isEmail",
        "validator.isURL",
        "validator.isAlphanumeric",
        "validator.whitelist",
        "xss-filters",
        "he.encode",
        "he.escape",
        # ORM/query builder sanitizers (parameterized by default)
        "sequelize.escape",
        "knex.where",
        "knex.select",
        # Path sanitization
        "path.basename",
        "path.normalize",
    ],
    cfg_if_node_types=["if_statement"],
    cfg_else_node_types=["else_clause"],
    cfg_for_node_types=["for_statement", "for_in_statement"],
    cfg_while_node_types=["while_statement", "do_statement"],
    cfg_try_node_types=["try_statement"],
    cfg_switch_node_types=["switch_statement"],
    resource_patterns=[
        ("createReadStream", "close", False, "stream"),
        ("createWriteStream", "close", False, "stream"),
        ("createConnection", "end", False, "connection"),
    ],
    literal_type_map={
        "number": "FLOAT",
        "string": "STRING",
        "true": "BOOL",
        "false": "BOOL",
        "null": "NONE",
        "undefined": "NONE",
        "array": "LIST",
        "object": "DICT",
    },
    nullable_return_patterns=[".find", ".match"],
    self_keyword="this",
)

LANGUAGE_CONFIGS.update(
    {
        "javascript": LanguageConfig(ts_language_name="javascript", **_JS_BASE),  # type: ignore[arg-type]  # dict unpacking matches LanguageConfig fields
        "typescript": LanguageConfig(ts_language_name="typescript", **_JS_BASE),  # type: ignore[arg-type]  # dict unpacking matches LanguageConfig fields
        "go": LanguageConfig(
            ts_language_name="go",
            import_node_types=["import_declaration"],
            function_node_types=["function_declaration", "method_declaration"],
            catch_node_types=[],  # Go uses defer/recover, not catch blocks
            catch_body_field="",
            return_node_types=["return_statement"],
            break_node_types=["break_statement"],
            continue_node_types=["continue_statement"],
            throw_node_types=[],  # Go uses panic() but it's a function call
            builtin_names={
                "len",
                "cap",
                "make",
                "new",
                "append",
                "copy",
                "delete",
                "close",
                "complex",
                "real",
                "imag",
                "panic",
                "recover",
                "print",
                "println",
            },
            default_value_node_types=[],  # Go doesn't have mutable defaults
            parameter_node_types=["parameter_list"],
            block_node_types=["block", "statement_list"],
            branch_node_types=[
                "if_statement",
                "for_statement",
                "expression_switch_statement",
                "type_switch_statement",
                "select_statement",
                "expression_case",
                "type_case",
                "default_case",
                "communication_case",
            ],
            pass_node_types=[],
            comment_node_types=["comment"],
            # Semantic extraction
            assignment_node_types=["short_var_declaration", "assignment_statement"],
            call_node_types=["call_expression"],
            class_node_types=["type_spec"],
            scope_boundary_types=["function_declaration", "method_declaration"],
            attribute_access_types=["selector_expression"],
            block_scoped=True,
            # Taint analysis
            taint_source_patterns=[
                # net/http
                ("r.FormValue", "user_input"),
                ("r.URL.Query", "user_input"),
                ("r.PostFormValue", "user_input"),
                ("r.Header.Get", "user_input"),
                ("r.Body", "user_input"),
                ("r.URL.Path", "user_input"),
                ("r.RequestURI", "user_input"),
                # Gin / Echo / Fiber (shared context patterns)
                ("c.Query", "user_input"),
                ("c.Param", "user_input"),
                ("c.PostForm", "user_input"),
                ("c.GetHeader", "user_input"),
                ("c.BindJSON", "user_input"),
                ("c.ShouldBindJSON", "user_input"),
                # Echo-specific
                ("c.QueryParam", "user_input"),
                ("c.FormValue", "user_input"),
                # Fiber-specific
                ("c.Params", "user_input"),
                ("c.Body", "user_input"),
                # Environment
                ("os.Getenv", "env_var"),
                # Database results
                ("rows.Scan", "db_input"),
            ],
            taint_sink_patterns=[
                ("exec.Command", "system_cmd"),
                ("exec.CommandContext", "system_cmd"),
                # SQL — database/sql
                ("db.Exec", "sql_query"),
                ("db.Query", "sql_query"),
                ("db.QueryRow", "sql_query"),
                ("db.ExecContext", "sql_query"),
                ("db.QueryContext", "sql_query"),
                ("db.QueryRowContext", "sql_query"),
                ("tx.Exec", "sql_query"),
                ("tx.Query", "sql_query"),
                # SQL — GORM raw (bypass ORM safety)
                ("db.Raw", "sql_query"),
                # XSS — template output
                ("template.HTML", "html_output"),
                ("template.JS", "html_output"),
                ("template.HTMLAttr", "html_output"),
                # XSS — Gin response
                ("c.HTML", "html_output"),
                ("c.String", "html_output"),
                # File operations
                ("os.Open", "file_path"),
                ("os.Create", "file_path"),
                ("os.ReadFile", "file_path"),
                ("os.WriteFile", "file_path"),
                ("ioutil.ReadFile", "file_path"),
                ("filepath.Join", "file_path"),
                # SSRF: standard http package functions
                ("http.Get", "ssrf"),
                ("http.Post", "ssrf"),
                ("http.PostForm", "ssrf"),
                ("http.Head", "ssrf"),
                ("http.NewRequest", "ssrf"),
                # SSRF: method calls on any http.Client instance
                (".Get", "ssrf"),
                (".Post", "ssrf"),
                (".Do", "ssrf"),
                (".PostForm", "ssrf"),
                (".Head", "ssrf"),
                # Open redirect
                ("http.Redirect", "open_redirect"),
                ("c.Redirect", "open_redirect"),
                # Log injection
                ("log.Printf", "log_injection"),
                ("log.Println", "log_injection"),
            ],
            taint_sanitizer_patterns=[
                "html.EscapeString",
                "template.HTMLEscapeString",
                "url.QueryEscape",
                "url.PathEscape",
                "strconv.Atoi",
                "strconv.ParseInt",
                "strconv.ParseFloat",
                "filepath.Base",
                "filepath.Clean",
                "filepath.Abs",
                # GORM ORM (parameterized by default)
                "db.Where",
                "db.Find",
                "db.First",
                "db.Create",
                "db.Save",
                "db.Delete",
                "db.Model",
                # sqlx named params
                "sqlx.Named",
                "db.NamedExec",
            ],
            # CFG control flow
            cfg_if_node_types=["if_statement"],
            cfg_else_node_types=["else_clause"],
            cfg_for_node_types=["for_statement"],
            cfg_while_node_types=[],
            cfg_try_node_types=[],
            cfg_switch_node_types=["expression_switch_statement", "type_switch_statement"],
            # Resource tracking
            resource_patterns=[
                ("os.Open", "Close", False, "file"),
                ("sql.Open", "Close", False, "connection"),
                ("net.Dial", "Close", False, "connection"),
            ],
            # Type inference
            literal_type_map={
                "int_literal": "INT",
                "float_literal": "FLOAT",
                "interpreted_string_literal": "STRING",
                "raw_string_literal": "STRING",
                "true": "BOOL",
                "false": "BOOL",
                "nil": "NONE",
            },
            nullable_return_patterns=[],
            # Class analysis
            self_keyword="",
        ),
        "rust": LanguageConfig(
            ts_language_name="rust",
            import_node_types=["use_declaration"],
            function_node_types=["function_item"],
            catch_node_types=[],  # Rust uses Result/Option, not exceptions
            catch_body_field="",
            return_node_types=["return_expression"],
            break_node_types=["break_expression"],
            continue_node_types=["continue_expression"],
            throw_node_types=[],
            builtin_names={
                "println",
                "eprintln",
                "print",
                "eprint",
                "format",
                "vec",
                "panic",
                "todo",
                "unimplemented",
                "unreachable",
                "assert",
                "assert_eq",
                "assert_ne",
                "dbg",
            },
            default_value_node_types=[],  # Rust doesn't have mutable defaults
            parameter_node_types=["parameters"],
            block_node_types=["block"],
            branch_node_types=[
                "if_expression",
                "else_clause",
                "for_expression",
                "while_expression",
                "loop_expression",
                "match_arm",
                "binary_expression",
            ],
            pass_node_types=[],
            comment_node_types=["line_comment", "block_comment"],
            # Semantic extraction
            assignment_node_types=["let_declaration", "assignment_expression", "compound_assignment_expr"],
            call_node_types=["call_expression"],
            class_node_types=["struct_item", "impl_item"],
            scope_boundary_types=["function_item", "impl_item"],
            attribute_access_types=["field_expression"],
            block_scoped=True,
            # Taint analysis
            taint_source_patterns=[("std::env::var", "env_var"), ("stdin", "user_input")],
            taint_sink_patterns=[("Command::new", "system_cmd")],
            taint_sanitizer_patterns=[],
            # CFG control flow
            cfg_if_node_types=["if_expression"],
            cfg_else_node_types=["else_clause"],
            cfg_for_node_types=["for_expression"],
            cfg_while_node_types=["while_expression", "loop_expression"],
            cfg_try_node_types=[],
            cfg_switch_node_types=["match_expression"],
            # Resource tracking
            resource_patterns=[
                ("File::open", "drop", False, "file"),
                ("TcpStream::connect", "drop", False, "connection"),
            ],
            # Type inference
            literal_type_map={
                "integer_literal": "INT",
                "float_literal": "FLOAT",
                "string_literal": "STRING",
                "char_literal": "STRING",
                "boolean_literal": "BOOL",
            },
            nullable_return_patterns=[],
            # Class analysis
            self_keyword="self",
        ),
        "java": LanguageConfig(
            ts_language_name="java",
            import_node_types=["import_declaration"],
            function_node_types=["method_declaration", "constructor_declaration"],
            catch_node_types=["catch_clause"],
            catch_body_field="body",
            return_node_types=["return_statement"],
            break_node_types=["break_statement"],
            continue_node_types=["continue_statement"],
            throw_node_types=["throw_statement"],
            builtin_names={
                "System",
                "String",
                "Integer",
                "Double",
                "Float",
                "Boolean",
                "Long",
                "Short",
                "Byte",
                "Character",
                "Object",
                "Class",
                "Math",
                "Collections",
                "Arrays",
            },
            default_value_node_types=[],  # Java doesn't have mutable defaults
            parameter_node_types=["formal_parameters"],
            block_node_types=["block"],
            branch_node_types=[
                "if_statement",
                "else",
                "for_statement",
                "enhanced_for_statement",
                "while_statement",
                "do_statement",
                "switch_expression",
                "catch_clause",
                "ternary_expression",
                "binary_expression",
            ],
            pass_node_types=[],
            comment_node_types=["line_comment", "block_comment"],
            # Semantic extraction
            assignment_node_types=["local_variable_declaration", "assignment_expression"],
            call_node_types=["method_invocation", "object_creation_expression"],
            class_node_types=["class_declaration"],
            scope_boundary_types=["method_declaration", "constructor_declaration", "class_declaration"],
            attribute_access_types=["field_access"],
            block_scoped=True,
            # Taint analysis
            taint_source_patterns=[
                # HTTP request parameters (Servlet API)
                ("request.getParameter", "user_input"),
                ("request.getParameterValues", "user_input"),
                ("request.getParameterMap", "user_input"),
                ("request.getHeader", "user_input"),
                ("request.getHeaders", "user_input"),
                ("request.getCookies", "user_input"),
                ("request.getQueryString", "user_input"),
                ("request.getRequestURI", "user_input"),
                ("request.getRequestURL", "user_input"),
                ("request.getPathInfo", "user_input"),
                ("request.getInputStream", "user_input"),
                ("request.getReader", "user_input"),
                ("request.getPart", "user_input"),
                ("request.getParts", "user_input"),
                # Spring MVC (annotation-based — params come via method args)
                # These methods read from the request object directly
                ("request.getAttribute", "user_input"),
                ("model.getAttribute", "user_input"),
                # Spring multipart
                ("multipartFile.getOriginalFilename", "user_input"),
                ("multipartFile.getInputStream", "user_input"),
                # Console/file input
                ("Scanner.nextLine", "user_input"),
                ("Scanner.next", "user_input"),
                ("BufferedReader.readLine", "file_read"),
                ("Files.readString", "file_read"),
                ("Files.readAllLines", "file_read"),
                ("Files.readAllBytes", "file_read"),
                # Environment
                ("System.getenv", "env_var"),
                ("System.getProperty", "env_var"),
                # Database results (second-order injection)
                ("ResultSet.getString", "db_input"),
                ("ResultSet.getObject", "db_input"),
                ("ResultSet.getInt", "db_input"),
            ],
            taint_sink_patterns=[
                # SQL Injection (CWE-89) — JDBC
                ("Statement.execute", "sql_query"),
                ("Statement.executeQuery", "sql_query"),
                ("Statement.executeUpdate", "sql_query"),
                ("PreparedStatement.execute", "sql_query"),
                ("createStatement", "sql_query"),
                ("prepareCall", "sql_query"),
                ("prepareStatement", "sql_query"),
                ("executeQuery", "sql_query"),
                ("executeUpdate", "sql_query"),
                # SQL — Spring JdbcTemplate
                ("JdbcTemplate.query", "sql_query"),
                ("JdbcTemplate.queryForObject", "sql_query"),
                ("JdbcTemplate.queryForList", "sql_query"),
                ("JdbcTemplate.queryForMap", "sql_query"),
                ("JdbcTemplate.update", "sql_query"),
                ("JdbcTemplate.execute", "sql_query"),
                ("JdbcTemplate.batchUpdate", "sql_query"),
                ("NamedParameterJdbcTemplate.query", "sql_query"),
                ("NamedParameterJdbcTemplate.update", "sql_query"),
                # SQL — JPA/Hibernate native queries (bypass parameterization)
                ("EntityManager.createNativeQuery", "sql_query"),
                ("entityManager.createNativeQuery", "sql_query"),
                ("Session.createSQLQuery", "sql_query"),
                ("session.createSQLQuery", "sql_query"),
                # Command Injection (CWE-78)
                ("Runtime.exec", "system_cmd"),
                ("runtime.exec", "system_cmd"),
                ("getRuntime().exec", "system_cmd"),
                ("new ProcessBuilder(", "system_cmd"),
                # LDAP Injection (CWE-90)
                ("DirContext.search", "ldap_query"),
                ("InitialDirContext.search", "ldap_query"),
                ("ctx.search", "ldap_query"),
                ("dirContext.search", "ldap_query"),
                # XPath Injection (CWE-643)
                ("XPath.evaluate", "xpath_query"),
                ("XPath.compile", "xpath_query"),
                ("XPathExpression.evaluate", "xpath_query"),
                ("xpath.evaluate", "xpath_query"),
                ("xpath.compile", "xpath_query"),
                ("xp.evaluate", "xpath_query"),
                ("xp.compile", "xpath_query"),
                # XXE (CWE-611)
                ("DocumentBuilderFactory.newInstance", "xxe"),
                ("SAXParserFactory.newInstance", "xxe"),
                ("XMLInputFactory.newInstance", "xxe"),
                # Path Traversal (CWE-22)
                ("new File(", "file_path"),
                ("new FileInputStream(", "file_path"),
                ("new FileOutputStream(", "file_path"),
                ("new FileReader(", "file_path"),
                ("new FileWriter(", "file_path"),
                ("Paths.get", "file_path"),
                ("Files.newInputStream", "file_path"),
                ("Files.copy", "file_path"),
                ("Files.move", "file_path"),
                # XSS (CWE-79) — output sinks
                ("response.getWriter", "http_response"),
                ("response.getOutputStream", "http_response"),
                ("PrintWriter.print", "http_response"),
                ("PrintWriter.println", "http_response"),
                ("PrintWriter.write", "http_response"),
                ("PrintWriter.format", "http_response"),
                ("PrintWriter.printf", "http_response"),
                ("PrintWriter.append", "http_response"),
                # HTTP headers and redirects
                ("response.setHeader", "http_header"),
                ("response.addHeader", "http_header"),
                ("response.sendRedirect", "http_redirect"),
                # Log injection
                ("Logger.info", "log_injection"),
                ("Logger.warning", "log_injection"),
                ("Logger.severe", "log_injection"),
                ("logger.info", "log_injection"),
                ("logger.warn", "log_injection"),
                ("logger.error", "log_injection"),
                ("log.info", "log_injection"),
                ("log.warn", "log_injection"),
                ("log.error", "log_injection"),
                # Trust Boundary (CWE-501)
                ("session.setAttribute", "trust_boundary"),
                ("session.putValue", "trust_boundary"),
                ("request.getSession().setAttribute", "trust_boundary"),
                # SSRF
                ("URL.openConnection", "ssrf"),
                ("URL.openStream", "ssrf"),
                ("HttpURLConnection.connect", "ssrf"),
                ("HttpClient.send", "ssrf"),
                ("RestTemplate.getForObject", "ssrf"),
                ("RestTemplate.postForObject", "ssrf"),
                ("RestTemplate.exchange", "ssrf"),
                ("WebClient.get", "ssrf"),
                ("WebClient.post", "ssrf"),
            ],
            taint_sanitizer_patterns=[
                # Encoding/escaping
                "StringEscapeUtils.escapeHtml",
                "StringEscapeUtils.escapeSql",
                "StringEscapeUtils.escapeXml",
                "ESAPI.encoder",
                "URLEncoder.encode",
                "HtmlUtils.htmlEscape",
                # Type conversion (converts string to non-injectable type)
                "Integer.parseInt",
                "Integer.valueOf",
                "Long.parseLong",
                "Long.valueOf",
                "Double.parseDouble",
                "Float.parseFloat",
                "Boolean.parseBoolean",
                # Path sanitization
                "Paths.get",
                "FilenameUtils.getName",
                "FilenameUtils.normalize",
                "Path.normalize",
                # Prepared statement binding (parameterized queries)
                "PreparedStatement.set",
                "setString",
                "setInt",
                "setLong",
                # Input validation
                "Pattern.matches",
                "String.matches",
                "Validator.validate",
                "StringUtils.isNumeric",
                "StringUtils.isAlpha",
                "StringUtils.isAlphanumeric",
                # LDAP encoding
                "LdapEncoder.filterEncode",
                "LdapNameBuilder",
                # JPA/Hibernate parameterized queries (safe by default)
                "EntityManager.createQuery",
                "entityManager.createQuery",
                "CriteriaBuilder",
                "CriteriaQuery",
                "Session.createQuery",
                "session.createQuery",
                # Spring Data (parameterized by default)
                "findById",
                "findAll",
                "findBy",
                "save",
                "saveAll",
                "deleteById",
                # XXE protection
                "setFeature",
                "setAttribute",
            ],
            # CFG control flow
            cfg_if_node_types=["if_statement"],
            cfg_else_node_types=["else"],
            cfg_for_node_types=["for_statement", "enhanced_for_statement"],
            cfg_while_node_types=["while_statement", "do_statement"],
            cfg_try_node_types=["try_statement"],
            cfg_switch_node_types=["switch_expression"],
            # Resource tracking
            resource_patterns=[
                ("new FileInputStream", "close", True, "stream"),
                ("new BufferedReader", "close", True, "reader"),
                ("DriverManager.getConnection", "close", True, "connection"),
                ("new Socket", "close", True, "socket"),
            ],
            # Type inference
            literal_type_map={
                "decimal_integer_literal": "INT",
                "decimal_floating_point_literal": "FLOAT",
                "string_literal": "STRING",
                "character_literal": "STRING",
                "true": "BOOL",
                "false": "BOOL",
                "null_literal": "NONE",
            },
            nullable_return_patterns=[".get", ".find", ".findFirst"],
            # Class analysis
            self_keyword="this",
        ),
        "csharp": LanguageConfig(
            ts_language_name="csharp",
            import_node_types=["using_directive"],
            function_node_types=["method_declaration", "constructor_declaration"],
            catch_node_types=["catch_clause"],
            catch_body_field="body",
            return_node_types=["return_statement"],
            break_node_types=["break_statement"],
            continue_node_types=["continue_statement"],
            throw_node_types=["throw_statement", "throw_expression"],
            builtin_names={
                "Console",
                "String",
                "Int32",
                "Double",
                "Boolean",
                "Object",
                "Math",
                "Convert",
                "Array",
                "List",
                "Dictionary",
            },
            default_value_node_types=[],  # C# doesn't have mutable defaults in the same way
            parameter_node_types=["parameter_list"],
            block_node_types=["block"],
            branch_node_types=[
                "if_statement",
                "else_clause",
                "for_statement",
                "for_each_statement",
                "while_statement",
                "do_statement",
                "switch_section",
                "catch_clause",
                "conditional_expression",
                "binary_expression",
            ],
            pass_node_types=[],
            comment_node_types=["comment"],
            # Semantic extraction
            assignment_node_types=["variable_declarator", "assignment_expression"],
            call_node_types=["invocation_expression"],
            class_node_types=["class_declaration"],
            scope_boundary_types=["method_declaration", "constructor_declaration", "class_declaration"],
            attribute_access_types=["member_access_expression"],
            block_scoped=True,
            # Taint analysis
            taint_source_patterns=[
                ("Request.Form", "user_input"),
                ("Request.QueryString", "user_input"),
                ("Console.ReadLine", "user_input"),
                ("Environment.GetEnvironmentVariable", "env_var"),
            ],
            taint_sink_patterns=[
                ("Process.Start", "system_cmd"),
                ("SqlCommand", "sql_query"),
                ("ExecuteNonQuery", "sql_query"),
            ],
            taint_sanitizer_patterns=[
                "HttpUtility.HtmlEncode",
                "WebUtility.HtmlEncode",
                "Uri.EscapeDataString",
                "int.Parse",
                "int.TryParse",
                "Path.GetFileName",
                "AntiXssEncoder.HtmlEncode",
            ],
            # CFG control flow
            cfg_if_node_types=["if_statement"],
            cfg_else_node_types=["else_clause"],
            cfg_for_node_types=["for_statement", "for_each_statement"],
            cfg_while_node_types=["while_statement", "do_statement"],
            cfg_try_node_types=["try_statement"],
            cfg_switch_node_types=["switch_statement"],
            # Resource tracking
            resource_patterns=[
                ("new StreamReader", "Dispose", True, "stream"),
                ("new SqlConnection", "Dispose", True, "connection"),
                ("File.Open", "Dispose", True, "file"),
            ],
            # Type inference
            literal_type_map={
                "integer_literal": "INT",
                "real_literal": "FLOAT",
                "string_literal": "STRING",
                "character_literal": "STRING",
                "boolean_literal": "BOOL",
                "null_literal": "NONE",
            },
            nullable_return_patterns=[".Find", ".FirstOrDefault", ".SingleOrDefault"],
            # Class analysis
            self_keyword="this",
        ),
    }
)


def get_config(language: str) -> LanguageConfig | None:
    """Get tree-sitter config for a dojigiri language name. Returns None if unsupported."""
    return LANGUAGE_CONFIGS.get(language)
