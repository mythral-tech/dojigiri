"""Per-language tree-sitter node type mappings for cross-language AST checks."""

from dataclasses import dataclass, field


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
            "print", "len", "range", "type", "int", "float", "str", "bool",
            "list", "dict", "set", "tuple", "open", "input", "sum", "min",
            "max", "sorted", "next", "id", "map", "filter", "zip", "hash",
            "iter", "bytes", "complex", "frozenset", "object", "super",
        },
        default_value_node_types=["list", "dictionary", "set"],
        parameter_node_types=["parameters"],
        block_node_types=["block"],
        branch_node_types=[
            "if_statement", "elif_clause", "for_statement", "while_statement",
            "try_statement", "except_clause", "with_statement",
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
            ("input", "user_input"), ("request.form", "user_input"),
            ("request.args", "user_input"), ("request.json", "user_input"),
            ("os.environ.get", "env_var"), ("os.environ", "env_var"),
            ("sys.argv", "user_input"), (".read", "file_read"),
        ],
        taint_sink_patterns=[
            ("cursor.execute", "sql_query"), ("execute", "sql_query"),
            ("eval", "eval"), ("exec", "eval"),
            ("os.system", "system_cmd"), ("subprocess.run", "system_cmd"),
            ("subprocess.call", "system_cmd"), ("subprocess.Popen", "system_cmd"),
        ],
        taint_sanitizer_patterns=[
            "html.escape", "bleach.clean", "markupsafe.escape",
        ],
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
            "integer": "INT", "float": "FLOAT", "string": "STRING",
            "true": "BOOL", "false": "BOOL", "none": "NONE",
            "list": "LIST", "dictionary": "DICT", "set": "SET",
        },
        nullable_return_patterns=[
            "dict.get", "re.search", "re.match", "re.fullmatch",
            ".get", "os.environ.get", "os.getenv",
        ],
        # Class analysis
        self_keyword="self",
    ),
}

# JS and TS share identical config except for ts_language_name
_JS_BASE = dict(
    import_node_types=["import_statement"],
    function_node_types=[
        "function_declaration", "arrow_function", "method_definition",
        "function",
    ],
    catch_node_types=["catch_clause"],
    catch_body_field="body",
    return_node_types=["return_statement"],
    break_node_types=["break_statement"],
    continue_node_types=["continue_statement"],
    throw_node_types=["throw_statement"],
    builtin_names={
        "console", "undefined", "NaN", "Infinity", "eval",
        "parseInt", "parseFloat", "isNaN", "isFinite",
        "encodeURI", "decodeURI", "encodeURIComponent",
        "decodeURIComponent", "Object", "Array", "String",
        "Number", "Boolean", "Symbol", "Map", "Set", "Promise",
    },
    default_value_node_types=["array", "object"],
    parameter_node_types=["formal_parameters"],
    block_node_types=["statement_block"],
    branch_node_types=[
        "if_statement", "else_clause", "for_statement",
        "for_in_statement", "while_statement", "do_statement",
        "switch_case", "catch_clause", "ternary_expression",
        "binary_expression",
    ],
    pass_node_types=[],
    comment_node_types=["comment"],
    assignment_node_types=["variable_declarator", "assignment_expression", "augmented_assignment_expression"],
    call_node_types=["call_expression"],
    class_node_types=["class_declaration"],
    scope_boundary_types=[
        "function_declaration", "arrow_function", "method_definition",
        "function", "class_declaration",
    ],
    attribute_access_types=["member_expression"],
    block_scoped=True,
    taint_source_patterns=[
        ("req.body", "user_input"), ("req.params", "user_input"),
        ("req.query", "user_input"), ("document.getElementById", "user_input"),
        ("window.location", "user_input"),
    ],
    taint_sink_patterns=[
        ("eval", "eval"), (".innerHTML", "html_output"),
        ("document.write", "html_output"),
        ("child_process.exec", "system_cmd"),
    ],
    taint_sanitizer_patterns=["DOMPurify.sanitize", "escapeHtml", "sanitizeHtml"],
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
        "number": "FLOAT", "string": "STRING",
        "true": "BOOL", "false": "BOOL", "null": "NONE",
        "undefined": "NONE", "array": "LIST", "object": "DICT",
    },
    nullable_return_patterns=[".find", ".match"],
    self_keyword="this",
)

LANGUAGE_CONFIGS.update({
    "javascript": LanguageConfig(ts_language_name="javascript", **_JS_BASE),
    "typescript": LanguageConfig(ts_language_name="typescript", **_JS_BASE),
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
            "len", "cap", "make", "new", "append", "copy", "delete",
            "close", "complex", "real", "imag", "panic", "recover",
            "print", "println",
        },
        default_value_node_types=[],  # Go doesn't have mutable defaults
        parameter_node_types=["parameter_list"],
        block_node_types=["block", "statement_list"],
        branch_node_types=[
            "if_statement", "for_statement", "expression_switch_statement",
            "type_switch_statement", "select_statement",
            "expression_case", "type_case", "default_case",
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
            ("r.FormValue", "user_input"), ("r.URL.Query", "user_input"),
            ("os.Getenv", "env_var"),
        ],
        taint_sink_patterns=[
            ("exec.Command", "system_cmd"), ("db.Exec", "sql_query"),
            ("db.Query", "sql_query"), ("fmt.Fprintf", "html_output"),
        ],
        taint_sanitizer_patterns=["html.EscapeString", "template.HTMLEscapeString"],
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
            "int_literal": "INT", "float_literal": "FLOAT",
            "interpreted_string_literal": "STRING", "raw_string_literal": "STRING",
            "true": "BOOL", "false": "BOOL", "nil": "NONE",
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
            "println", "eprintln", "print", "eprint", "format",
            "vec", "panic", "todo", "unimplemented", "unreachable",
            "assert", "assert_eq", "assert_ne", "dbg",
        },
        default_value_node_types=[],  # Rust doesn't have mutable defaults
        parameter_node_types=["parameters"],
        block_node_types=["block"],
        branch_node_types=[
            "if_expression", "else_clause", "for_expression",
            "while_expression", "loop_expression", "match_arm",
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
            "integer_literal": "INT", "float_literal": "FLOAT",
            "string_literal": "STRING", "char_literal": "STRING",
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
            "System", "String", "Integer", "Double", "Float", "Boolean",
            "Long", "Short", "Byte", "Character", "Object", "Class",
            "Math", "Collections", "Arrays",
        },
        default_value_node_types=[],  # Java doesn't have mutable defaults
        parameter_node_types=["formal_parameters"],
        block_node_types=["block"],
        branch_node_types=[
            "if_statement", "else", "for_statement", "enhanced_for_statement",
            "while_statement", "do_statement", "switch_expression",
            "catch_clause", "ternary_expression", "binary_expression",
        ],
        pass_node_types=[],
        comment_node_types=["line_comment", "block_comment"],
        # Semantic extraction
        assignment_node_types=["local_variable_declaration", "assignment_expression"],
        call_node_types=["method_invocation"],
        class_node_types=["class_declaration"],
        scope_boundary_types=["method_declaration", "constructor_declaration", "class_declaration"],
        attribute_access_types=["field_access"],
        block_scoped=True,
        # Taint analysis
        taint_source_patterns=[
            ("request.getParameter", "user_input"),
            ("Scanner.nextLine", "user_input"),
            ("System.getenv", "env_var"),
        ],
        taint_sink_patterns=[
            ("Runtime.exec", "system_cmd"),
            ("Statement.execute", "sql_query"),
            ("PreparedStatement.execute", "sql_query"),
        ],
        taint_sanitizer_patterns=["StringEscapeUtils.escapeHtml", "ESAPI.encoder"],
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
            "decimal_integer_literal": "INT", "decimal_floating_point_literal": "FLOAT",
            "string_literal": "STRING", "character_literal": "STRING",
            "true": "BOOL", "false": "BOOL", "null_literal": "NONE",
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
            "Console", "String", "Int32", "Double", "Boolean", "Object",
            "Math", "Convert", "Array", "List", "Dictionary",
        },
        default_value_node_types=[],  # C# doesn't have mutable defaults in the same way
        parameter_node_types=["parameter_list"],
        block_node_types=["block"],
        branch_node_types=[
            "if_statement", "else_clause", "for_statement",
            "for_each_statement", "while_statement", "do_statement",
            "switch_section", "catch_clause", "conditional_expression",
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
            ("Request.Form", "user_input"), ("Request.QueryString", "user_input"),
            ("Console.ReadLine", "user_input"),
            ("Environment.GetEnvironmentVariable", "env_var"),
        ],
        taint_sink_patterns=[
            ("Process.Start", "system_cmd"),
            ("SqlCommand", "sql_query"), ("ExecuteNonQuery", "sql_query"),
        ],
        taint_sanitizer_patterns=["HttpUtility.HtmlEncode", "WebUtility.HtmlEncode"],
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
            "integer_literal": "INT", "real_literal": "FLOAT",
            "string_literal": "STRING", "character_literal": "STRING",
            "boolean_literal": "BOOL", "null_literal": "NONE",
        },
        nullable_return_patterns=[".Find", ".FirstOrDefault", ".SingleOrDefault"],
        # Class analysis
        self_keyword="this",
    ),
})


def get_config(language: str) -> LanguageConfig | None:
    """Get tree-sitter config for a wiz language name. Returns None if unsupported."""
    return LANGUAGE_CONFIGS.get(language)
