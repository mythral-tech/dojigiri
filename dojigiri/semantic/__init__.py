"""dojigiri.semantic — Tree-sitter based semantic analysis subsystem."""

from .lang_config import LanguageConfig, LANGUAGE_CONFIGS, get_config
from .core import (
    Assignment,
    NameReference,
    FunctionDef,
    FunctionCall,
    ClassDef,
    ScopeInfo,
    FileSemantics,
    extract_semantics,
)
from .checks import (
    check_unused_imports,
    check_unreachable_code,
    check_empty_catch,
    check_shadowed_builtins,
    check_function_complexity,
    check_too_many_args,
    check_mutable_defaults,
    ALL_CHECKS,
    run_tree_sitter_checks,
)
from .cfg import CfgStatement, BasicBlock, FunctionCFG, build_cfg, get_reverse_postorder
from .types import (
    InferredType,
    TypeInfo,
    FileTypeMap,
    FunctionContract,
    infer_types,
    infer_contracts,
)
from .taint import TaintSource, TaintSink, TaintPath, analyze_taint, analyze_taint_pathsensitive
from .scope import check_unused_variables, check_variable_shadowing, check_uninitialized_variables
from .smells import (
    SemanticSignature,
    check_god_class,
    check_feature_envy,
    check_long_method,
    check_near_duplicate_functions,
    build_semantic_signature,
    check_semantic_clones,
)
from .nullsafety import check_null_safety
from .resource import ResourceState, check_resource_leaks
from .explain import ExplainSection, FileExplanation, explain_file

__all__ = [
    # lang_config
    "LanguageConfig", "LANGUAGE_CONFIGS", "get_config",
    # core
    "Assignment", "NameReference", "FunctionDef", "FunctionCall",
    "ClassDef", "ScopeInfo", "FileSemantics", "extract_semantics",
    # checks
    "check_unused_imports", "check_unreachable_code", "check_empty_catch",
    "check_shadowed_builtins", "check_function_complexity", "check_too_many_args",
    "check_mutable_defaults", "ALL_CHECKS", "run_tree_sitter_checks",
    # cfg
    "CfgStatement", "BasicBlock", "FunctionCFG", "build_cfg", "get_reverse_postorder",
    # types
    "InferredType", "TypeInfo", "FileTypeMap", "FunctionContract",
    "infer_types", "infer_contracts",
    # taint
    "TaintSource", "TaintSink", "TaintPath", "analyze_taint", "analyze_taint_pathsensitive",
    # scope
    "check_unused_variables", "check_variable_shadowing", "check_uninitialized_variables",
    # smells
    "SemanticSignature", "check_god_class", "check_feature_envy", "check_long_method",
    "check_near_duplicate_functions", "build_semantic_signature", "check_semantic_clones",
    # nullsafety
    "check_null_safety",
    # resource
    "ResourceState", "check_resource_leaks",
    # explain
    "ExplainSection", "FileExplanation", "explain_file",
]
