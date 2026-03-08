"""dojigiri.semantic — Tree-sitter based semantic analysis subsystem."""

from .cfg import BasicBlock, CfgStatement, FunctionCFG, build_cfg, get_reverse_postorder  # doji:ignore(unused-import)
from .checks import (  # doji:ignore(unused-import)
    ALL_CHECKS,
    check_empty_catch,
    check_function_complexity,
    check_mutable_defaults,
    check_shadowed_builtins,
    check_too_many_args,
    check_unreachable_code,
    check_unused_imports,
    run_tree_sitter_checks,
)
from .core import (  # doji:ignore(unused-import)
    Assignment,
    ClassDef,
    FileSemantics,
    FunctionCall,
    FunctionDef,
    NameReference,
    ScopeInfo,
    extract_semantics,
)
from .explain import ExplainSection, FileExplanation, explain_file  # doji:ignore(unused-import)
from .lang_config import LANGUAGE_CONFIGS, LanguageConfig, get_config  # doji:ignore(unused-import)
from .nullsafety import check_null_safety  # doji:ignore(unused-import)
from .resource import ResourceState, check_resource_leaks  # doji:ignore(unused-import)
from .scope import (  # doji:ignore(unused-import)
    check_uninitialized_variables,
    check_unused_variables,
    check_variable_shadowing,
)
from .smells import (  # doji:ignore(unused-import)
    SemanticSignature,
    build_semantic_signature,
    check_feature_envy,
    check_god_class,
    check_long_method,
    check_near_duplicate_functions,
    check_semantic_clones,
)
from .taint import (  # doji:ignore(unused-import)
    TaintPath,
    TaintSink,
    TaintSource,
    analyze_taint,
    analyze_taint_pathsensitive,
)
from .types import (  # doji:ignore(unused-import)
    FileTypeMap,
    FunctionContract,
    InferredType,
    TypeInfo,
    infer_contracts,
    infer_types,
)

__all__ = [
    # lang_config
    "LanguageConfig",
    "LANGUAGE_CONFIGS",
    "get_config",
    # core
    "Assignment",
    "NameReference",
    "FunctionDef",
    "FunctionCall",
    "ClassDef",
    "ScopeInfo",
    "FileSemantics",
    "extract_semantics",
    # checks
    "check_unused_imports",
    "check_unreachable_code",
    "check_empty_catch",
    "check_shadowed_builtins",
    "check_function_complexity",
    "check_too_many_args",
    "check_mutable_defaults",
    "ALL_CHECKS",
    "run_tree_sitter_checks",
    # cfg
    "CfgStatement",
    "BasicBlock",
    "FunctionCFG",
    "build_cfg",
    "get_reverse_postorder",
    # types
    "InferredType",
    "TypeInfo",
    "FileTypeMap",
    "FunctionContract",
    "infer_types",
    "infer_contracts",
    # taint
    "TaintSource",
    "TaintSink",
    "TaintPath",
    "analyze_taint",
    "analyze_taint_pathsensitive",
    # scope
    "check_unused_variables",
    "check_variable_shadowing",
    "check_uninitialized_variables",
    # smells
    "SemanticSignature",
    "check_god_class",
    "check_feature_envy",
    "check_long_method",
    "check_near_duplicate_functions",
    "build_semantic_signature",
    "check_semantic_clones",
    # nullsafety
    "check_null_safety",
    # resource
    "ResourceState",
    "check_resource_leaks",
    # explain
    "ExplainSection",
    "FileExplanation",
    "explain_file",
]
