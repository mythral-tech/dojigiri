"""Control Flow Graph construction from tree-sitter AST.

Builds a per-function CFG with basic blocks, successor/predecessor edges,
entry/exit blocks. Used by path-sensitive taint analysis and resource leak
detection. Returns empty dict when tree-sitter is not available.

Called by: detector.py, taint.py, nullsafety.py, resource.py, types.py
Calls into: semantic/lang_config.py, semantic/core.py
Data in → Data out: FileSemantics + source bytes → dict[scope_id, FunctionCFG]
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .core import FileSemantics, FunctionDef
from .lang_config import LanguageConfig

# ─── Data structures ─────────────────────────────────────────────────


@dataclass
class CfgStatement:
    line: int
    kind: str  # "assignment", "call", "return", "break", "continue", "other"
    text: str
    assignment_idx: int | None = None  # index into FileSemantics.assignments
    call_idx: int | None = None  # index into FileSemantics.function_calls
    # Additional indices when multiple assignments/calls share the same line
    # (e.g., `a = 1; b = 2` or `foo(); bar()`)
    extra_assignment_idxs: list[int] = field(default_factory=list)
    extra_call_idxs: list[int] = field(default_factory=list)


@dataclass
class BasicBlock:
    id: int
    statements: list[CfgStatement] = field(default_factory=list)
    successors: list[int] = field(default_factory=list)
    predecessors: list[int] = field(default_factory=list)
    is_entry: bool = False
    is_exit: bool = False


@dataclass
class FunctionCFG:
    function_name: str
    qualified_name: str
    scope_id: int
    entry_block: int
    exit_block: int
    blocks: dict[int, BasicBlock] = field(default_factory=dict)
    line_to_block: dict[int, int] = field(default_factory=dict)


# ─── Helpers ─────────────────────────────────────────────────────────

from ._utils import _get_text, _line  # noqa: E402

# ─── CFG Builder ─────────────────────────────────────────────────────


class _CfgBuilder:
    """Builds a CFG for a single function body."""

    def __init__(self, source_bytes: bytes, config: LanguageConfig, semantics: FileSemantics, fdef: FunctionDef):
        self.src = source_bytes
        self.config = config
        self.semantics = semantics
        self.fdef = fdef

        self._block_counter = 0
        self.blocks: dict[int, BasicBlock] = {}
        self.line_to_block: dict[int, int] = {}

        # Pre-compute lookup sets
        self._if_types = set(config.cfg_if_node_types)
        self._else_types = set(config.cfg_else_node_types)
        self._for_types = set(config.cfg_for_node_types)
        self._while_types = set(config.cfg_while_node_types)
        self._try_types = set(config.cfg_try_node_types)
        self._switch_types = set(config.cfg_switch_node_types)
        self._return_types = set(config.return_node_types)
        self._break_types = set(config.break_node_types)
        self._continue_types = set(config.continue_node_types)
        self._throw_types = set(config.throw_node_types)
        self._func_types = set(config.function_node_types)

        # Build assignment/call index lookups by line (lists to handle
        # multiple statements on the same line, e.g. `a = 1; b = 2`)
        self._asgn_by_line: dict[int, list[int]] = {}
        for i, a in enumerate(semantics.assignments):
            if fdef.line <= a.line <= fdef.end_line:
                self._asgn_by_line.setdefault(a.line, []).append(i)
        self._call_by_line: dict[int, list[int]] = {}
        for i, c in enumerate(semantics.function_calls):
            if fdef.line <= c.line <= fdef.end_line:
                self._call_by_line.setdefault(c.line, []).append(i)

        # Loop context stack for break/continue: (header_block, exit_block)
        self._loop_stack: list[tuple[int, int]] = []

    def _new_block(self, is_entry=False, is_exit=False) -> BasicBlock:
        self._block_counter += 1
        blk = BasicBlock(id=self._block_counter, is_entry=is_entry, is_exit=is_exit)
        self.blocks[blk.id] = blk
        return blk

    def _link(self, from_id: int, to_id: int) -> None:
        """Add a directed edge from_id → to_id."""
        if to_id not in self.blocks[from_id].successors:
            self.blocks[from_id].successors.append(to_id)
        if from_id not in self.blocks[to_id].predecessors:
            self.blocks[to_id].predecessors.append(from_id)

    def _add_stmt(self, block: BasicBlock, node) -> CfgStatement:
        line_num = _line(node)
        text = _get_text(node, self.src)[:120]

        kind = "other"
        ntype = node.type
        if ntype in self._return_types:
            kind = "return"
        elif ntype in self._break_types:
            kind = "break"
        elif ntype in self._continue_types:
            kind = "continue"
        elif ntype in self._throw_types:
            kind = "throw"
        else:
            # Check if this line has assignment or call
            if line_num in self._asgn_by_line:
                kind = "assignment"
            elif line_num in self._call_by_line:
                kind = "call"

        asgn_idxs = self._asgn_by_line.get(line_num, [])
        call_idxs = self._call_by_line.get(line_num, [])
        stmt = CfgStatement(
            line=line_num,
            kind=kind,
            text=text,
            assignment_idx=asgn_idxs[0] if asgn_idxs else None,
            call_idx=call_idxs[0] if call_idxs else None,
            extra_assignment_idxs=asgn_idxs[1:],
            extra_call_idxs=call_idxs[1:],
        )
        block.statements.append(stmt)
        self.line_to_block[line_num] = block.id
        return stmt

    def build(self, func_body_node) -> FunctionCFG:
        """Build CFG from function body AST node."""
        entry = self._new_block(is_entry=True)
        exit_block = self._new_block(is_exit=True)

        # Process the function body statements
        tail_blocks = self._process_body(func_body_node, entry, exit_block)

        # Link any remaining tail blocks to exit
        for tb in tail_blocks:
            if tb != exit_block.id:
                self._link(tb, exit_block.id)

        return FunctionCFG(
            function_name=self.fdef.name,
            qualified_name=self.fdef.qualified_name,
            scope_id=self.fdef.scope_id,
            entry_block=entry.id,
            exit_block=exit_block.id,
            blocks=self.blocks,
            line_to_block=self.line_to_block,
        )

    def _dispatch_statement(
        self, child, cur: BasicBlock, exit_block: BasicBlock,
    ) -> list[int] | None:
        """Dispatch a single statement node. Returns new tails, or None for regular statements."""
        ntype = child.type

        if ntype in self._if_types:
            return self._process_if(child, cur, exit_block)
        if ntype in self._for_types or ntype in self._while_types:
            return self._process_loop(child, cur, exit_block)
        if ntype in self._try_types:
            return self._process_try(child, cur, exit_block)
        if ntype in self._switch_types:
            return self._process_switch(child, cur, exit_block)

        if ntype in self._return_types or ntype in self._throw_types:
            self._add_stmt(cur, child)
            self._link(cur.id, exit_block.id)
            return []

        if ntype in self._break_types:
            self._add_stmt(cur, child)
            if self._loop_stack:
                _, loop_exit = self._loop_stack[-1]
                self._link(cur.id, loop_exit)
            return []

        if ntype in self._continue_types:
            self._add_stmt(cur, child)
            if self._loop_stack:
                loop_header, _ = self._loop_stack[-1]
                self._link(cur.id, loop_header)
            return []

        return None

    def _process_body(self, body_node, current_block: BasicBlock, exit_block: BasicBlock) -> list[int]:
        """Process a sequence of statements. Returns list of block IDs that
        are the 'tails' (blocks that fall through to the next statement)."""
        tails = [current_block.id]

        for child in self._get_statement_children(body_node):
            if not tails:
                break  # unreachable code after return/break/continue

            if child.type in self._func_types:
                continue

            # Merge tails into a single block if needed
            if len(tails) > 1:
                merge = self._new_block()
                for t in tails:
                    self._link(t, merge.id)
                tails = [merge.id]

            cur = self.blocks[tails[0]]
            result = self._dispatch_statement(child, cur, exit_block)
            if result is not None:
                tails = result
            else:
                self._add_stmt(cur, child)
                tails = [cur.id]

        return tails

    def _process_if(self, node, current_block: BasicBlock, exit_block: BasicBlock) -> list[int]:
        """Process if/elif/else chain. Returns tail block IDs."""
        # Add the condition as a statement on the current block
        condition = node.child_by_field_name("condition")
        if condition:
            self._add_stmt(current_block, condition)

        tails = []

        # Then branch (consequence)
        consequence = node.child_by_field_name("consequence") or node.child_by_field_name("body")
        if consequence is None:
            # Fallback: look for first block/body child
            for ch in node.children:
                if ch.type in ("block", "statement_block", "compound_statement"):
                    consequence = ch
                    break

        if consequence:
            then_block = self._new_block()
            self._link(current_block.id, then_block.id)
            then_tails = self._process_body(consequence, then_block, exit_block)
            tails.extend(then_tails)

        # Else / elif branch (alternative)
        alternative = node.child_by_field_name("alternative")
        if alternative:
            else_block = self._new_block()
            self._link(current_block.id, else_block.id)

            if alternative.type in self._if_types or alternative.type in self._else_types:
                # elif or else clause — check for nested if
                nested_if = None
                body_node = None
                for ch in alternative.children:
                    if ch.type in self._if_types:
                        nested_if = ch
                        break
                    if ch.type in ("block", "statement_block", "compound_statement"):
                        body_node = ch

                if nested_if:
                    else_tails = self._process_if(nested_if, else_block, exit_block)
                elif body_node:
                    else_tails = self._process_body(body_node, else_block, exit_block)
                else:
                    else_tails = self._process_body(alternative, else_block, exit_block)
                tails.extend(else_tails)
            else:
                else_tails = self._process_body(alternative, else_block, exit_block)
                tails.extend(else_tails)
        else:
            # No else — current block also falls through
            tails.append(current_block.id)

        return tails

    def _process_loop(self, node, current_block: BasicBlock, exit_block: BasicBlock) -> list[int]:
        """Process for/while loop. Returns tail block IDs (the loop exit)."""
        header = self._new_block()
        self._link(current_block.id, header.id)

        loop_exit = self._new_block()

        # Add condition to header
        condition = node.child_by_field_name("condition") or node.child_by_field_name("value")
        if condition:
            self._add_stmt(header, condition)

        # Header branches to body or exit
        self._link(header.id, loop_exit.id)

        # Find the loop body
        body = node.child_by_field_name("body")
        if body is None:
            for ch in node.children:
                if ch.type in ("block", "statement_block", "compound_statement"):
                    body = ch
                    break

        if body:
            body_block = self._new_block()
            self._link(header.id, body_block.id)

            self._loop_stack.append((header.id, loop_exit.id))
            body_tails = self._process_body(body, body_block, exit_block)
            self._loop_stack.pop()

            # Body loops back to header
            for bt in body_tails:
                self._link(bt, header.id)

        return [loop_exit.id]

    def _process_try(self, node, current_block: BasicBlock, exit_block: BasicBlock) -> list[int]:
        """Process try/catch/finally. Returns tail block IDs."""
        tails = []

        # Find try body
        try_body = node.child_by_field_name("body")
        if try_body is None:
            for ch in node.children:
                if ch.type in ("block", "statement_block", "compound_statement"):
                    try_body = ch
                    break

        if try_body:
            try_block = self._new_block()
            self._link(current_block.id, try_block.id)
            try_tails = self._process_body(try_body, try_block, exit_block)
            tails.extend(try_tails)

        # Find catch/except handlers
        catch_types = set(self.config.catch_node_types)
        for ch in node.children:
            if ch.type in catch_types:
                catch_block = self._new_block()
                self._link(current_block.id, catch_block.id)

                catch_body = ch.child_by_field_name("body")
                if catch_body is None:
                    # Look for block child
                    for sub in ch.children:
                        if sub.type in ("block", "statement_block", "compound_statement"):
                            catch_body = sub
                            break

                if catch_body:
                    catch_tails = self._process_body(catch_body, catch_block, exit_block)
                    tails.extend(catch_tails)
                else:
                    # Process catch node children directly
                    catch_tails = self._process_body(ch, catch_block, exit_block)
                    tails.extend(catch_tails)

        # Find finally block
        for ch in node.children:
            if ch.type in ("finally_clause", "finally"):
                finally_body = None
                for sub in ch.children:
                    if sub.type in ("block", "statement_block", "compound_statement"):
                        finally_body = sub
                        break
                if finally_body:
                    # Finally runs after all tails
                    if tails:
                        finally_block = self._new_block()
                        for t in tails:
                            self._link(t, finally_block.id)
                        finally_tails = self._process_body(finally_body, finally_block, exit_block)
                        tails = finally_tails

        if not tails:
            tails = [current_block.id]

        return tails

    def _process_switch(self, node, current_block: BasicBlock, exit_block: BasicBlock) -> list[int]:
        """Process switch/match statement. Returns tail block IDs."""
        tails = []

        for ch in node.children:
            if ch.type in (
                "switch_case",
                "switch_default",
                "match_arm",
                "expression_case",
                "type_case",
                "default_case",
                "switch_section",
            ):
                case_block = self._new_block()
                self._link(current_block.id, case_block.id)
                case_tails = self._process_body(ch, case_block, exit_block)
                tails.extend(case_tails)

        if not tails:
            tails = [current_block.id]

        return tails

    def _get_statement_children(self, node) -> list:
        """Get direct statement children of a body/block node.

        Unwraps container nodes like statement_list (Go) that just group
        statements without adding control flow.
        """
        # Container types that should be unwrapped (not treated as statements)
        _CONTAINER_TYPES = {
            "statement_list",  # Go
            "declaration_list",  # C#
            "expression_list",  # Go
        }

        children = []
        for ch in node.children:
            if not ch.is_named:
                continue
            if ch.type in ("comment", "line_comment", "block_comment"):
                continue
            if ch.type in _CONTAINER_TYPES:
                # Unwrap: recurse into container
                children.extend(self._get_statement_children(ch))
            else:
                children.append(ch)
        return children


# ─── Entry point ─────────────────────────────────────────────────────


def build_cfg(
    semantics: FileSemantics,
    source_bytes: bytes,
    config: LanguageConfig,
) -> dict[int, FunctionCFG]:
    """Build CFGs for all functions in the file.

    Uses the cached tree-sitter root from FileSemantics to avoid double parsing.
    Returns {scope_id: FunctionCFG} mapping.
    Returns empty dict if tree root is not cached or CFG types not configured.
    """
    if not config.cfg_if_node_types and not config.cfg_for_node_types:
        return {}

    root_node = getattr(semantics, "_tree_root", None)
    if root_node is None:
        return {}

    func_types = set(config.function_node_types)
    cfgs: dict[int, FunctionCFG] = {}

    # Map function defs by line for lookup
    fdef_by_line: dict[int, FunctionDef] = {}
    for fdef in semantics.function_defs:
        fdef_by_line[fdef.line] = fdef

    # Build mapping: fdef → function's own scope_id
    # (FunctionDef.scope_id is the OUTER scope where it's defined;
    #  we need the inner scope pushed in _handle_function)
    fdef_to_func_scope: dict[str, int] = {}
    for scope in semantics.scopes:
        if scope.kind == "function" and scope.name:
            fdef_to_func_scope[scope.name] = scope.scope_id

    # Walk the AST to find function nodes
    def find_functions(node) -> None:
        if node.type in func_types:
            func_line = node.start_point[0] + 1
            fdef = fdef_by_line.get(func_line)
            if fdef:
                # Find the function body
                body = node.child_by_field_name("body")
                if body is None:
                    for ch in node.children:
                        if ch.type in ("block", "statement_block", "compound_statement"):
                            body = ch
                            break
                if body:
                    builder = _CfgBuilder(source_bytes, config, semantics, fdef)
                    cfg = builder.build(body)
                    # Store by function's own scope ID (not the defining scope)
                    func_scope_id = fdef_to_func_scope.get(fdef.qualified_name, fdef.scope_id)
                    cfgs[func_scope_id] = cfg
            return  # Don't recurse into nested functions

        for child in node.children:
            find_functions(child)

    find_functions(root_node)
    return cfgs


def get_reverse_postorder(cfg: FunctionCFG) -> list[int]:
    """Return block IDs in reverse postorder (for forward dataflow analysis)."""
    visited = set()
    postorder = []

    def dfs(block_id: int) -> None:
        if block_id in visited:
            return
        visited.add(block_id)
        block = cfg.blocks.get(block_id)
        if block:
            for succ in block.successors:
                dfs(succ)
            postorder.append(block_id)

    dfs(cfg.entry_block)
    return list(reversed(postorder))
