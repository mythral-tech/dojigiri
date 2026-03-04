import * as vscode from 'vscode';

/**
 * Rules that have deterministic fixers in doji.
 * Maps rule name to a description of the fix.
 */
const FIXABLE_RULES: Record<string, string> = {
    'unused-import': 'Remove unused import',
    'bare-except': 'Replace with except Exception:',
    'loose-equality': 'Replace with strict equality (===)',
    'var-usage': 'Replace var with let',
    'none-comparison': 'Use is/is not None',
    'type-comparison': 'Use isinstance()',
    'console-log': 'Remove console.log()',
    'insecure-http': 'Upgrade to HTTPS',
    'fstring-no-expr': 'Remove unnecessary f-prefix',
    'hardcoded-secret': 'Use environment variable',
    'open-without-with': 'Wrap in with statement',
};

export class DojiCodeActionProvider implements vscode.CodeActionProvider {
    provideCodeActions(
        document: vscode.TextDocument,
        range: vscode.Range | vscode.Selection,
        context: vscode.CodeActionContext,
    ): vscode.CodeAction[] {
        const actions: vscode.CodeAction[] = [];

        for (const diagnostic of context.diagnostics) {
            if (diagnostic.source !== 'doji') {
                continue;
            }

            const rule = diagnostic.code as string;
            if (!rule || !(rule in FIXABLE_RULES)) {
                continue;
            }

            const fixDescription = FIXABLE_RULES[rule];
            const action = new vscode.CodeAction(
                `Dojigiri: ${fixDescription}`,
                vscode.CodeActionKind.QuickFix
            );

            action.diagnostics = [diagnostic];
            action.isPreferred = true;

            // Run doji fix for this specific rule on the file
            action.command = {
                command: 'doji.fixRule',
                title: fixDescription,
                arguments: [document.uri, rule, diagnostic.range.start.line + 1],
            };

            actions.push(action);
        }

        // Add "Fix all doji issues" action if there are multiple fixable diagnostics
        const dojiDiagnostics = context.diagnostics.filter(
            (d) => d.source === 'doji' && d.code && (d.code as string) in FIXABLE_RULES
        );

        if (dojiDiagnostics.length > 1) {
            const fixAll = new vscode.CodeAction(
                'Dojigiri: Fix all auto-fixable issues',
                vscode.CodeActionKind.QuickFix
            );
            fixAll.command = {
                command: 'doji.fixAll',
                title: 'Fix all doji issues',
                arguments: [document.uri],
            };
            actions.push(fixAll);
        }

        return actions;
    }
}

/**
 * Register fix commands. Call this from extension activate().
 */
export function registerFixCommands(context: vscode.ExtensionContext): void {
    // Fix a single rule at a specific line
    context.subscriptions.push(
        vscode.commands.registerCommand(
            'doji.fixRule',
            async (uri: vscode.Uri, rule: string, _line: number) => {
                const config = vscode.workspace.getConfiguration('doji');
                const pythonPath = config.get<string>('pythonPath', 'python');

                const terminal = vscode.window.createTerminal('Doji Fix');
                terminal.sendText(
                    `${pythonPath} -m dojigiri fix "${uri.fsPath}" --apply --rules ${rule}`
                );
                terminal.show();
            }
        )
    );

    // Fix all auto-fixable issues in a file
    context.subscriptions.push(
        vscode.commands.registerCommand(
            'doji.fixAll',
            async (uri: vscode.Uri) => {
                const config = vscode.workspace.getConfiguration('doji');
                const pythonPath = config.get<string>('pythonPath', 'python');

                const terminal = vscode.window.createTerminal('Doji Fix');
                terminal.sendText(
                    `${pythonPath} -m dojigiri fix "${uri.fsPath}" --apply`
                );
                terminal.show();
            }
        )
    );
}
