import * as vscode from 'vscode';
import { execFile } from 'child_process';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);

interface DojiFinding {
    file: string;
    line: number;
    severity: string;
    category: string;
    source: string;
    rule: string;
    message: string;
    suggestion?: string;
    snippet?: string;
}

interface DojiFileAnalysis {
    path: string;
    language: string;
    lines: number;
    findings: DojiFinding[];
}

interface DojiScanResult {
    files: DojiFileAnalysis[];
    total_findings: number;
}

const SEVERITY_MAP: Record<string, vscode.DiagnosticSeverity> = {
    critical: vscode.DiagnosticSeverity.Error,
    warning: vscode.DiagnosticSeverity.Warning,
    info: vscode.DiagnosticSeverity.Information,
};

export async function refreshDiagnostics(
    document: vscode.TextDocument,
    collection: vscode.DiagnosticCollection
): Promise<void> {
    const config = vscode.workspace.getConfiguration('doji');
    const pythonPath = config.get<string>('pythonPath', 'python');
    const minSeverity = config.get<string>('minSeverity', 'warning');

    const filePath = document.uri.fsPath;

    // Build command args
    const args = ['-m', 'doji', 'scan', filePath, '--output', 'json', '--no-cache'];
    if (minSeverity !== 'info') {
        args.push('--min-severity', minSeverity);
    }

    try {
        const { stdout } = await execFileAsync(pythonPath, args, {
            timeout: 30000,
            maxBuffer: 1024 * 1024,
        });

        const result: DojiScanResult = JSON.parse(stdout);
        const diagnostics: vscode.Diagnostic[] = [];

        for (const fileAnalysis of result.files || []) {
            for (const finding of fileAnalysis.findings) {
                const line = Math.max(0, finding.line - 1); // VS Code is 0-indexed
                const range = new vscode.Range(line, 0, line, 1000);

                const severity = SEVERITY_MAP[finding.severity] ?? vscode.DiagnosticSeverity.Warning;
                const diagnostic = new vscode.Diagnostic(range, finding.message, severity);

                diagnostic.source = 'doji';
                diagnostic.code = finding.rule;

                if (finding.suggestion) {
                    diagnostic.relatedInformation = [
                        new vscode.DiagnosticRelatedInformation(
                            new vscode.Location(document.uri, range),
                            finding.suggestion
                        ),
                    ];
                }

                diagnostics.push(diagnostic);
            }
        }

        collection.set(document.uri, diagnostics);
    } catch (error: any) {
        // Silently fail — don't block the editor
        if (error.code !== 'ENOENT') {
            console.error(`Dojigiri scan failed: ${error.message}`);
        }
    }
}

export function subscribeToDocumentChanges(
    context: vscode.ExtensionContext,
    collection: vscode.DiagnosticCollection
): void {
    // Clear diagnostics when document is closed
    context.subscriptions.push(
        vscode.workspace.onDidCloseTextDocument((doc) => {
            collection.delete(doc.uri);
        })
    );
}
