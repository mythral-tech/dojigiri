import * as vscode from "vscode";
import { execFile, spawn } from "child_process";
import * as path from "path";

// ─── Types matching dojigiri JSON output ────────────────────────────

interface DojiFinding {
  file: string;
  line: number;
  column?: number;
  end_line?: number;
  end_column?: number;
  severity: "critical" | "warning" | "info";
  category: string;
  source: string;
  rule: string;
  message: string;
  suggestion?: string;
  snippet?: string;
  confidence?: string;
  cwe?: string;
  nist?: string;
}

interface DojiFileAnalysis {
  path: string;
  language: string;
  lines: number;
  findings: DojiFinding[];
}

interface DojiScanReport {
  root: string;
  mode: string;
  files_scanned: number;
  total_findings: number;
  critical: number;
  warnings: number;
  info: number;
  files: DojiFileAnalysis[];
}

// ─── Severity mapping ───────────────────────────────────────────────

const SEVERITY_MAP: Record<string, vscode.DiagnosticSeverity> = {
  critical: vscode.DiagnosticSeverity.Error,
  warning: vscode.DiagnosticSeverity.Warning,
  info: vscode.DiagnosticSeverity.Information,
};

// ─── State ──────────────────────────────────────────────────────────

let diagnosticCollection: vscode.DiagnosticCollection;
let statusBarItem: vscode.StatusBarItem;
let typingTimers: Map<string, NodeJS.Timeout> = new Map();

const DEBOUNCE_MS = 1500;

// ─── Activation ─────────────────────────────────────────────────────

export function activate(context: vscode.ExtensionContext): void {
  diagnosticCollection =
    vscode.languages.createDiagnosticCollection("dojigiri");
  context.subscriptions.push(diagnosticCollection);

  // Status bar
  statusBarItem = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left,
    100
  );
  statusBarItem.command = "workbench.actions.view.problems";
  statusBarItem.text = "$(shield) Dojigiri: 0";
  statusBarItem.tooltip = "Dojigiri findings";
  statusBarItem.show();
  context.subscriptions.push(statusBarItem);

  // Check installation
  checkInstallation();

  // Commands
  context.subscriptions.push(
    vscode.commands.registerCommand("dojigiri.scanFile", () => {
      const editor = vscode.window.activeTextEditor;
      if (editor) {
        scanFile(editor.document);
      } else {
        vscode.window.showWarningMessage("No active file to scan.");
      }
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("dojigiri.scanWorkspace", () => {
      scanWorkspace();
    })
  );

  // Code action provider for quick fixes
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      [
        { language: "python" },
        { language: "javascript" },
        { language: "typescript" },
        { language: "go" },
        { language: "rust" },
      ],
      new DojiCodeActionProvider(),
      { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }
    )
  );

  // Run on save
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((document) => {
      const config = vscode.workspace.getConfiguration("dojigiri");
      if (
        config.get<boolean>("runOnSave", true) &&
        isSupportedLanguage(document)
      ) {
        scanFile(document);
      }
    })
  );

  // Run on type (debounced)
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument((event) => {
      const config = vscode.workspace.getConfiguration("dojigiri");
      if (!config.get<boolean>("runOnType", false)) {
        return;
      }
      if (!isSupportedLanguage(event.document)) {
        return;
      }

      const uri = event.document.uri.toString();
      const existing = typingTimers.get(uri);
      if (existing) {
        clearTimeout(existing);
      }

      typingTimers.set(
        uri,
        setTimeout(() => {
          typingTimers.delete(uri);
          scanFile(event.document);
        }, DEBOUNCE_MS)
      );
    })
  );

  // Clean up diagnostics on close
  context.subscriptions.push(
    vscode.workspace.onDidCloseTextDocument((doc) => {
      diagnosticCollection.delete(doc.uri);
      updateStatusBarFromCollection();
    })
  );

  // Scan active file on activation
  if (vscode.window.activeTextEditor) {
    const doc = vscode.window.activeTextEditor.document;
    if (isSupportedLanguage(doc)) {
      scanFile(doc);
    }
  }
}

export function deactivate(): void {
  for (const timer of typingTimers.values()) {
    clearTimeout(timer);
  }
  typingTimers.clear();
}

// ─── Helpers ────────────────────────────────────────────────────────

const SUPPORTED_LANGUAGES = ["python", "javascript", "typescript", "go", "rust"];

function isSupportedLanguage(doc: vscode.TextDocument): boolean {
  return SUPPORTED_LANGUAGES.includes(doc.languageId);
}

function getConfig() {
  const config = vscode.workspace.getConfiguration("dojigiri");
  return {
    path: config.get<string>("path", "dojigiri"),
    minSeverity: config.get<string>("minSeverity", "warning"),
  };
}

// ─── Installation check ─────────────────────────────────────────────

function checkInstallation(): void {
  const { path: dojiPath } = getConfig();

  // Try direct executable first, then python -m fallback
  execFile(dojiPath, ["--version"], (error) => {
    if (error) {
      execFile("python", ["-m", "dojigiri", "--version"], (error2) => {
        if (error2) {
          vscode.window
            .showWarningMessage(
              "Dojigiri not found. Install it with: pip install dojigiri",
              "Install"
            )
            .then((selection) => {
              if (selection === "Install") {
                const terminal =
                  vscode.window.createTerminal("Dojigiri Install");
                terminal.show();
                terminal.sendText("pip install dojigiri");
              }
            });
        }
      });
    }
  });
}

// ─── Command building ───────────────────────────────────────────────

function buildScanArgs(filePath: string): { cmd: string; args: string[] } {
  const { path: dojiPath, minSeverity } = getConfig();

  const scanArgs = [
    "scan",
    filePath,
    "--output",
    "json",
    "--min-severity",
    minSeverity,
  ];

  // Support "python -m dojigiri" style paths
  if (dojiPath.includes(" ")) {
    const parts = dojiPath.split(/\s+/);
    return { cmd: parts[0], args: [...parts.slice(1), ...scanArgs] };
  }

  return { cmd: dojiPath, args: scanArgs };
}

// ─── Single file scan ───────────────────────────────────────────────

function scanFile(document: vscode.TextDocument): void {
  if (!isSupportedLanguage(document)) {
    return;
  }

  const filePath = document.uri.fsPath;
  const { cmd, args } = buildScanArgs(filePath);

  updateStatusBar("$(sync~spin) Scanning...");

  const proc = spawn(cmd, args, {
    cwd: vscode.workspace.workspaceFolders?.[0]?.uri.fsPath,
    shell: true,
  });

  let stdout = "";
  let stderr = "";

  proc.stdout.on("data", (data: Buffer) => {
    stdout += data.toString();
  });

  proc.stderr.on("data", (data: Buffer) => {
    stderr += data.toString();
  });

  proc.on("close", (code: number | null) => {
    if (code !== null && code > 1) {
      console.error(`dojigiri exited with code ${code}: ${stderr}`);
      updateStatusBar("$(error) Dojigiri error");
      return;
    }

    try {
      const report: DojiScanReport = JSON.parse(stdout);
      applyDiagnostics(document, report);
    } catch {
      if (stdout.trim()) {
        console.error("Failed to parse dojigiri output:", stdout);
      }
      updateStatusBar("$(shield) Dojigiri: 0");
    }
  });

  proc.on("error", (err: Error) => {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      // Try python -m fallback
      scanFileWithPythonFallback(document);
    } else {
      console.error("Failed to run dojigiri:", err);
      updateStatusBar("$(error) Dojigiri error");
    }
  });
}

function scanFileWithPythonFallback(document: vscode.TextDocument): void {
  const filePath = document.uri.fsPath;
  const { minSeverity } = getConfig();

  const args = [
    "-m",
    "dojigiri",
    "scan",
    filePath,
    "--output",
    "json",
    "--min-severity",
    minSeverity,
  ];

  const proc = spawn("python", args, {
    cwd: vscode.workspace.workspaceFolders?.[0]?.uri.fsPath,
    shell: true,
  });

  let stdout = "";

  proc.stdout.on("data", (data: Buffer) => {
    stdout += data.toString();
  });

  proc.on("close", (code: number | null) => {
    if (code !== null && code > 1) {
      updateStatusBar("$(error) Dojigiri error");
      return;
    }
    try {
      const report: DojiScanReport = JSON.parse(stdout);
      applyDiagnostics(document, report);
    } catch {
      updateStatusBar("$(shield) Dojigiri: 0");
    }
  });
}

// ─── Workspace scan ─────────────────────────────────────────────────

function scanWorkspace(): void {
  const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
  if (!workspaceFolder) {
    vscode.window.showWarningMessage("No workspace folder open.");
    return;
  }

  const folderPath = workspaceFolder.uri.fsPath;
  const { path: dojiPath, minSeverity } = getConfig();

  const scanArgs = [
    "scan",
    folderPath,
    "--output",
    "json",
    "--min-severity",
    minSeverity,
  ];

  let cmd: string;
  let args: string[];
  if (dojiPath.includes(" ")) {
    const parts = dojiPath.split(/\s+/);
    cmd = parts[0];
    args = [...parts.slice(1), ...scanArgs];
  } else {
    cmd = dojiPath;
    args = scanArgs;
  }

  vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "Dojigiri: Scanning workspace...",
      cancellable: true,
    },
    (_progress, token) => {
      return new Promise<void>((resolve) => {
        updateStatusBar("$(sync~spin) Scanning workspace...");

        const proc = spawn(cmd, args, {
          cwd: folderPath,
          shell: true,
        });

        token.onCancellationRequested(() => {
          proc.kill();
          updateStatusBar("$(shield) Dojigiri: 0");
          resolve();
        });

        let stdout = "";

        proc.stdout.on("data", (data: Buffer) => {
          stdout += data.toString();
        });

        proc.on("close", (code: number | null) => {
          if (code !== null && code > 1) {
            vscode.window.showErrorMessage(
              "Dojigiri scan failed. Check the output for details."
            );
            updateStatusBar("$(error) Dojigiri error");
            resolve();
            return;
          }

          try {
            const report: DojiScanReport = JSON.parse(stdout);
            diagnosticCollection.clear();

            for (const fileAnalysis of report.files) {
              const fileUri = vscode.Uri.file(
                path.resolve(folderPath, fileAnalysis.path)
              );
              const diagnostics = fileAnalysis.findings.map((f) =>
                findingToDiagnostic(f)
              );
              diagnosticCollection.set(fileUri, diagnostics);
            }

            updateStatusBarFromCollection();
            vscode.window.showInformationMessage(
              `Dojigiri: ${report.total_findings} finding(s) in ${report.files_scanned} file(s)`
            );
          } catch {
            updateStatusBar("$(shield) Dojigiri: 0");
          }

          resolve();
        });
      });
    }
  );
}

// ─── Diagnostics ────────────────────────────────────────────────────

function findingToDiagnostic(finding: DojiFinding): vscode.Diagnostic {
  const line = Math.max(0, (finding.line || 1) - 1);
  const col = Math.max(0, (finding.column || 1) - 1);
  const endLine = finding.end_line ? finding.end_line - 1 : line;
  const endCol = finding.end_column
    ? finding.end_column - 1
    : Number.MAX_SAFE_INTEGER;

  const range = new vscode.Range(line, col, endLine, endCol);
  const severity =
    SEVERITY_MAP[finding.severity] ?? vscode.DiagnosticSeverity.Warning;

  // Format: [rule-name] message (CWE-XXX)
  let message = `[${finding.rule}] ${finding.message}`;
  if (finding.cwe) {
    message += ` (${finding.cwe})`;
  }

  const diagnostic = new vscode.Diagnostic(range, message, severity);
  diagnostic.source = "dojigiri";
  diagnostic.code = finding.rule;

  // Store suggestion in relatedInformation for the code action provider
  if (finding.suggestion) {
    diagnostic.relatedInformation = [
      new vscode.DiagnosticRelatedInformation(
        new vscode.Location(
          vscode.Uri.file(finding.file),
          new vscode.Position(line, 0)
        ),
        `Fix: ${finding.suggestion}`
      ),
    ];
  }

  // Tag dead code as unnecessary (faded in editor)
  if (finding.category === "dead_code") {
    diagnostic.tags = [vscode.DiagnosticTag.Unnecessary];
  }

  return diagnostic;
}

function applyDiagnostics(
  document: vscode.TextDocument,
  report: DojiScanReport
): void {
  const allFindings: DojiFinding[] = [];

  for (const fileAnalysis of report.files) {
    for (const finding of fileAnalysis.findings) {
      finding.file = document.uri.fsPath;
      allFindings.push(finding);
    }
  }

  const diagnostics = allFindings.map((f) => findingToDiagnostic(f));
  diagnosticCollection.set(document.uri, diagnostics);

  updateStatusBarFromCollection();
}

// ─── Code Actions (Quick Fixes) ─────────────────────────────────────

class DojiCodeActionProvider implements vscode.CodeActionProvider {
  provideCodeActions(
    document: vscode.TextDocument,
    _range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];

    for (const diagnostic of context.diagnostics) {
      if (diagnostic.source !== "dojigiri") {
        continue;
      }

      // Extract suggestion from relatedInformation
      const suggestion = diagnostic.relatedInformation?.[0]?.message;
      if (!suggestion) {
        continue;
      }

      // Strip the "Fix: " prefix
      const suggestionText = suggestion.startsWith("Fix: ")
        ? suggestion.slice(5)
        : suggestion;

      const action = new vscode.CodeAction(
        `Dojigiri: ${suggestionText}`,
        vscode.CodeActionKind.QuickFix
      );
      action.diagnostics = [diagnostic];
      action.isPreferred = true;

      // Insert suggestion as a comment above the flagged line
      const line = diagnostic.range.start.line;
      const indent = document.lineAt(line).text.match(/^\s*/)?.[0] ?? "";
      const commentPrefix = getCommentPrefix(document.languageId);
      const commentText = `${indent}${commentPrefix} TODO(dojigiri): ${suggestionText}\n`;

      action.edit = new vscode.WorkspaceEdit();
      action.edit.insert(
        document.uri,
        new vscode.Position(line, 0),
        commentText
      );

      actions.push(action);
    }

    return actions;
  }
}

function getCommentPrefix(languageId: string): string {
  switch (languageId) {
    case "python":
      return "#";
    default:
      return "//";
  }
}

// ─── Status Bar ─────────────────────────────────────────────────────

function updateStatusBar(text: string): void {
  statusBarItem.text = text;
}

function updateStatusBarFromCollection(): void {
  let total = 0;
  diagnosticCollection.forEach((_uri, diagnostics) => {
    total += diagnostics.length;
  });

  if (total === 0) {
    statusBarItem.text = "$(shield) Dojigiri: 0";
    statusBarItem.backgroundColor = undefined;
  } else {
    statusBarItem.text = `$(shield) Dojigiri: ${total}`;
    statusBarItem.backgroundColor = new vscode.ThemeColor(
      "statusBarItem.warningBackground"
    );
  }
}
