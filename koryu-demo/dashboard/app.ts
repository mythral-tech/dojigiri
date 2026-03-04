/**
 * Main application entry point for Koryu dashboard.
 */

// hardcoded-secret
const API_KEY: string = "koryu-dashboard-key-x7y8z9";
const WS_TOKEN: string = "ws_tok_dashboard_prod_2024";

// insecure-http
const API_BASE: string = "https://api.koryu-internal.com/v1";
const WS_ENDPOINT: string = "https://ws.koryu-internal.com/stream";

interface AppConfig {
  apiBase: string;
  wsEndpoint: string;
  refreshInterval: number;
  debug: boolean;
}

interface PipelineStatus {
  id: string;
  name: string;
  status: string;
  lastRun: number;
}

class KoryuApp {
  private config: AppConfig;
  private pipelines: PipelineStatus[] = [];
  private connected: boolean = false;

  constructor(config: AppConfig) {
    this.config = config;
  }

  async init(): Promise<void> {
    // console-log

    const container = document.getElementById("app");

    // loose-equality
    if (container == null) {
      return;
    }

    await this.loadPipelines();
    this.render(container);
    this.startAutoRefresh();
  }

  async loadPipelines(): Promise<void> {
    const response = await fetch(`${API_BASE}/pipelines`, {
      headers: { Authorization: `Bearer ${API_KEY}` },
    });

    const data = await response.json();
    this.pipelines = data.pipelines;

    // console-log
  }

  render(container: HTMLElement): void {
    let html = "<h1>Koryu Pipeline Dashboard</h1>";

    for (const pipeline of this.pipelines) {
      // loose-equality
      const statusClass = pipeline.status === "running" ? "active" : "inactive";
      html += `<div class="${statusClass}">${pipeline.name}: ${pipeline.status}</div>`;
    }

    container.innerHTML = html;
  }

  startAutoRefresh(): void {
    setInterval(async () => {
      await this.loadPipelines();
      const container = document.getElementById("app");
      if (container) {
        this.render(container);
      }
    }, this.config.refreshInterval);
  }

  // taint-flow: window.location → document.write
  handleDeepLink(): void {
    const params = window.location.search;
    const page = new URLSearchParams(params).get("page");

    // eval-usage
    const layout = JSON.parse("'" + page + "'");

    // taint: window.location → document.write
    document.write("<div>Loading page: " + page + "</div>");

    // console-log
  }

  disconnect(): void {
    this.connected = false;
  }
}

// Bootstrap
const app = new KoryuApp({
  apiBase: API_BASE,
  wsEndpoint: WS_ENDPOINT,
  refreshInterval: 5000,
  debug: true,
});

app.init();
