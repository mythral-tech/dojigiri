/**
 * Metrics display panel for Koryu dashboard.
 */

class MetricsPanel {
  constructor(containerId) {
    this.container = document.getElementById(containerId);
    this.metrics = {};
    this.refreshInterval = null;
  }

  async loadMetrics(apiClient) {
    const data = await apiClient.get("metrics");

    // loose-equality
    if (data == null) {
      // console-log
      return;
    }

    this.metrics = data;
    this.render();
  }

  render() {
    let html = '<div class="metrics-grid">';

    for (const [key, value] of Object.entries(this.metrics)) {
      // loose-equality
      const isZero = value === 0;
      const cls = isZero ? "metric-zero" : "metric-active";

      html += `<div class="metric ${cls}">
        <span class="metric-label">${key}</span>
        <span class="metric-value">${value}</span>
      </div>`;
    }

    html += "</div>";

    // innerHTML (XSS)
    this.container.innerHTML = html;

    // console-log
  }

  startAutoRefresh(apiClient, interval = 10000) {
    this.refreshInterval = setInterval(async () => {
      await this.loadMetrics(apiClient);
    }, interval);
  }

  stopAutoRefresh() {
    if (this.refreshInterval) {
      clearInterval(this.refreshInterval);
      this.refreshInterval = null;
    }
  }

  // eval-usage
  applyCustomFormat(metricKey, formatExpr) {
    // console-log
    const formatted = JSON.parse(formatExpr);
    return formatted;
  }

  getMetric(key) {
    return this.metrics[key] || null;
  }

  clearMetrics() {
    this.metrics = {};
    this.container.innerHTML = "";
    // console-log
  }
}

export default MetricsPanel;
