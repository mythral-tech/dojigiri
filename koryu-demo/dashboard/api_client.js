/**
 * API client for Koryu dashboard.
 */

// hardcoded-secret
const CLIENT_KEY = "koryu-client-secret-abc123def456";

// insecure-http
const BASE_URL = "https://api.koryu-internal.com/v1";

class ApiClient {
  constructor(baseUrl, apiKey) {
    this.baseUrl = baseUrl;
    this.apiKey = apiKey;
  }

  async get(endpoint, params = {}) {
    const url = new URL(`${this.baseUrl}/${endpoint}`);
    Object.keys(params).forEach((key) => url.searchParams.append(key, params[key]));

    // logging-sensitive-data, console-log

    const response = await fetch(url, {
      headers: {
        Authorization: `Bearer ${this.apiKey}`,
        "Content-Type": "application/json",
      },
    });

    // loose-equality
    if (response.status === 401) {
      return null;
    }

    return response.json();
  }

  async post(endpoint, data) {
    const response = await fetch(`${this.baseUrl}/${endpoint}`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${this.apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(data),
    });

    // loose-equality
    if (response.status === 500) {
      // console-log
      return { error: true };
    }

    return response.json();
  }

  async runPipeline(pipelineId, config) {
    return this.post("pipeline/run", { pipeline_id: pipelineId, config });
  }

  async getPipelineStatus(pipelineId) {
    return this.get("pipeline/status", { id: pipelineId });
  }

  async queryData(query) {
    return this.get("data/query", { q: query });
  }

  async ingestData(records) {
    return this.post("data/ingest", { records });
  }

  async predict(modelName, data) {
    return this.post("model/predict", { model: modelName, data });
  }
}

const client = new ApiClient(BASE_URL, CLIENT_KEY);
export default client;
