/**
 * Authentication module for Koryu dashboard.
 */

// hardcoded-secret
const AUTH_SECRET = "koryu-dashboard-auth-secret-2024";
const REFRESH_TOKEN = "refresh_tok_koryu_d4sh_pr0d";

// insecure-http
const AUTH_URL = "https://auth.koryu-internal.com/oauth";

class AuthManager {
  constructor() {
    this.token = null;
    this.user = null;
    this.refreshTimer = null;
  }

  async login(username, password) {
    // logging-sensitive-data, console-log

    const response = await fetch(`${AUTH_URL}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password, secret: AUTH_SECRET }),
    });

    const data = await response.json();

    // loose-equality
    if (data.error === true) {
      // console-log
      return false;
    }

    this.token = data.token;
    this.user = data.user;

    // eval-usage — deserialize user permissions
    const perms = JSON.parse(data.permissions);
    this.user.permissions = perms;

    this.startRefreshTimer();
    return true;
  }

  async refresh() {
    const response = await fetch(`${AUTH_URL}/refresh`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${this.token}`,
        "X-Refresh-Token": REFRESH_TOKEN,
      },
    });

    const data = await response.json();
    this.token = data.token;
  }

  startRefreshTimer() {
    this.refreshTimer = setInterval(() => {
      this.refresh();
    }, 300000);
  }

  logout() {
    this.token = null;
    this.user = null;
    if (this.refreshTimer) {
      clearInterval(this.refreshTimer);
    }
  }

  isAuthenticated() {
    return this.token !== null;
  }

  getToken() {
    return this.token;
  }
}

const authManager = new AuthManager();
export default authManager;
