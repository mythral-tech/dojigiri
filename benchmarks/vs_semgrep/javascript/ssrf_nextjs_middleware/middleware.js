export function buildProxyUrl(rawUrl) {
  const url = new URL(rawUrl);
  url.searchParams.set("via", "proxy");
  return url.toString();
}

export function validateContentType(headers) {
  const ct = headers.get("content-type") || "";
  return ct.startsWith("application/json") || ct.startsWith("text/");
}
