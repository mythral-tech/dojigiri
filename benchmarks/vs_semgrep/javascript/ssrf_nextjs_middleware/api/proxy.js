import { buildProxyUrl, validateContentType } from "../middleware";

export default async function handler(req, res) {
  const { url } = req.query;

  if (!url) {
    return res.status(400).json({ error: "url parameter required" });
  }

  const proxyUrl = buildProxyUrl(url);

  try {
    const upstream = await fetch(proxyUrl);

    if (!validateContentType(upstream.headers)) {
      return res.status(415).json({ error: "unsupported content type" });
    }

    const body = await upstream.text();
    res.status(upstream.status).send(body);
  } catch (err) {
    res.status(502).json({ error: "upstream request failed" });
  }
}
