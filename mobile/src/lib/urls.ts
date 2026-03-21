export function normalizeBaseUrl(raw: string, defaultPort?: string): string {
  let value = raw.trim();
  if (!value) return "";

  if (!/^https?:\/\//i.test(value)) {
    value = `http://${value}`;
  }

  try {
    const url = new URL(value);
    if (defaultPort && !url.port) {
      url.port = defaultPort;
    }
    url.pathname = "";
    url.search = "";
    url.hash = "";
    return url.toString().replace(/\/$/, "");
  } catch {
    return value.replace(/\/+$/, "");
  }
}

export function deriveAdviceBaseUrl(agentBaseUrl: string): string | null {
  try {
    const url = new URL(agentBaseUrl);
    url.port = "3000";
    url.pathname = "";
    url.search = "";
    url.hash = "";
    return url.toString().replace(/\/$/, "");
  } catch {
    return null;
  }
}
