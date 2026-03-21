import type { AdviceRequest, AdviceResponse } from "@netwise/shared";

const TIMEOUT_MS = 15000;

function base(serverBaseUrl: string, path: string): string {
  const trimmed = serverBaseUrl.replace(/\/+$/, "");
  return path.startsWith("/") ? `${trimmed}${path}` : `${trimmed}/${path}`;
}

export async function getAdvice(
  serverBaseUrl: string,
  request: AdviceRequest
): Promise<AdviceResponse> {
  const ctrl = new AbortController();
  const id = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(base(serverBaseUrl, "advice"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
      signal: ctrl.signal,
    });
    clearTimeout(id);
    if (!res.ok) throw new Error(`Advice failed: ${res.status}`);
    return res.json();
  } catch (e) {
    clearTimeout(id);
    throw e;
  }
}
