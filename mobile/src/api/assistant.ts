import type {
  AssistantContextSyncRequest,
  AssistantContextSyncResponse,
  AssistantRequest,
  AssistantResponse,
} from "@netwise/shared";

const TIMEOUT_MS = 30000;

function base(serverBaseUrl: string, path: string): string {
  const trimmed = serverBaseUrl.replace(/\/+$/, "");
  return path.startsWith("/") ? `${trimmed}${path}` : `${trimmed}/${path}`;
}

export async function getAssistantReply(
  serverBaseUrl: string,
  request: AssistantRequest
): Promise<AssistantResponse> {
  const ctrl = new AbortController();
  const id = setTimeout(() => ctrl.abort(), TIMEOUT_MS);

  try {
    const res = await fetch(base(serverBaseUrl, "assistant"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
      signal: ctrl.signal,
    });
    clearTimeout(id);

    if (!res.ok) {
      throw new Error(`Assistant failed: ${res.status}`);
    }

    return res.json();
  } catch (error) {
    clearTimeout(id);
    throw error;
  }
}

export async function syncAssistantContext(
  serverBaseUrl: string,
  request: AssistantContextSyncRequest
): Promise<AssistantContextSyncResponse> {
  const ctrl = new AbortController();
  const id = setTimeout(() => ctrl.abort(), TIMEOUT_MS);

  try {
    const res = await fetch(base(serverBaseUrl, "assistant/context"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
      signal: ctrl.signal,
    });
    clearTimeout(id);

    if (!res.ok) {
      throw new Error(`Assistant context sync failed: ${res.status}`);
    }

    return res.json();
  } catch (error) {
    clearTimeout(id);
    throw error;
  }
}
