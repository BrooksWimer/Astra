import type { AssistantContextPayload } from "@netwise/shared";

const SESSION_TTL_MS = 6 * 60 * 60 * 1000;

export type AssistantSession = {
  id: string;
  context: AssistantContextPayload | null;
  lastResponseId: string | null;
  updatedAt: number;
};

const sessions = new Map<string, AssistantSession>();

function pruneExpiredSessions(now: number) {
  for (const [id, session] of sessions.entries()) {
    if (now - session.updatedAt > SESSION_TTL_MS) {
      sessions.delete(id);
    }
  }
}

function getOrCreateSession(sessionId: string): AssistantSession {
  const now = Date.now();
  pruneExpiredSessions(now);

  const existing = sessions.get(sessionId);

  if (existing) {
    existing.updatedAt = now;
    return existing;
  }

  const created: AssistantSession = {
    id: sessionId,
    context: null,
    lastResponseId: null,
    updatedAt: now,
  };
  sessions.set(sessionId, created);
  return created;
}

export function syncAssistantSessionContext(
  sessionId: string,
  context: AssistantContextPayload
): AssistantSession {
  const session = getOrCreateSession(sessionId);
  session.context = context;
  session.updatedAt = Date.now();
  return session;
}

export function getAssistantSession(sessionId: string): AssistantSession | null {
  const session = getOrCreateSession(sessionId);
  return session;
}

export function setAssistantSessionResponseId(
  sessionId: string,
  responseId: string | null
): AssistantSession {
  const session = getOrCreateSession(sessionId);
  session.lastResponseId = responseId;
  session.updatedAt = Date.now();
  return session;
}
