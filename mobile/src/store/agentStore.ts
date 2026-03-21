import { create } from "zustand";
import type { AgentInfo } from "../api/agent";

type AgentState = {
  agentBaseUrl: string | null;
  adviceBaseUrl: string | null;
  agentInfo: AgentInfo | null;
  lastScanId: string | null;
  connectSession: (session: {
    agentBaseUrl: string;
    adviceBaseUrl: string;
    agentInfo: AgentInfo;
  }) => void;
  clearSession: () => void;
  setAdviceBaseUrl: (url: string | null) => void;
  setAgentInfo: (info: AgentInfo | null) => void;
  setLastScanId: (id: string | null) => void;
};

export const useAgentStore = create<AgentState>((set) => ({
  agentBaseUrl: null,
  adviceBaseUrl: null,
  agentInfo: null,
  lastScanId: null,
  connectSession: ({ agentBaseUrl, adviceBaseUrl, agentInfo }) =>
    set({ agentBaseUrl, adviceBaseUrl, agentInfo, lastScanId: null }),
  clearSession: () =>
    set({ agentBaseUrl: null, adviceBaseUrl: null, agentInfo: null, lastScanId: null }),
  setAdviceBaseUrl: (adviceBaseUrl) => set({ adviceBaseUrl }),
  setAgentInfo: (agentInfo) => set({ agentInfo }),
  setLastScanId: (lastScanId) => set({ lastScanId }),
}));

export function getAgentBaseUrl(): string | null {
  return useAgentStore.getState().agentBaseUrl;
}
