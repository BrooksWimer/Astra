import { create } from "zustand";
import type { RootStackParamList } from "../navigation/RootStack";

export type AssistantMessage = {
  id: string;
  role: "assistant" | "user";
  text: string;
  createdAt: number;
  suggestions?: string[];
  metaLabel?: string;
};

function createAssistantSessionId(): string {
  return `astra-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

type AssistantStore = {
  isOpen: boolean;
  isExpanded: boolean;
  sessionId: string;
  routeName: keyof RootStackParamList | null;
  routeParams: Record<string, unknown> | null;
  draft: string;
  messages: AssistantMessage[];
  openAssistant: (draft?: string) => void;
  closeAssistant: () => void;
  toggleExpanded: () => void;
  setRouteContext: (
    routeName: keyof RootStackParamList | null,
    routeParams?: Record<string, unknown> | null
  ) => void;
  setDraft: (draft: string) => void;
  appendMessage: (message: Omit<AssistantMessage, "id" | "createdAt">) => void;
  clearConversation: () => void;
};

export const useAssistantStore = create<AssistantStore>((set) => ({
  isOpen: false,
  isExpanded: false,
  sessionId: createAssistantSessionId(),
  routeName: null,
  routeParams: null,
  draft: "",
  messages: [],
  openAssistant: (draft) =>
    set((state) => ({
      isOpen: true,
      draft: typeof draft === "string" ? draft : state.draft,
    })),
  closeAssistant: () => set({ isOpen: false }),
  toggleExpanded: () =>
    set((state) => ({ isExpanded: !state.isExpanded })),
  setRouteContext: (routeName, routeParams = null) => set({ routeName, routeParams }),
  setDraft: (draft) => set({ draft }),
  appendMessage: (message) =>
    set((state) => ({
      messages: [
        ...state.messages,
        {
          ...message,
          id: `${Date.now()}-${state.messages.length}`,
          createdAt: Date.now(),
        },
      ],
    })),
  clearConversation: () =>
    set({
      messages: [],
      draft: "",
      sessionId: createAssistantSessionId(),
    }),
}));
