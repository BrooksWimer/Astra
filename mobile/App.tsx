import React from "react";
import { View } from "react-native";
import {
  NavigationContainer,
  useNavigationContainerRef,
} from "@react-navigation/native";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RootStack } from "./src/navigation/RootStack";
import type { RootStackParamList } from "./src/navigation/RootStack";
import { AstraAssistantOverlay } from "./src/features/assistant/AstraAssistantOverlay";
import { useAssistantStore } from "./src/store/assistantStore";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { staleTime: 2000, retry: 1 },
  },
});

export default function App() {
  const navigationRef = useNavigationContainerRef<RootStackParamList>();
  const setRouteContext = useAssistantStore((state) => state.setRouteContext);

  return (
    <QueryClientProvider client={queryClient}>
      <View style={{ flex: 1 }}>
        <NavigationContainer
          ref={navigationRef}
          onReady={() => {
            const currentRoute = navigationRef.getCurrentRoute();
            setRouteContext(
              currentRoute?.name ?? null,
              (currentRoute?.params as Record<string, unknown> | undefined) ?? null
            );
          }}
          onStateChange={() => {
            const currentRoute = navigationRef.getCurrentRoute();
            setRouteContext(
              currentRoute?.name ?? null,
              (currentRoute?.params as Record<string, unknown> | undefined) ?? null
            );
          }}
        >
          <RootStack />
        </NavigationContainer>
        <AstraAssistantOverlay />
      </View>
    </QueryClientProvider>
  );
}
