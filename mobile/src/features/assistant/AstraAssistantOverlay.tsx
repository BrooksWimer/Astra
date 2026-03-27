import React, { useEffect, useRef, useState } from "react";
import {
  Animated,
  Easing,
  KeyboardAvoidingView,
  Platform,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  View,
} from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { LinearGradient } from "expo-linear-gradient";
import { getAssistantContext } from "./assistantContext";
import { getAssistantReply, syncAssistantContext } from "../../api/assistant";
import { buildAssistantContextSyncRequest } from "./buildAssistantRequest";
import {
  detectServiceBaseUrlAsync,
  getDetectedServiceBaseUrl,
} from "../../lib/urls";
import { useAssistantStore } from "../../store/assistantStore";
import { useAgentStore } from "../../store/agentStore";
import { useBluetoothStore } from "../../store/bluetoothStore";
import { AstraColors, AstraShadow } from "../../theme/astra";

export function AstraAssistantOverlay() {
  const isOpen = useAssistantStore((state) => state.isOpen);
  const isExpanded = useAssistantStore((state) => state.isExpanded);
  const sessionId = useAssistantStore((state) => state.sessionId);
  const routeName = useAssistantStore((state) => state.routeName);
  const routeParams = useAssistantStore((state) => state.routeParams);
  const draft = useAssistantStore((state) => state.draft);
  const messages = useAssistantStore((state) => state.messages);
  const openAssistant = useAssistantStore((state) => state.openAssistant);
  const closeAssistant = useAssistantStore((state) => state.closeAssistant);
  const toggleExpanded = useAssistantStore((state) => state.toggleExpanded);
  const setDraft = useAssistantStore((state) => state.setDraft);
  const appendMessage = useAssistantStore((state) => state.appendMessage);
  const clearConversation = useAssistantStore((state) => state.clearConversation);
  const agentBaseUrl = useAgentStore((state) => state.agentBaseUrl);
  const adviceBaseUrl = useAgentStore((state) => state.adviceBaseUrl);
  const agentInfo = useAgentStore((state) => state.agentInfo);
  const lastScanId = useAgentStore((state) => state.lastScanId);
  const bluetoothDevices = useBluetoothStore((state) => state.devices);
  const bluetoothScanning = useBluetoothStore((state) => state.isScanning);
  const [detectedAdviceBaseUrl, setDetectedAdviceBaseUrl] = useState(() =>
    getDetectedServiceBaseUrl("3000")
  );
  const [isRendered, setIsRendered] = useState(isOpen);
  const [isSending, setIsSending] = useState(false);
  const lastSyncedPayloadRef = useRef<string | null>(null);
  const translateY = useRef(new Animated.Value(420)).current;
  const backdropOpacity = useRef(new Animated.Value(0)).current;
  const context = getAssistantContext(routeName);
  const effectiveAdviceBaseUrl = adviceBaseUrl || detectedAdviceBaseUrl;

  useEffect(() => {
    let active = true;

    void detectServiceBaseUrlAsync("3000").then((url) => {
      if (active && url) {
        setDetectedAdviceBaseUrl(url);
      }
    });

    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    lastSyncedPayloadRef.current = null;
  }, [sessionId, effectiveAdviceBaseUrl]);

  const selectedBluetoothDeviceId =
    routeName === "BluetoothDeviceDetail" &&
    typeof routeParams?.deviceId === "string"
      ? routeParams.deviceId
      : null;
  const selectedBluetoothDevice =
    bluetoothDevices.find((device) => device.id === selectedBluetoothDeviceId) ??
    null;

  const assistantContextSyncRequest = buildAssistantContextSyncRequest({
    sessionId,
    routeName,
    routeParams,
    agentInfo,
    agentBaseUrl,
    adviceBaseUrl: effectiveAdviceBaseUrl,
    wifiScanInProgress: Boolean(lastScanId),
    bluetoothScanInProgress: bluetoothScanning,
    bluetoothDevices,
    selectedBluetoothDevice,
  });

  useEffect(() => {
    if (!effectiveAdviceBaseUrl) {
      return;
    }

    const timeout = setTimeout(() => {
      const payload = JSON.stringify(assistantContextSyncRequest);

      if (payload === lastSyncedPayloadRef.current) {
        return;
      }

      void syncAssistantContext(effectiveAdviceBaseUrl, assistantContextSyncRequest)
        .then(() => {
          lastSyncedPayloadRef.current = payload;
        })
        .catch(() => {
          // The send flow handles visible failures. Background sync stays quiet.
        });
    }, 350);

    return () => clearTimeout(timeout);
  }, [assistantContextSyncRequest, effectiveAdviceBaseUrl]);

  useEffect(() => {
    if (isOpen) {
      setIsRendered(true);
      Animated.parallel([
        Animated.timing(translateY, {
          toValue: 0,
          duration: 260,
          easing: Easing.out(Easing.cubic),
          useNativeDriver: true,
        }),
        Animated.timing(backdropOpacity, {
          toValue: 1,
          duration: 220,
          easing: Easing.out(Easing.quad),
          useNativeDriver: true,
        }),
      ]).start();
      return;
    }

    if (!isRendered) {
      return;
    }

    Animated.parallel([
      Animated.timing(translateY, {
        toValue: 420,
        duration: 220,
        easing: Easing.in(Easing.cubic),
        useNativeDriver: true,
      }),
      Animated.timing(backdropOpacity, {
        toValue: 0,
        duration: 180,
        easing: Easing.in(Easing.quad),
        useNativeDriver: true,
      }),
    ]).start(({ finished }) => {
      if (finished) {
        setIsRendered(false);
      }
    });
  }, [backdropOpacity, isOpen, isRendered, translateY]);

  const sendMessage = async () => {
    const text = draft.trim();

    if (!text || isSending) {
      return;
    }

    appendMessage({ role: "user", text });
    setDraft("");
    setIsSending(true);

    if (!effectiveAdviceBaseUrl) {
      appendMessage({
        role: "assistant",
        text: "Astra can’t reach the assistant server yet. Add or derive the server URL in connection settings, then try again.",
        metaLabel: "Server unavailable",
      });
      setIsSending(false);
      return;
    }

    try {
      await syncAssistantContext(
        effectiveAdviceBaseUrl,
        assistantContextSyncRequest
      );
      lastSyncedPayloadRef.current = JSON.stringify(assistantContextSyncRequest);

      const response = await getAssistantReply(
        effectiveAdviceBaseUrl,
        {
          session_id: sessionId,
          message: text,
        }
      );

      appendMessage({
        role: "assistant",
        text: response.reply,
        suggestions: response.suggestions,
        metaLabel:
          response.mode === "ai"
            ? response.model
              ? `AI response via ${response.model}`
              : "AI response"
            : "Grounded fallback",
      });
    } catch {
      appendMessage({
        role: "assistant",
        text: "Astra couldn't reach the assistant service just now. Make sure the server is running and try again.",
        metaLabel: "Request failed",
      });
    } finally {
      setIsSending(false);
    }
  };

  return (
    <View pointerEvents="box-none" style={styles.overlayRoot}>
      {!isOpen ? (
        <Pressable style={styles.fab} onPress={() => openAssistant()}>
          <LinearGradient
            colors={[AstraColors.accentSoft, AstraColors.accentWarm]}
            start={{ x: 0, y: 0 }}
            end={{ x: 1, y: 1 }}
            style={styles.fabGlow}
          >
            <Ionicons
              name="sparkles"
              size={22}
              color={AstraColors.textPrimary}
            />
          </LinearGradient>
        </Pressable>
      ) : null}

      {isRendered ? (
        <>
          <Pressable style={styles.backdropPressable} onPress={closeAssistant}>
            <Animated.View
              style={[styles.backdrop, { opacity: backdropOpacity }]}
            />
          </Pressable>

          <KeyboardAvoidingView
            behavior={Platform.OS === "ios" ? "padding" : undefined}
            style={styles.sheetHost}
            pointerEvents="box-none"
          >
            <Animated.View
              style={[
                styles.sheet,
                isExpanded ? styles.sheetExpanded : styles.sheetCompact,
                { transform: [{ translateY }] },
              ]}
            >
              <View style={styles.handle} />

              <View style={styles.header}>
                <View style={styles.headerCopy}>
                  <Text style={styles.headerTitle}>{context.title}</Text>
                  <Text style={styles.headerSubtitle}>{context.subtitle}</Text>
                </View>

                <View style={styles.headerActions}>
                  <Pressable style={styles.iconButton} onPress={clearConversation}>
                    <Ionicons
                      name="refresh-outline"
                      size={17}
                      color={AstraColors.textSecondary}
                    />
                  </Pressable>
                  <Pressable style={styles.iconButton} onPress={toggleExpanded}>
                    <Ionicons
                      name={
                        isExpanded ? "contract-outline" : "expand-outline"
                      }
                      size={17}
                      color={AstraColors.textSecondary}
                    />
                  </Pressable>
                  <Pressable style={styles.iconButton} onPress={closeAssistant}>
                    <Ionicons
                      name="close-outline"
                      size={20}
                      color={AstraColors.textSecondary}
                    />
                  </Pressable>
                </View>
              </View>

              <ScrollView
                style={styles.body}
                contentContainerStyle={styles.bodyContent}
                keyboardShouldPersistTaps="handled"
                showsVerticalScrollIndicator={false}
              >
                <View style={styles.previewCard}>
                  <Text style={styles.previewEyebrow}>Grounded Assistant</Text>
                  <Text style={styles.previewText}>
                    Astra keeps the current screen and live Bluetooth state in
                    sync with the server, then queries live tools when you ask
                    a question.
                  </Text>
                </View>

                <View style={styles.promptSection}>
                  <Text style={styles.promptSectionTitle}>Quick starts</Text>
                  <View style={styles.promptRow}>
                    {context.prompts.map((prompt) => (
                      <Pressable
                        key={prompt}
                        style={styles.promptChip}
                        onPress={() => openAssistant(prompt)}
                      >
                        <Text style={styles.promptChipText}>{prompt}</Text>
                      </Pressable>
                    ))}
                  </View>
                </View>

                {messages.length ? (
                  <View style={styles.messageList}>
                    {messages.map((message) => (
                      <View
                        key={message.id}
                        style={[
                          styles.messageBubble,
                          message.role === "user"
                            ? styles.userBubble
                            : styles.assistantBubble,
                        ]}
                      >
                        <Text style={styles.messageRole}>
                          {message.role === "user" ? "You" : "Astra"}
                        </Text>
                        {message.metaLabel ? (
                          <Text style={styles.messageMeta}>{message.metaLabel}</Text>
                        ) : null}
                        <Text style={styles.messageText}>{message.text}</Text>
                        {message.role === "assistant" && message.suggestions?.length ? (
                          <View style={styles.messageSuggestions}>
                            {message.suggestions.map((suggestion) => (
                              <Pressable
                                key={`${message.id}-${suggestion}`}
                                style={styles.promptChip}
                                onPress={() => openAssistant(suggestion)}
                              >
                                <Text style={styles.promptChipText}>{suggestion}</Text>
                              </Pressable>
                            ))}
                          </View>
                        ) : null}
                      </View>
                    ))}
                  </View>
                ) : (
                  <View style={styles.emptyConversation}>
                    <Ionicons
                      name="chatbubbles-outline"
                      size={26}
                      color={AstraColors.textMuted}
                    />
                    <Text style={styles.emptyConversationTitle}>
                      No conversation yet
                    </Text>
                    <Text style={styles.emptyConversationBody}>
                      Start with a quick prompt or type your own question. Astra
                      will answer using the current screen context and scan data
                      the app can already see.
                    </Text>
                  </View>
                )}
              </ScrollView>

              <View style={styles.composer}>
                <TextInput
                  value={draft}
                  onChangeText={setDraft}
                  placeholder="Ask Astra anything about this screen..."
                  placeholderTextColor={AstraColors.textMuted}
                  style={styles.input}
                  multiline
                />
                <Pressable
                  style={[styles.sendButton, isSending && styles.sendButtonDisabled]}
                  onPress={() => {
                    void sendMessage();
                  }}
                  disabled={isSending}
                >
                  <Ionicons
                    name={isSending ? "time-outline" : "arrow-up"}
                    size={18}
                    color={AstraColors.textPrimary}
                  />
                </Pressable>
              </View>
            </Animated.View>
          </KeyboardAvoidingView>
        </>
      ) : null}
    </View>
  );
}

const styles = StyleSheet.create({
  overlayRoot: {
    ...StyleSheet.absoluteFillObject,
  },
  fab: {
    position: "absolute",
    right: 18,
    bottom: 28,
    zIndex: 20,
    borderRadius: 999,
    ...AstraShadow,
  },
  fabGlow: {
    width: 62,
    height: 62,
    borderRadius: 31,
    alignItems: "center",
    justifyContent: "center",
    borderWidth: 1,
    borderColor: "rgba(255,255,255,0.2)",
  },
  backdropPressable: {
    ...StyleSheet.absoluteFillObject,
  },
  backdrop: {
    ...StyleSheet.absoluteFillObject,
    backgroundColor: "rgba(4, 6, 16, 0.6)",
  },
  sheetHost: {
    ...StyleSheet.absoluteFillObject,
    justifyContent: "flex-end",
  },
  sheet: {
    marginHorizontal: 10,
    marginBottom: 10,
    borderRadius: 30,
    backgroundColor: "rgba(11, 13, 25, 0.98)",
    borderWidth: 1,
    borderColor: AstraColors.borderStrong,
    paddingHorizontal: 18,
    paddingTop: 12,
    paddingBottom: 16,
    gap: 14,
    ...AstraShadow,
  },
  sheetCompact: {
    minHeight: "52%",
    maxHeight: "72%",
  },
  sheetExpanded: {
    minHeight: "78%",
    maxHeight: "92%",
  },
  handle: {
    alignSelf: "center",
    width: 42,
    height: 5,
    borderRadius: 999,
    backgroundColor: "rgba(255,255,255,0.16)",
  },
  header: {
    flexDirection: "row",
    alignItems: "flex-start",
    justifyContent: "space-between",
    gap: 14,
  },
  headerCopy: {
    flex: 1,
    gap: 4,
  },
  headerTitle: {
    color: AstraColors.textPrimary,
    fontSize: 20,
    fontWeight: "700",
  },
  headerSubtitle: {
    color: AstraColors.textSecondary,
    fontSize: 13,
    lineHeight: 18,
  },
  headerActions: {
    flexDirection: "row",
    gap: 8,
  },
  iconButton: {
    width: 34,
    height: 34,
    borderRadius: 12,
    alignItems: "center",
    justifyContent: "center",
    backgroundColor: "rgba(255,255,255,0.05)",
    borderWidth: 1,
    borderColor: AstraColors.border,
  },
  body: {
    flex: 1,
  },
  bodyContent: {
    gap: 14,
    paddingBottom: 8,
  },
  previewCard: {
    borderRadius: 20,
    padding: 14,
    backgroundColor: "rgba(139,124,255,0.12)",
    borderWidth: 1,
    borderColor: "rgba(139,124,255,0.2)",
    gap: 6,
  },
  previewEyebrow: {
    color: AstraColors.accentSoft,
    fontSize: 11,
    fontWeight: "700",
    textTransform: "uppercase",
    letterSpacing: 1.2,
  },
  previewText: {
    color: AstraColors.textSecondary,
    fontSize: 13,
    lineHeight: 18,
  },
  promptSection: {
    gap: 10,
  },
  promptSectionTitle: {
    color: AstraColors.textSecondary,
    fontSize: 14,
    fontWeight: "700",
  },
  promptRow: {
    flexDirection: "row",
    flexWrap: "wrap",
    gap: 8,
  },
  promptChip: {
    borderRadius: 999,
    paddingHorizontal: 12,
    paddingVertical: 9,
    backgroundColor: "rgba(255,255,255,0.06)",
    borderWidth: 1,
    borderColor: AstraColors.border,
  },
  promptChipText: {
    color: AstraColors.textPrimary,
    fontSize: 12,
    fontWeight: "600",
  },
  emptyConversation: {
    borderRadius: 24,
    padding: 20,
    alignItems: "center",
    gap: 8,
    backgroundColor: "rgba(255,255,255,0.04)",
    borderWidth: 1,
    borderColor: AstraColors.border,
  },
  emptyConversationTitle: {
    color: AstraColors.textPrimary,
    fontSize: 16,
    fontWeight: "700",
  },
  emptyConversationBody: {
    color: AstraColors.textSecondary,
    fontSize: 13,
    lineHeight: 18,
    textAlign: "center",
  },
  messageList: {
    gap: 10,
  },
  messageBubble: {
    borderRadius: 20,
    padding: 14,
    gap: 6,
  },
  userBubble: {
    alignSelf: "flex-end",
    backgroundColor: "rgba(139,124,255,0.18)",
    maxWidth: "92%",
  },
  assistantBubble: {
    alignSelf: "flex-start",
    backgroundColor: "rgba(255,255,255,0.06)",
    borderWidth: 1,
    borderColor: AstraColors.border,
    maxWidth: "96%",
  },
  messageRole: {
    color: AstraColors.textMuted,
    fontSize: 11,
    fontWeight: "700",
    textTransform: "uppercase",
    letterSpacing: 1.1,
  },
  messageMeta: {
    color: AstraColors.accentSoft,
    fontSize: 11,
    fontWeight: "600",
  },
  messageText: {
    color: AstraColors.textPrimary,
    fontSize: 14,
    lineHeight: 20,
  },
  messageSuggestions: {
    flexDirection: "row",
    flexWrap: "wrap",
    gap: 8,
    marginTop: 2,
  },
  composer: {
    flexDirection: "row",
    alignItems: "flex-end",
    gap: 10,
    borderRadius: 22,
    padding: 10,
    backgroundColor: "rgba(255,255,255,0.05)",
    borderWidth: 1,
    borderColor: AstraColors.border,
  },
  input: {
    flex: 1,
    minHeight: 42,
    maxHeight: 100,
    color: AstraColors.textPrimary,
    fontSize: 14,
    paddingHorizontal: 6,
    paddingVertical: 8,
  },
  sendButton: {
    width: 42,
    height: 42,
    borderRadius: 16,
    alignItems: "center",
    justifyContent: "center",
    backgroundColor: AstraColors.accent,
  },
  sendButtonDisabled: {
    opacity: 0.72,
  },
});
