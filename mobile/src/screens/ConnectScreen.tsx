import React, { useState } from "react";
import {
  ActivityIndicator,
  KeyboardAvoidingView,
  Platform,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  View,
} from "react-native";
import { LinearGradient } from "expo-linear-gradient";
import { Ionicons } from "@expo/vector-icons";
import { SafeAreaView } from "react-native-safe-area-context";
import { StatusBar } from "expo-status-bar";
import { useNavigation } from "@react-navigation/native";
import type { NativeStackNavigationProp } from "@react-navigation/native-stack";
import { getInfo, health } from "../api/agent";
import {
  deriveAdviceBaseUrl,
  normalizeBaseUrl,
} from "../lib/urls";
import type { RootStackParamList } from "../navigation/RootStack";
import { useAgentStore } from "../store/agentStore";
import { AstraColors, AstraShadow } from "../theme/astra";

type Nav = NativeStackNavigationProp<RootStackParamList, "Connect">;

const DEFAULT_AGENT_BASE_URL = "http://192.168.4.253:7777";
const DEFAULT_ADVICE_BASE_URL = "http://192.168.4.253:3000";

export function ConnectScreen() {
  const agentBaseUrl = useAgentStore((state) => state.agentBaseUrl);
  const existingAdviceBaseUrl = useAgentStore((state) => state.adviceBaseUrl);
  const [agentInput, setAgentInput] = useState(
    agentBaseUrl ?? DEFAULT_AGENT_BASE_URL
  );
  const [adviceInput, setAdviceInput] = useState(
    existingAdviceBaseUrl ?? DEFAULT_ADVICE_BASE_URL
  );
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const connectSession = useAgentStore((state) => state.connectSession);
  const clearSession = useAgentStore((state) => state.clearSession);
  const navigation = useNavigation<Nav>();

  const derivedAdviceUrl = deriveAdviceBaseUrl(normalizeBaseUrl(agentInput, "7777"));

  const connect = async () => {
    const agentBaseUrl = normalizeBaseUrl(agentInput, "7777");
    if (!agentBaseUrl) {
      setError("Enter the local agent URL, like http://192.168.1.10:7777.");
      return;
    }

    const adviceBaseUrl = adviceInput.trim()
      ? normalizeBaseUrl(adviceInput, "3000")
      : derivedAdviceUrl;
    if (!adviceBaseUrl) {
      setError("Could not derive the advice server URL. Add one in Advanced settings.");
      return;
    }

    setError(null);
    setLoading(true);
    try {
      const ok = await health(agentBaseUrl);
      if (!ok) {
        setError("Agent did not respond. Check the IP address and confirm it is listening on port 7777.");
        return;
      }

      const agentInfo = await getInfo(agentBaseUrl);
      connectSession({ agentBaseUrl, adviceBaseUrl, agentInfo });
      if (navigation.canGoBack()) {
        navigation.goBack();
      } else {
        navigation.replace("Dashboard");
      }
    } catch {
      setError("Could not reach the local agent and load its network info. Make sure the scanner is running on the same network.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <LinearGradient
      colors={[AstraColors.backgroundTop, AstraColors.backgroundBottom]}
      style={styles.screen}
    >
      <StatusBar style="light" />
      <SafeAreaView style={styles.safeArea}>
        <KeyboardAvoidingView
          style={styles.keyboardFrame}
          behavior={Platform.OS === "ios" ? "padding" : undefined}
        >
          <ScrollView
            contentContainerStyle={styles.content}
            keyboardShouldPersistTaps="handled"
            showsVerticalScrollIndicator={false}
          >
            <View style={styles.hero}>
              <View style={styles.topBar}>
                <Pressable style={styles.topButton} onPress={() => navigation.goBack()}>
                  <Ionicons name="chevron-back" size={18} color={AstraColors.textPrimary} />
                </Pressable>
                <Text style={styles.topLabel}>Connections</Text>
                <View style={styles.topButtonSpacer} />
              </View>
              <View style={styles.brandMark}>
                <Ionicons name="sparkles" size={22} color={AstraColors.textPrimary} />
              </View>
              <Text style={styles.brandName}>Astra</Text>
              <Text style={styles.heroTitle}>Private network intelligence for the room you're in.</Text>
              <Text style={styles.heroBody}>
                Connect Astra to your scanner, map your WiFi environment, and review the devices that deserve a closer look.
              </Text>
            </View>

            <View style={styles.card}>
              <Text style={styles.sectionEyebrow}>Scanner Connection</Text>
              <Text style={styles.cardTitle}>Attach to your local agent</Text>
              <Text style={styles.cardBody}>
                Astra no longer requires a scanner connection at launch. Save the agent URL here when you're ready to run a scan.
              </Text>

              <Text style={styles.label}>Agent URL</Text>
              <TextInput
                style={styles.input}
                placeholder={DEFAULT_AGENT_BASE_URL}
                placeholderTextColor={AstraColors.textMuted}
                value={agentInput}
                onChangeText={(value) => {
                  setAgentInput(value);
                  setError(null);
                }}
                autoCapitalize="none"
                autoCorrect={false}
                editable={!loading}
              />

              <Pressable
                onPress={() => setAdvancedOpen((current) => !current)}
                style={styles.advancedToggle}
              >
                <View>
                  <Text style={styles.advancedTitle}>Advanced settings</Text>
                  <Text style={styles.advancedHint}>
                    Advice server defaults to{" "}
                    {derivedAdviceUrl || DEFAULT_ADVICE_BASE_URL || "the same host on port 3000"}.
                  </Text>
                </View>
                <Ionicons
                  name={advancedOpen ? "chevron-up" : "chevron-down"}
                  size={18}
                  color={AstraColors.textSecondary}
                />
              </Pressable>

              {advancedOpen ? (
                <View style={styles.advancedPanel}>
                  <Text style={styles.label}>Advice server override</Text>
                  <TextInput
                    style={styles.input}
                    placeholder={
                      derivedAdviceUrl || DEFAULT_ADVICE_BASE_URL || "http://192.168.1.10:3000"
                    }
                    placeholderTextColor={AstraColors.textMuted}
                    value={adviceInput}
                    onChangeText={(value) => {
                      setAdviceInput(value);
                      setError(null);
                    }}
                    autoCapitalize="none"
                    autoCorrect={false}
                    editable={!loading}
                  />
                  <Text style={styles.fieldHint}>
                    Leave this blank to reuse the same host and point Astra's advisor to port 3000.
                  </Text>
                </View>
              ) : null}

              {DEFAULT_AGENT_BASE_URL ? (
                <Text style={styles.fieldHint}>
                  Prefilled for this dev machine: {DEFAULT_AGENT_BASE_URL}
                </Text>
              ) : null}

              {error ? <Text style={styles.error}>{error}</Text> : null}

              <Pressable
                style={[styles.button, loading && styles.buttonDisabled]}
                onPress={connect}
                disabled={loading}
              >
                {loading ? (
                  <ActivityIndicator color={AstraColors.textPrimary} />
                ) : (
                  <>
                    <Text style={styles.buttonText}>Connect to Astra</Text>
                    <Ionicons name="arrow-forward" size={18} color={AstraColors.textPrimary} />
                  </>
                )}
              </Pressable>

              {agentBaseUrl ? (
                <Pressable
                  style={styles.secondaryButton}
                  onPress={() => {
                    clearSession();
                    setAgentInput(DEFAULT_AGENT_BASE_URL);
                    setAdviceInput(DEFAULT_ADVICE_BASE_URL);
                    setError(null);
                    navigation.goBack();
                  }}
                >
                  <Text style={styles.secondaryButtonText}>Disconnect scanner</Text>
                </Pressable>
              ) : null}
            </View>

            <View style={styles.noteCard}>
              <View style={styles.noteIcon}>
                <Ionicons name="server-outline" size={18} color={AstraColors.accentSoft} />
              </View>
              <View style={styles.noteContent}>
                <Text style={styles.noteTitle}>Local setup</Text>
                <Text style={styles.noteText}>
                  Run the Go agent on port 7777 and the advice server on port 3000 from the same machine for the smoothest first pass.
                </Text>
              </View>
            </View>
          </ScrollView>
        </KeyboardAvoidingView>
      </SafeAreaView>
    </LinearGradient>
  );
}

const styles = StyleSheet.create({
  screen: { flex: 1 },
  safeArea: { flex: 1 },
  keyboardFrame: { flex: 1 },
  content: {
    flexGrow: 1,
    paddingHorizontal: 24,
    paddingBottom: 36,
    gap: 20,
    justifyContent: "center",
  },
  hero: { gap: 10, paddingTop: 18 },
  topBar: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "space-between",
    marginBottom: 10,
  },
  topButton: {
    width: 38,
    height: 38,
    borderRadius: 14,
    alignItems: "center",
    justifyContent: "center",
    backgroundColor: "rgba(255,255,255,0.05)",
    borderWidth: 1,
    borderColor: AstraColors.border,
  },
  topLabel: {
    color: AstraColors.textSecondary,
    fontSize: 13,
    fontWeight: "700",
    letterSpacing: 1.6,
    textTransform: "uppercase",
  },
  topButtonSpacer: { width: 38 },
  brandMark: {
    width: 52,
    height: 52,
    borderRadius: 20,
    alignItems: "center",
    justifyContent: "center",
    backgroundColor: "rgba(139, 124, 255, 0.18)",
    borderWidth: 1,
    borderColor: "rgba(255,255,255,0.12)",
  },
  brandName: {
    color: AstraColors.textSecondary,
    textTransform: "uppercase",
    letterSpacing: 3,
    fontSize: 12,
    fontWeight: "700",
  },
  heroTitle: {
    color: AstraColors.textPrimary,
    fontSize: 34,
    lineHeight: 40,
    fontWeight: "700",
  },
  heroBody: {
    color: AstraColors.textSecondary,
    fontSize: 15,
    lineHeight: 22,
    maxWidth: 340,
  },
  card: {
    borderRadius: 28,
    padding: 22,
    backgroundColor: AstraColors.panel,
    borderWidth: 1,
    borderColor: AstraColors.border,
    gap: 12,
    ...AstraShadow,
  },
  sectionEyebrow: {
    color: AstraColors.accentSoft,
    textTransform: "uppercase",
    letterSpacing: 2,
    fontSize: 11,
    fontWeight: "700",
  },
  cardTitle: { color: AstraColors.textPrimary, fontSize: 24, fontWeight: "700" },
  cardBody: { color: AstraColors.textSecondary, fontSize: 14, lineHeight: 21 },
  label: { color: AstraColors.textPrimary, fontSize: 13, fontWeight: "600", marginTop: 2 },
  input: {
    backgroundColor: "rgba(10, 10, 22, 0.9)",
    borderRadius: 18,
    borderWidth: 1,
    borderColor: AstraColors.borderStrong,
    paddingHorizontal: 16,
    paddingVertical: 15,
    fontSize: 15,
    color: AstraColors.textPrimary,
  },
  advancedToggle: {
    borderRadius: 18,
    borderWidth: 1,
    borderColor: AstraColors.border,
    paddingHorizontal: 16,
    paddingVertical: 15,
    backgroundColor: "rgba(255,255,255,0.03)",
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "space-between",
    marginTop: 4,
  },
  advancedTitle: { color: AstraColors.textPrimary, fontSize: 14, fontWeight: "600" },
  advancedHint: { color: AstraColors.textMuted, fontSize: 12, marginTop: 4 },
  advancedPanel: { gap: 8, marginTop: 4 },
  fieldHint: { color: AstraColors.textMuted, fontSize: 12, lineHeight: 18 },
  error: { color: "#FF99A4", fontSize: 13, lineHeight: 19 },
  button: {
    marginTop: 6,
    borderRadius: 20,
    backgroundColor: AstraColors.accent,
    paddingVertical: 16,
    paddingHorizontal: 20,
    alignItems: "center",
    justifyContent: "center",
    flexDirection: "row",
    gap: 8,
  },
  buttonDisabled: { opacity: 0.7 },
  buttonText: { color: AstraColors.textPrimary, fontSize: 16, fontWeight: "700" },
  secondaryButton: {
    marginTop: 4,
    borderRadius: 20,
    paddingVertical: 14,
    paddingHorizontal: 18,
    alignItems: "center",
    justifyContent: "center",
    borderWidth: 1,
    borderColor: AstraColors.borderStrong,
    backgroundColor: "rgba(255,255,255,0.03)",
  },
  secondaryButtonText: {
    color: AstraColors.textSecondary,
    fontSize: 14,
    fontWeight: "700",
  },
  noteCard: {
    borderRadius: 22,
    padding: 18,
    flexDirection: "row",
    alignItems: "flex-start",
    gap: 14,
    backgroundColor: "rgba(255,255,255,0.04)",
    borderWidth: 1,
    borderColor: AstraColors.border,
  },
  noteIcon: {
    width: 34,
    height: 34,
    borderRadius: 12,
    alignItems: "center",
    justifyContent: "center",
    backgroundColor: "rgba(139,124,255,0.12)",
  },
  noteContent: { flex: 1, gap: 4 },
  noteTitle: { color: AstraColors.textPrimary, fontSize: 14, fontWeight: "700" },
  noteText: { color: AstraColors.textSecondary, fontSize: 13, lineHeight: 19 },
});
