import React, { useEffect, useMemo, useState } from "react";
import {
  ActivityIndicator,
  Alert,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  View,
  type ViewStyle,
} from "react-native";
import * as Clipboard from "expo-clipboard";
import { useNavigation, useRoute } from "@react-navigation/native";
import type { RouteProp } from "@react-navigation/native";
import type { NativeStackNavigationProp } from "@react-navigation/native-stack";
import { useQuery } from "@tanstack/react-query";
import { LinearGradient } from "expo-linear-gradient";
import { Ionicons } from "@expo/vector-icons";
import { SafeAreaView } from "react-native-safe-area-context";
import { StatusBar } from "expo-status-bar";
import type { AdviceResponse } from "@netwise/shared";
import { getAdvice } from "../api/advice";
import { getDevice } from "../api/agent";
import type { RootStackParamList } from "../navigation/RootStack";
import {
  deviceNeedsReview,
  formatConfidence,
  formatRelativeTime,
  getDeviceStatusLabel,
  getDeviceSubtitle,
  getDeviceTags,
  getDeviceTitle,
  getDeviceTypeLabel,
} from "../presentation/devicePresentation";
import { useAgentStore } from "../store/agentStore";
import { AstraColors, AstraShadow } from "../theme/astra";

type Route = RouteProp<RootStackParamList, "DeviceDetail">;
type Nav = NativeStackNavigationProp<RootStackParamList, "DeviceDetail">;

export function DeviceDetailScreen() {
  const { params } = useRoute<Route>();
  const navigation = useNavigation<Nav>();
  const agentBaseUrl = useAgentStore((state) => state.agentBaseUrl);
  const adviceBaseUrl = useAgentStore((state) => state.adviceBaseUrl);
  const agentInfo = useAgentStore((state) => state.agentInfo);
  const [advice, setAdvice] = useState<AdviceResponse | null>(null);
  const [adviceLoading, setAdviceLoading] = useState(false);
  const [adviceError, setAdviceError] = useState<string | null>(null);

  const { data: device, isLoading } = useQuery({
    queryKey: ["device", agentBaseUrl, params.deviceId],
    queryFn: () => getDevice(agentBaseUrl!, params.deviceId),
    enabled: !!agentBaseUrl && !!params.deviceId,
  });

  useEffect(() => {
    if (!agentBaseUrl) {
      navigation.replace("Connect");
    }
  }, [agentBaseUrl, navigation]);

  const copy = (label: string, value: string) => {
    Clipboard.setStringAsync(value).then(() => {
      Alert.alert("Copied", `${label} copied to clipboard`);
    });
  };

  const fetchAdvice = async () => {
    if (!device || !agentBaseUrl || !adviceBaseUrl) return;

    setAdviceError(null);
    setAdviceLoading(true);
    try {
      const result = await getAdvice(adviceBaseUrl, {
        scan_id: "last",
        device_id: device.id,
        device,
        network: {
          subnet: agentInfo?.cidr || agentInfo?.subnet,
          gateway_ip: agentInfo?.gateway,
          local_ip: agentInfo?.local_ip,
          interface_name: agentInfo?.interface,
        },
        user_context: "home",
      });
      setAdvice(result);
    } catch {
      setAdviceError(`Could not reach the advice server at ${adviceBaseUrl}.`);
    } finally {
      setAdviceLoading(false);
    }
  };

  const deviceTags = useMemo(() => (device ? getDeviceTags(device) : []), [device]);
  const observedSignals = useMemo(() => {
    if (!device) return [];

    const signals: string[] = [];
    if (device.protocols_seen.mdns.length > 0) signals.push(`${device.protocols_seen.mdns.length} mDNS`);
    if (device.protocols_seen.ssdp.length > 0) signals.push(`${device.protocols_seen.ssdp.length} SSDP`);
    if (device.protocols_seen.netbios.length > 0) signals.push(`${device.protocols_seen.netbios.length} NetBIOS`);
    if ((device.ports_open?.length ?? 0) > 0) signals.push(`${device.ports_open?.length ?? 0} open ports`);
    return signals;
  }, [device]);

  if (!agentBaseUrl) {
    return null;
  }

  if (isLoading || !device) {
    return (
      <LinearGradient
        colors={[AstraColors.backgroundTop, AstraColors.backgroundBottom]}
        style={styles.screen}
      >
        <SafeAreaView style={styles.safeArea}>
          <View style={styles.loadingWrap}>
            <ActivityIndicator size="large" color={AstraColors.accentSoft} />
          </View>
        </SafeAreaView>
      </LinearGradient>
    );
  }

  const adviceRiskStyles: Record<AdviceResponse["risk_level"], ViewStyle> = {
    low: styles.adviceRiskLow,
    medium: styles.adviceRiskMedium,
    high: styles.adviceRiskHigh,
  };
  const needsReview = deviceNeedsReview(device);
  const title = getDeviceTitle(device);

  return (
    <LinearGradient
      colors={[AstraColors.backgroundTop, AstraColors.backgroundBottom]}
      style={styles.screen}
    >
      <StatusBar style="light" />
      <SafeAreaView style={styles.safeArea}>
        <ScrollView
          style={styles.scroll}
          contentContainerStyle={styles.content}
          showsVerticalScrollIndicator={false}
        >
          <View style={styles.header}>
            <Pressable style={styles.headerButton} onPress={() => navigation.goBack()}>
              <Ionicons name="chevron-back" size={20} color={AstraColors.textPrimary} />
            </Pressable>
            <Text style={styles.headerTitle}>Device Insights</Text>
            <View style={styles.headerSpacer} />
          </View>

          <View style={styles.identityCard}>
            <LinearGradient
              colors={
                needsReview
                  ? ["rgba(255, 165, 94, 0.28)", "rgba(255, 126, 141, 0.12)"]
                  : ["rgba(139, 124, 255, 0.28)", "rgba(139, 124, 255, 0.08)"]
              }
              style={styles.identityIcon}
            >
              <Ionicons
                name={needsReview ? "warning-outline" : "shield-checkmark-outline"}
                size={28}
                color={AstraColors.textPrimary}
              />
            </LinearGradient>

            <View style={styles.identityCopy}>
              <Text style={styles.identityTitle}>{title}</Text>
              <Text style={styles.identitySubtitle}>{getDeviceSubtitle(device)}</Text>
              <View style={[styles.statusPill, needsReview ? styles.statusPillWarning : styles.statusPillSafe]}>
                <Text style={styles.statusPillText}>{getDeviceStatusLabel(device)}</Text>
              </View>
            </View>
          </View>

          <View style={styles.sectionCard}>
            <Text style={styles.sectionTitle}>Device facts</Text>
            <FactRow label="IP address" value={device.ip} onCopy={() => copy("IP address", device.ip)} />
            <FactRow label="MAC address" value={device.mac} onCopy={() => copy("MAC address", device.mac)} />
            <FactRow label="Vendor" value={device.vendor || "Unknown"} />
            <FactRow label="Type" value={getDeviceTypeLabel(device.device_type)} />
            <FactRow label="Confidence" value={formatConfidence(device.confidence)} />
            <FactRow label="First seen" value={formatRelativeTime(device.first_seen)} />
            <FactRow label="Last seen" value={formatRelativeTime(device.last_seen)} />
          </View>

          <View style={styles.sectionCard}>
            <Text style={styles.sectionTitle}>Signals observed</Text>
            <View style={styles.chipRow}>
              {deviceTags.length > 0 ? (
                deviceTags.map((tag) => (
                  <View key={tag} style={styles.chip}>
                    <Text style={styles.chipText}>{tag}</Text>
                  </View>
                ))
              ) : (
                <Text style={styles.sectionBody}>No elevated flags from the current scan.</Text>
              )}
            </View>
            {observedSignals.length > 0 ? (
              <Text style={styles.sectionBody}>Observed signals: {observedSignals.join(" | ")}</Text>
            ) : (
              <Text style={styles.sectionBody}>
                No discovery protocols or open ports were captured for this device in the current scan.
              </Text>
            )}
          </View>

          <View style={styles.sectionCard}>
            <Text style={styles.sectionTitle}>Network context</Text>
            <FactRow label="Local IP" value={agentInfo?.local_ip || "Unknown"} />
            <FactRow label="Gateway" value={agentInfo?.gateway || "Unknown"} />
            <FactRow label="Network" value={agentInfo?.cidr || agentInfo?.subnet || "Unknown"} />
            <FactRow label="Advice server" value={adviceBaseUrl || "Unavailable"} />
          </View>

          <View style={styles.sectionCard}>
            <View style={styles.advisorHeader}>
              <View style={styles.advisorBadge}>
                <Ionicons name="sparkles-outline" size={16} color={AstraColors.accentSoft} />
              </View>
              <View style={styles.advisorCopy}>
                <Text style={styles.sectionTitle}>Astra Advisor</Text>
                <Text style={styles.sectionBody}>
                  Pull grounded guidance from the existing rule-based advice service using this device's live scanner facts.
                </Text>
              </View>
            </View>

            <Pressable
              style={[styles.adviceButton, (adviceLoading || !adviceBaseUrl) && styles.buttonDisabled]}
              onPress={fetchAdvice}
              disabled={adviceLoading || !adviceBaseUrl}
            >
              {adviceLoading ? (
                <ActivityIndicator color={AstraColors.textPrimary} />
              ) : (
                <>
                  <Ionicons name="sparkles" size={17} color={AstraColors.textPrimary} />
                  <Text style={styles.adviceButtonText}>Get Advice</Text>
                </>
              )}
            </Pressable>

            {adviceError ? <Text style={styles.errorText}>{adviceError}</Text> : null}

            {advice ? (
              <View style={styles.adviceWrap}>
                <View style={[styles.adviceRiskBadge, adviceRiskStyles[advice.risk_level]]}>
                  <Text style={styles.adviceRiskText}>{advice.risk_level.toUpperCase()} RISK</Text>
                </View>

                <Text style={styles.summary}>{advice.summary}</Text>

                {advice.reasons.length > 0 ? (
                  <>
                    <Text style={styles.subTitle}>Why Astra flagged it</Text>
                    {advice.reasons.map((reason, index) => (
                      <Text key={`${reason}-${index}`} style={styles.bullet}>
                        - {reason}
                      </Text>
                    ))}
                  </>
                ) : null}

                {advice.actions.length > 0 ? (
                  <>
                    <Text style={styles.subTitle}>Recommended actions</Text>
                    {advice.actions.map((action, index) => (
                      <View key={`${action.title}-${index}`} style={styles.actionCard}>
                        <View style={styles.actionHeader}>
                          <Text style={styles.actionTitle}>{action.title}</Text>
                          <Text style={styles.urgency}>{action.urgency}</Text>
                        </View>
                        {action.steps.map((step, stepIndex) => (
                          <Text key={`${step}-${stepIndex}`} style={styles.step}>
                            {stepIndex + 1}. {step}
                          </Text>
                        ))}
                      </View>
                    ))}
                  </>
                ) : null}

                {advice.uncertainty_notes.length > 0 ? (
                  <>
                    <Text style={styles.subTitle}>Uncertainty</Text>
                    {advice.uncertainty_notes.map((note, index) => (
                      <Text key={`${note}-${index}`} style={styles.bullet}>
                        - {note}
                      </Text>
                    ))}
                  </>
                ) : null}
              </View>
            ) : null}
          </View>
        </ScrollView>
      </SafeAreaView>
    </LinearGradient>
  );
}

function FactRow({
  label,
  value,
  onCopy,
}: {
  label: string;
  value: string;
  onCopy?: () => void;
}) {
  return (
    <View style={styles.factRow}>
      <View style={styles.factCopy}>
        <Text style={styles.factLabel}>{label}</Text>
        <Text style={styles.factValue}>{value}</Text>
      </View>
      {onCopy ? (
        <Pressable onPress={onCopy} style={styles.copyBtn}>
          <Ionicons name="copy-outline" size={16} color={AstraColors.textPrimary} />
        </Pressable>
      ) : null}
    </View>
  );
}

const styles = StyleSheet.create({
  screen: { flex: 1 },
  safeArea: { flex: 1 },
  scroll: { flex: 1 },
  content: { paddingHorizontal: 20, paddingBottom: 36, gap: 16 },
  loadingWrap: { flex: 1, justifyContent: "center", alignItems: "center" },
  header: {
    paddingTop: 4,
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "space-between",
  },
  headerButton: {
    width: 40,
    height: 40,
    borderRadius: 16,
    alignItems: "center",
    justifyContent: "center",
    backgroundColor: "rgba(255,255,255,0.05)",
    borderWidth: 1,
    borderColor: AstraColors.border,
  },
  headerTitle: { color: AstraColors.textPrimary, fontSize: 16, fontWeight: "700" },
  headerSpacer: { width: 40 },
  identityCard: {
    borderRadius: 28,
    padding: 22,
    backgroundColor: AstraColors.panel,
    borderWidth: 1,
    borderColor: AstraColors.border,
    flexDirection: "row",
    gap: 16,
    ...AstraShadow,
  },
  identityIcon: {
    width: 72,
    height: 72,
    borderRadius: 24,
    alignItems: "center",
    justifyContent: "center",
    borderWidth: 1,
    borderColor: "rgba(255,255,255,0.12)",
  },
  identityCopy: { flex: 1, gap: 6 },
  identityTitle: { color: AstraColors.textPrimary, fontSize: 24, fontWeight: "700" },
  identitySubtitle: { color: AstraColors.textSecondary, fontSize: 14, fontWeight: "600" },
  statusPill: {
    alignSelf: "flex-start",
    borderRadius: 999,
    paddingHorizontal: 12,
    paddingVertical: 7,
    marginTop: 4,
  },
  statusPillSafe: { backgroundColor: AstraColors.safeMuted },
  statusPillWarning: { backgroundColor: AstraColors.warningMuted },
  statusPillText: {
    color: AstraColors.textPrimary,
    fontSize: 12,
    fontWeight: "700",
    letterSpacing: 0.6,
  },
  sectionCard: {
    borderRadius: 24,
    padding: 18,
    backgroundColor: "rgba(255,255,255,0.05)",
    borderWidth: 1,
    borderColor: AstraColors.border,
    gap: 12,
  },
  sectionTitle: { color: AstraColors.textPrimary, fontSize: 18, fontWeight: "700" },
  sectionBody: { color: AstraColors.textSecondary, fontSize: 14, lineHeight: 20 },
  factRow: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "space-between",
    gap: 12,
    paddingVertical: 2,
  },
  factCopy: { flex: 1, gap: 4 },
  factLabel: {
    color: AstraColors.textMuted,
    fontSize: 12,
    textTransform: "uppercase",
    letterSpacing: 1.2,
  },
  factValue: { color: AstraColors.textPrimary, fontSize: 15, fontWeight: "600" },
  copyBtn: {
    width: 34,
    height: 34,
    borderRadius: 12,
    alignItems: "center",
    justifyContent: "center",
    backgroundColor: "rgba(255,255,255,0.06)",
    borderWidth: 1,
    borderColor: AstraColors.border,
  },
  chipRow: { flexDirection: "row", flexWrap: "wrap", gap: 8 },
  chip: {
    borderRadius: 999,
    paddingHorizontal: 10,
    paddingVertical: 6,
    backgroundColor: "rgba(255,255,255,0.07)",
  },
  chipText: { color: AstraColors.textPrimary, fontSize: 12, fontWeight: "600" },
  advisorHeader: { flexDirection: "row", gap: 12, alignItems: "flex-start" },
  advisorBadge: {
    width: 34,
    height: 34,
    borderRadius: 12,
    alignItems: "center",
    justifyContent: "center",
    backgroundColor: "rgba(139,124,255,0.14)",
  },
  advisorCopy: { flex: 1, gap: 4 },
  adviceButton: {
    backgroundColor: AstraColors.accent,
    paddingVertical: 15,
    paddingHorizontal: 16,
    borderRadius: 18,
    alignItems: "center",
    justifyContent: "center",
    flexDirection: "row",
    gap: 8,
  },
  buttonDisabled: { opacity: 0.7 },
  adviceButtonText: { color: AstraColors.textPrimary, fontSize: 15, fontWeight: "700" },
  errorText: { color: "#FF97A2", fontSize: 13, lineHeight: 18 },
  adviceWrap: { gap: 10, marginTop: 4 },
  adviceRiskBadge: {
    alignSelf: "flex-start",
    paddingHorizontal: 12,
    paddingVertical: 7,
    borderRadius: 999,
  },
  adviceRiskLow: { backgroundColor: AstraColors.safeMuted },
  adviceRiskMedium: { backgroundColor: AstraColors.warningMuted },
  adviceRiskHigh: { backgroundColor: AstraColors.dangerMuted },
  adviceRiskText: {
    color: AstraColors.textPrimary,
    fontWeight: "700",
    fontSize: 12,
    letterSpacing: 0.8,
  },
  summary: { color: AstraColors.textPrimary, fontSize: 15, lineHeight: 22 },
  subTitle: { fontSize: 14, fontWeight: "700", color: AstraColors.textSecondary, marginTop: 6 },
  bullet: { color: AstraColors.textSecondary, fontSize: 14, lineHeight: 21 },
  actionCard: {
    backgroundColor: AstraColors.panelStrong,
    padding: 14,
    borderRadius: 18,
    gap: 8,
  },
  actionHeader: {
    flexDirection: "row",
    justifyContent: "space-between",
    gap: 12,
    alignItems: "center",
  },
  actionTitle: { color: AstraColors.textPrimary, fontWeight: "700", fontSize: 15, flex: 1 },
  urgency: {
    fontSize: 11,
    color: AstraColors.textMuted,
    textTransform: "uppercase",
    letterSpacing: 1.2,
    fontWeight: "700",
  },
  step: { color: AstraColors.textSecondary, fontSize: 13, lineHeight: 19 },
});
