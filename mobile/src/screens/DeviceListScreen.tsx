import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ActivityIndicator,
  Animated,
  Easing,
  Pressable,
  RefreshControl,
  ScrollView,
  StyleSheet,
  Text,
  View,
} from "react-native";
import { LinearGradient } from "expo-linear-gradient";
import { Ionicons } from "@expo/vector-icons";
import { SafeAreaView } from "react-native-safe-area-context";
import { StatusBar } from "expo-status-bar";
import { useNavigation } from "@react-navigation/native";
import type { NativeStackNavigationProp } from "@react-navigation/native-stack";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { Device } from "@netwise/shared";
import { AstraAssistantPromptCard } from "../features/assistant/AstraAssistantPromptCard";
import { BluetoothScanPanel } from "../features/bluetooth/BluetoothScanPanel";
import { getDevices, getScanResult, startScan } from "../api/agent";
import type { RootStackParamList } from "../navigation/RootStack";
import { featureFlags } from "../config/featureFlags";
import {
  deviceNeedsReview,
  formatConfidence,
  formatRelativeTime,
  getDeviceStatusLabel,
  getDeviceSubtitle,
  getDeviceTags,
  getDeviceTitle,
  sortDevicesForDashboard,
} from "../presentation/devicePresentation";
import { useAgentStore } from "../store/agentStore";
import { AstraColors, AstraShadow } from "../theme/astra";

type Nav = NativeStackNavigationProp<RootStackParamList, "Dashboard">;
type DashboardTab = "wifi" | "bluetooth";

const POLL_INTERVAL_MS = 2000;
const RADAR_DOT_POSITIONS = [
  { top: 32, right: 44 },
  { bottom: 34, left: 30 },
  { top: 84, left: 18 },
] as const;

export function DashboardScreen() {
  const agentBaseUrl = useAgentStore((state) => state.agentBaseUrl);
  const agentInfo = useAgentStore((state) => state.agentInfo);
  const lastScanId = useAgentStore((state) => state.lastScanId);
  const setLastScanId = useAgentStore((state) => state.setLastScanId);
  const navigation = useNavigation<Nav>();
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<DashboardTab>("wifi");
  const [scanError, setScanError] = useState<string | null>(null);
  const sweepValue = useRef(new Animated.Value(0)).current;

  const { data: devices = [], isLoading, isRefetching, refetch } = useQuery({
    queryKey: ["devices", agentBaseUrl],
    queryFn: () => getDevices(agentBaseUrl!),
    enabled: !!agentBaseUrl,
  });

  const scanMutation = useMutation({
    mutationFn: () => startScan(agentBaseUrl!),
    onSuccess: (data) => {
      setScanError(null);
      setLastScanId(data.scan_id);
      queryClient.invalidateQueries({ queryKey: ["devices", agentBaseUrl] });
    },
    onError: (err: Error) => {
      setScanError(err.message || "Failed to start scan");
    },
  });

  const pollScan = useCallback(() => {
    if (!agentBaseUrl || !lastScanId) return;
    getScanResult(agentBaseUrl, lastScanId).then((result) => {
      if (result?.scan_finished_at) {
        setLastScanId(null);
        queryClient.invalidateQueries({ queryKey: ["devices", agentBaseUrl] });
      }
    });
  }, [agentBaseUrl, lastScanId, queryClient, setLastScanId]);

  useEffect(() => {
    if (!lastScanId) return;
    const id = setInterval(pollScan, POLL_INTERVAL_MS);
    return () => clearInterval(id);
  }, [lastScanId, pollScan]);

  useEffect(() => {
    const animation = Animated.loop(
      Animated.timing(sweepValue, {
        toValue: 1,
        duration: 3200,
        easing: Easing.linear,
        useNativeDriver: true,
      })
    );
    animation.start();
    return () => animation.stop();
  }, [sweepValue]);

  const sortedDevices = useMemo(() => sortDevicesForDashboard(devices), [devices]);
  const reviewCount = useMemo(
    () => sortedDevices.filter((device) => deviceNeedsReview(device)).length,
    [sortedDevices]
  );
  const knownCount = Math.max(sortedDevices.length - reviewCount, 0);
  const scanning = scanMutation.isPending || !!lastScanId;
  const sweepRotation = sweepValue.interpolate({
    inputRange: [0, 1],
    outputRange: ["0deg", "360deg"],
  });

  return (
    <LinearGradient
      colors={[AstraColors.backgroundTop, AstraColors.backgroundBottom]}
      style={styles.screen}
    >
      <StatusBar style="light" />
      <SafeAreaView style={styles.safeArea}>
        <ScrollView
          contentContainerStyle={styles.content}
          showsVerticalScrollIndicator={false}
          refreshControl={
            <RefreshControl
              refreshing={isRefetching && !scanning}
              onRefresh={refetch}
              tintColor={AstraColors.accentSoft}
            />
          }
        >
          <View style={styles.header}>
            <View>
              <View style={styles.brandRow}>
                <View style={styles.brandBadge}>
                  <Ionicons name="sparkles" size={17} color={AstraColors.textPrimary} />
                </View>
                <Text style={styles.brandName}>Astra</Text>
              </View>
              <Text style={styles.headerTitle}>Your local network, made legible.</Text>
            </View>

            <Pressable
              style={styles.headerButton}
              onPress={() => navigation.navigate("Connect")}
            >
              <Ionicons name="settings-outline" size={20} color={AstraColors.textPrimary} />
            </Pressable>
          </View>

          <View style={styles.heroCard}>
            <View style={styles.radarFrame}>
              <View style={styles.radarCircleOuter} />
              <View style={styles.radarCircleMid} />
              <View style={styles.radarCircleInner} />
              <Animated.View
                style={[styles.radarSweep, { transform: [{ rotate: sweepRotation }] }]}
              >
                <LinearGradient
                  colors={[
                    "rgba(139, 124, 255, 0)",
                    "rgba(139, 124, 255, 0.12)",
                    "rgba(255, 154, 98, 0.42)",
                  ]}
                  start={{ x: 0.5, y: 1 }}
                  end={{ x: 0.5, y: 0 }}
                  style={styles.radarSweepGlow}
                />
              </Animated.View>

              {sortedDevices.slice(0, 3).map((device, index) => (
                <View
                  key={device.id}
                  style={[
                    styles.radarDot,
                    RADAR_DOT_POSITIONS[index],
                    deviceNeedsReview(device) ? styles.radarDotWarning : styles.radarDotSafe,
                  ]}
                />
              ))}

              <LinearGradient
                colors={[AstraColors.accentSoft, AstraColors.accent]}
                start={{ x: 0, y: 0 }}
                end={{ x: 1, y: 1 }}
                style={styles.radarCore}
              >
                <Ionicons name="wifi" size={28} color={AstraColors.textPrimary} />
              </LinearGradient>
            </View>

            <View style={styles.heroCopy}>
              <Text style={styles.heroEyebrow}>{scanning ? "Scan in progress" : "Live visibility"}</Text>
              <Text style={styles.heroTitle}>
                {sortedDevices.length} device{sortedDevices.length === 1 ? "" : "s"} mapped
              </Text>
              <Text style={styles.heroBody}>
                {!agentBaseUrl
                  ? "Browse the interface now, then add your scanner URL when you're ready to run a live network scan."
                  : reviewCount > 0
                  ? `${reviewCount} device${reviewCount === 1 ? "" : "s"} need review across your current WiFi environment.`
                  : featureFlags.localWifiScan
                  ? "Local iPhone Wi-Fi scan mode is enabled, but the app still falls back to the remote agent until the native path is ready."
                  : "No obvious review items surfaced from the latest scan."}
              </Text>
              <View style={styles.heroStats}>
                <StatPill label="Known" value={knownCount} tone="safe" />
                <StatPill label="Review" value={reviewCount} tone="warning" />
              </View>
            </View>
          </View>

          <View style={styles.scanCard}>
            <View style={styles.scanCopy}>
              <Text style={styles.scanTitle}>{scanning ? "Scanning your local network..." : "Run a fresh scan"}</Text>
              <Text style={styles.scanText}>
                {!agentBaseUrl
                  ? "Add a scanner URL the first time you want to run discovery. Astra only asks for it when scan functionality is needed."
                  : scanning
                  ? "Astra is polling the agent and will refresh devices as soon as the scan finishes."
                  : featureFlags.localWifiScan
                  ? "Remote scanning is still active while the local iOS path is scaffolded behind a feature flag."
                  : "Refresh the current environment and bubble review-worthy devices to the top."}
              </Text>
            </View>
            <Pressable
              style={[styles.scanButton, scanning && styles.scanButtonDisabled]}
              onPress={() => {
                if (!agentBaseUrl) {
                  navigation.navigate("Connect");
                  return;
                }
                setScanError(null);
                scanMutation.mutate();
              }}
              disabled={scanning}
            >
              {scanning ? (
                <ActivityIndicator color={AstraColors.textPrimary} />
              ) : (
                <>
                  <Ionicons
                    name={agentBaseUrl ? "scan-circle-outline" : "link-outline"}
                    size={18}
                    color={AstraColors.textPrimary}
                  />
                  <Text style={styles.scanButtonText}>{agentBaseUrl ? "Run Scan" : "Set Scanner URL"}</Text>
                </>
              )}
            </Pressable>
          </View>

          {scanError ? <Text style={styles.scanError}>{scanError}</Text> : null}

          <View style={styles.segmented}>
            <SegmentButton
              label="WiFi Network"
              icon="wifi-outline"
              selected={activeTab === "wifi"}
              onPress={() => setActiveTab("wifi")}
            />
            <SegmentButton
              label="Bluetooth Scan"
              icon="bluetooth-outline"
              selected={activeTab === "bluetooth"}
              onPress={() => setActiveTab("bluetooth")}
            />
          </View>

          {activeTab === "wifi" ? (
            <>
              <AstraAssistantPromptCard
                title="Ask Astra About This Scan"
                body="Launch the assistant with network-aware prompts based on what you are seeing right now."
                prompts={[
                  "What stands out in this network scan?",
                  "What should I review first?",
                  "How risky does this environment look?",
                ]}
              />

              <View style={styles.networkCard}>
                <View style={styles.networkCardHeader}>
                  <Text style={styles.sectionTitle}>Network snapshot</Text>
                  <Text style={styles.sectionCaption}>
                    {agentBaseUrl ? agentInfo?.hostname || "Local agent" : "Scanner disconnected"}
                  </Text>
                </View>
                <View style={styles.networkGrid}>
                  <InfoTile label="Local IP" value={agentBaseUrl ? agentInfo?.local_ip || "Unknown" : "Not connected"} />
                  <InfoTile label="Gateway" value={agentBaseUrl ? agentInfo?.gateway || "Unknown" : "Not connected"} />
                  <InfoTile
                    label="Network"
                    value={agentBaseUrl ? agentInfo?.cidr || agentInfo?.subnet || "Unknown" : "Connect to scan"}
                  />
                  <InfoTile label="Adapter" value={agentBaseUrl ? agentInfo?.interface || "Unknown" : "Connect to scan"} />
                </View>
              </View>

              <View style={styles.deviceSectionHeader}>
                <Text style={styles.sectionTitle}>Devices in range</Text>
                <Text style={styles.sectionCaption}>{sortedDevices.length} total</Text>
              </View>

              {isLoading && !sortedDevices.length ? (
                <View style={styles.loadingPanel}>
                  <ActivityIndicator size="large" color={AstraColors.accentSoft} />
                </View>
              ) : sortedDevices.length > 0 ? (
                sortedDevices.map((device) => (
                  <DeviceCard
                    key={device.id}
                    device={device}
                    onPress={() => navigation.navigate("DeviceDetail", { deviceId: device.id })}
                  />
                ))
              ) : (
                <View style={styles.emptyCard}>
                  <Ionicons
                    name={agentBaseUrl ? "wifi-outline" : "phone-portrait-outline"}
                    size={28}
                    color={AstraColors.textMuted}
                  />
                  <Text style={styles.emptyTitle}>{agentBaseUrl ? "No devices yet" : "Astra preview is ready"}</Text>
                  <Text style={styles.emptyBody}>
                    {agentBaseUrl
                      ? "Run a scan to populate the dashboard with devices from your current WiFi network."
                      : "You can explore the interface right away. Add a scanner URL only when you want live network data."}
                  </Text>
                  {!agentBaseUrl ? (
                    <Pressable style={styles.emptyAction} onPress={() => navigation.navigate("Connect")}>
                      <Text style={styles.emptyActionText}>Add Scanner URL</Text>
                    </Pressable>
                  ) : null}
                </View>
              )}
            </>
          ) : (
            <>
              <AstraAssistantPromptCard
                title="Ask Astra About Bluetooth"
                body="Start the assistant from the Bluetooth view with prompts tailored to nearby devices and unnamed signals."
                prompts={[
                  "What might these named Bluetooth devices be?",
                  "How should I interpret unnamed signals?",
                  "What should I pay attention to here?",
                ]}
              />
              <BluetoothScanPanel />
            </>
          )}
        </ScrollView>
      </SafeAreaView>
    </LinearGradient>
  );
}

function DeviceCard({ device, onPress }: { device: Device; onPress: () => void }) {
  const needsReview = deviceNeedsReview(device);
  const tags = getDeviceTags(device);

  return (
    <Pressable
      style={[styles.deviceCard, needsReview ? styles.deviceCardWarning : styles.deviceCardSafe]}
      onPress={onPress}
    >
      <View style={styles.deviceCardHeader}>
        <View style={[styles.deviceIconWrap, needsReview ? styles.deviceIconWarning : styles.deviceIconSafe]}>
          <Ionicons
            name={needsReview ? "warning-outline" : "shield-checkmark-outline"}
            size={20}
            color={needsReview ? AstraColors.warning : AstraColors.accentSoft}
          />
        </View>
        <View style={styles.deviceCopy}>
          <Text style={styles.deviceTitle}>{getDeviceTitle(device)}</Text>
          <Text style={styles.deviceSubtitle}>{getDeviceSubtitle(device)}</Text>
        </View>
        <Ionicons name="chevron-forward" size={18} color={AstraColors.textMuted} />
      </View>

      <Text style={styles.deviceMeta}>
        {device.ip} | {device.vendor || "Unknown vendor"}
      </Text>
      <Text style={styles.deviceSeen}>
        First seen {formatRelativeTime(device.first_seen)} | Last seen {formatRelativeTime(device.last_seen)}
      </Text>
      <Text style={styles.deviceConfidence}>
        {formatConfidence(device.confidence)} | {getDeviceStatusLabel(device)}
      </Text>

      {tags.length > 0 ? (
        <View style={styles.tagRow}>
          {tags.map((tag) => (
            <View
              key={`${device.id}-${tag}`}
              style={[styles.tag, needsReview ? styles.tagWarning : styles.tagNeutral]}
            >
              <Text style={styles.tagText}>{tag}</Text>
            </View>
          ))}
        </View>
      ) : null}
    </Pressable>
  );
}

function SegmentButton({
  label,
  icon,
  onPress,
  selected,
}: {
  label: string;
  icon: React.ComponentProps<typeof Ionicons>["name"];
  onPress: () => void;
  selected: boolean;
}) {
  return (
    <Pressable
      style={[styles.segmentButton, selected && styles.segmentButtonSelected]}
      onPress={onPress}
    >
      <Ionicons
        name={icon}
        size={16}
        color={selected ? AstraColors.textPrimary : AstraColors.textMuted}
      />
      <Text style={[styles.segmentLabel, selected && styles.segmentLabelSelected]}>{label}</Text>
    </Pressable>
  );
}

function StatPill({
  label,
  value,
  tone,
}: {
  label: string;
  value: number;
  tone: "safe" | "warning";
}) {
  return (
    <View style={[styles.statPill, tone === "safe" ? styles.statPillSafe : styles.statPillWarning]}>
      <Text style={styles.statValue}>{value}</Text>
      <Text style={styles.statLabel}>{label}</Text>
    </View>
  );
}

function InfoTile({ label, value }: { label: string; value: string }) {
  return (
    <View style={styles.infoTile}>
      <Text style={styles.infoTileLabel}>{label}</Text>
      <Text style={styles.infoTileValue}>{value}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  screen: { flex: 1 },
  safeArea: { flex: 1 },
  content: { paddingHorizontal: 20, paddingBottom: 36, gap: 18 },
  header: {
    paddingTop: 6,
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
  },
  brandRow: { flexDirection: "row", alignItems: "center", gap: 10, marginBottom: 8 },
  brandBadge: {
    width: 34,
    height: 34,
    borderRadius: 14,
    backgroundColor: "rgba(139,124,255,0.18)",
    alignItems: "center",
    justifyContent: "center",
    borderWidth: 1,
    borderColor: AstraColors.border,
  },
  brandName: {
    color: AstraColors.textSecondary,
    fontSize: 13,
    fontWeight: "700",
    letterSpacing: 2,
    textTransform: "uppercase",
  },
  headerTitle: {
    color: AstraColors.textPrimary,
    fontSize: 28,
    lineHeight: 33,
    fontWeight: "700",
    maxWidth: 260,
  },
  headerButton: {
    width: 42,
    height: 42,
    borderRadius: 16,
    alignItems: "center",
    justifyContent: "center",
    borderWidth: 1,
    borderColor: AstraColors.border,
    backgroundColor: "rgba(255,255,255,0.04)",
  },
  heroCard: {
    borderRadius: 30,
    padding: 22,
    backgroundColor: AstraColors.panel,
    borderWidth: 1,
    borderColor: AstraColors.border,
    gap: 16,
    ...AstraShadow,
  },
  radarFrame: {
    alignSelf: "center",
    width: 220,
    height: 220,
    alignItems: "center",
    justifyContent: "center",
    position: "relative",
  },
  radarCircleOuter: {
    position: "absolute",
    width: 220,
    height: 220,
    borderRadius: 110,
    borderWidth: 1,
    borderColor: "rgba(139,124,255,0.24)",
  },
  radarCircleMid: {
    position: "absolute",
    width: 164,
    height: 164,
    borderRadius: 82,
    borderWidth: 1,
    borderColor: "rgba(139,124,255,0.16)",
  },
  radarCircleInner: {
    position: "absolute",
    width: 108,
    height: 108,
    borderRadius: 54,
    borderWidth: 1,
    borderColor: "rgba(255,255,255,0.08)",
  },
  radarSweep: {
    position: "absolute",
    width: 220,
    height: 220,
    alignItems: "center",
    justifyContent: "flex-start",
  },
  radarSweepGlow: {
    marginTop: 12,
    width: 10,
    height: 98,
    borderRadius: 10,
  },
  radarCore: {
    width: 78,
    height: 78,
    borderRadius: 39,
    alignItems: "center",
    justifyContent: "center",
    borderWidth: 1,
    borderColor: "rgba(255,255,255,0.16)",
  },
  radarDot: {
    position: "absolute",
    width: 11,
    height: 11,
    borderRadius: 6,
  },
  radarDotSafe: {
    backgroundColor: AstraColors.safe,
    shadowColor: AstraColors.safe,
    shadowOpacity: 0.5,
    shadowRadius: 10,
  },
  radarDotWarning: {
    backgroundColor: AstraColors.warning,
    shadowColor: AstraColors.warning,
    shadowOpacity: 0.6,
    shadowRadius: 12,
  },
  heroCopy: { gap: 8 },
  heroEyebrow: {
    color: AstraColors.accentSoft,
    fontSize: 12,
    fontWeight: "700",
    letterSpacing: 1.8,
    textTransform: "uppercase",
  },
  heroTitle: { color: AstraColors.textPrimary, fontSize: 26, fontWeight: "700" },
  heroBody: { color: AstraColors.textSecondary, fontSize: 14, lineHeight: 20 },
  heroStats: { flexDirection: "row", gap: 10, marginTop: 4 },
  statPill: {
    flexDirection: "row",
    alignItems: "center",
    gap: 8,
    paddingHorizontal: 14,
    paddingVertical: 10,
    borderRadius: 16,
  },
  statPillSafe: { backgroundColor: AstraColors.safeMuted },
  statPillWarning: { backgroundColor: AstraColors.warningMuted },
  statValue: { color: AstraColors.textPrimary, fontSize: 16, fontWeight: "700" },
  statLabel: { color: AstraColors.textSecondary, fontSize: 13, fontWeight: "600" },
  scanCard: {
    borderRadius: 26,
    padding: 18,
    backgroundColor: "rgba(255,255,255,0.04)",
    borderWidth: 1,
    borderColor: AstraColors.border,
    gap: 16,
  },
  scanCopy: { gap: 6 },
  scanTitle: { color: AstraColors.textPrimary, fontSize: 18, fontWeight: "700" },
  scanText: { color: AstraColors.textSecondary, fontSize: 14, lineHeight: 20 },
  scanButton: {
    alignSelf: "flex-start",
    borderRadius: 18,
    paddingHorizontal: 16,
    paddingVertical: 13,
    backgroundColor: AstraColors.accent,
    flexDirection: "row",
    gap: 8,
    alignItems: "center",
  },
  scanButtonDisabled: { opacity: 0.72 },
  scanButtonText: { color: AstraColors.textPrimary, fontWeight: "700", fontSize: 14 },
  scanError: { color: "#FF97A2", fontSize: 13, lineHeight: 18 },
  segmented: {
    padding: 6,
    borderRadius: 24,
    backgroundColor: "rgba(255,255,255,0.05)",
    borderWidth: 1,
    borderColor: AstraColors.border,
    flexDirection: "row",
    gap: 8,
  },
  segmentButton: {
    flex: 1,
    borderRadius: 18,
    paddingVertical: 13,
    paddingHorizontal: 14,
    flexDirection: "row",
    justifyContent: "center",
    alignItems: "center",
    gap: 6,
  },
  segmentButtonSelected: {
    backgroundColor: "rgba(139,124,255,0.18)",
    borderWidth: 1,
    borderColor: AstraColors.borderStrong,
  },
  segmentLabel: { color: AstraColors.textMuted, fontSize: 13, fontWeight: "600" },
  segmentLabelSelected: { color: AstraColors.textPrimary },
  networkCard: {
    borderRadius: 26,
    padding: 18,
    backgroundColor: AstraColors.panelStrong,
    borderWidth: 1,
    borderColor: AstraColors.border,
    gap: 16,
  },
  networkCardHeader: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "space-between",
  },
  networkGrid: { flexDirection: "row", flexWrap: "wrap", gap: 12 },
  infoTile: {
    width: "48%",
    minWidth: 140,
    borderRadius: 20,
    padding: 14,
    backgroundColor: "rgba(255,255,255,0.04)",
    borderWidth: 1,
    borderColor: AstraColors.border,
    gap: 6,
  },
  infoTileLabel: {
    color: AstraColors.textMuted,
    fontSize: 12,
    textTransform: "uppercase",
    letterSpacing: 1.2,
  },
  infoTileValue: { color: AstraColors.textPrimary, fontSize: 14, fontWeight: "600" },
  deviceSectionHeader: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    marginTop: 2,
  },
  sectionTitle: { color: AstraColors.textPrimary, fontSize: 20, fontWeight: "700" },
  sectionCaption: { color: AstraColors.textMuted, fontSize: 13, fontWeight: "600" },
  loadingPanel: { paddingVertical: 28, alignItems: "center", justifyContent: "center" },
  deviceCard: {
    borderRadius: 24,
    padding: 16,
    borderWidth: 1,
    gap: 8,
  },
  deviceCardSafe: {
    backgroundColor: "rgba(255,255,255,0.05)",
    borderColor: AstraColors.border,
  },
  deviceCardWarning: {
    backgroundColor: "rgba(255,165,94,0.09)",
    borderColor: "rgba(255,165,94,0.28)",
  },
  deviceCardHeader: { flexDirection: "row", alignItems: "center", gap: 12 },
  deviceIconWrap: {
    width: 42,
    height: 42,
    borderRadius: 16,
    alignItems: "center",
    justifyContent: "center",
  },
  deviceIconSafe: { backgroundColor: "rgba(139,124,255,0.12)" },
  deviceIconWarning: { backgroundColor: "rgba(255,165,94,0.16)" },
  deviceCopy: { flex: 1, gap: 2 },
  deviceTitle: { color: AstraColors.textPrimary, fontSize: 16, fontWeight: "700" },
  deviceSubtitle: { color: AstraColors.textSecondary, fontSize: 13, fontWeight: "600" },
  deviceMeta: { color: AstraColors.textSecondary, fontSize: 13, lineHeight: 18 },
  deviceSeen: { color: AstraColors.textMuted, fontSize: 12, lineHeight: 17 },
  deviceConfidence: { color: AstraColors.textMuted, fontSize: 12, lineHeight: 17 },
  tagRow: { flexDirection: "row", flexWrap: "wrap", gap: 8, marginTop: 2 },
  tag: { borderRadius: 999, paddingHorizontal: 10, paddingVertical: 6 },
  tagNeutral: { backgroundColor: "rgba(255,255,255,0.06)" },
  tagWarning: { backgroundColor: "rgba(255,165,94,0.16)" },
  tagText: { color: AstraColors.textPrimary, fontSize: 11, fontWeight: "600" },
  emptyCard: {
    borderRadius: 24,
    padding: 26,
    alignItems: "center",
    gap: 10,
    backgroundColor: "rgba(255,255,255,0.04)",
    borderWidth: 1,
    borderColor: AstraColors.border,
  },
  emptyTitle: { color: AstraColors.textPrimary, fontSize: 18, fontWeight: "700" },
  emptyBody: {
    color: AstraColors.textSecondary,
    fontSize: 14,
    lineHeight: 20,
    textAlign: "center",
  },
  emptyAction: {
    marginTop: 6,
    borderRadius: 18,
    paddingHorizontal: 16,
    paddingVertical: 12,
    backgroundColor: "rgba(139,124,255,0.18)",
    borderWidth: 1,
    borderColor: AstraColors.borderStrong,
  },
  emptyActionText: {
    color: AstraColors.textPrimary,
    fontSize: 14,
    fontWeight: "700",
  },
  placeholderCard: {
    borderRadius: 26,
    padding: 24,
    gap: 12,
    backgroundColor: "rgba(255,255,255,0.04)",
    borderWidth: 1,
    borderColor: AstraColors.border,
  },
  placeholderBadge: {
    width: 44,
    height: 44,
    borderRadius: 16,
    alignItems: "center",
    justifyContent: "center",
    backgroundColor: "rgba(139,124,255,0.14)",
  },
  placeholderTitle: { color: AstraColors.textPrimary, fontSize: 20, fontWeight: "700" },
  placeholderBody: { color: AstraColors.textSecondary, fontSize: 14, lineHeight: 21 },
});
