import React from "react";
import {
  Alert,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  View,
} from "react-native";
import * as Clipboard from "expo-clipboard";
import { useNavigation, useRoute } from "@react-navigation/native";
import type { RouteProp } from "@react-navigation/native";
import type { NativeStackNavigationProp } from "@react-navigation/native-stack";
import { LinearGradient } from "expo-linear-gradient";
import { Ionicons } from "@expo/vector-icons";
import { SafeAreaView } from "react-native-safe-area-context";
import { StatusBar } from "expo-status-bar";
import type { BleAdvice, BleEvidence } from "@netwise/shared";
import type { RootStackParamList } from "../navigation/RootStack";
import { AstraAssistantPromptCard } from "../features/assistant/AstraAssistantPromptCard";
import {
  formatBluetoothRssi,
  formatBluetoothSeenTime,
  getBluetoothDeviceSubtitle,
  getBluetoothDeviceTags,
  getBluetoothDeviceTitle,
  getBluetoothSignalLabel,
} from "../features/bluetooth/bluetoothPresentation";
import { useBluetoothStore } from "../store/bluetoothStore";
import { AstraColors, AstraShadow } from "../theme/astra";

type Route = RouteProp<RootStackParamList, "BluetoothDeviceDetail">;
type Nav = NativeStackNavigationProp<RootStackParamList, "BluetoothDeviceDetail">;

export function BluetoothDeviceDetailScreen() {
  const { params } = useRoute<Route>();
  const navigation = useNavigation<Nav>();
  const device = useBluetoothStore((state) =>
    state.devices.find((entry) => entry.id === params.deviceId)
  );

  const copy = (label: string, value: string) => {
    void Clipboard.setStringAsync(value).then(() => {
      Alert.alert("Copied", `${label} copied to clipboard`);
    });
  };

  if (!device) {
    return (
      <LinearGradient
        colors={[AstraColors.backgroundTop, AstraColors.backgroundBottom]}
        style={styles.screen}
      >
        <StatusBar style="light" />
        <SafeAreaView style={styles.safeArea}>
          <View style={styles.content}>
            <View style={styles.header}>
              <Pressable
                style={styles.headerButton}
                onPress={() => navigation.goBack()}
              >
                <Ionicons
                  name="chevron-back"
                  size={20}
                  color={AstraColors.textPrimary}
                />
              </Pressable>
              <Text style={styles.headerTitle}>Bluetooth Details</Text>
              <View style={styles.headerSpacer} />
            </View>

            <View style={styles.emptyCard}>
              <Ionicons
                name="radio-outline"
                size={28}
                color={AstraColors.textMuted}
              />
              <Text style={styles.emptyTitle}>Device not available</Text>
              <Text style={styles.emptyBody}>
                That Bluetooth signal is no longer in Astra's current scan state.
                Run another scan and open it again.
              </Text>
            </View>
          </View>
        </SafeAreaView>
      </LinearGradient>
    );
  }

  const tags = getBluetoothDeviceTags(device);
  const classification = device.classification;
  const categoryEvidence = classification?.likely_category.evidence ?? [];
  const vendorEvidence = classification?.likely_vendor.evidence ?? [];
  const serviceDataPayloads = Object.entries(device.serviceDataHexByUuid).map(
    ([uuid, hex]) => `${uuid} | ${hex}`
  );

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
            <Pressable
              style={styles.headerButton}
              onPress={() => navigation.goBack()}
            >
              <Ionicons
                name="chevron-back"
                size={20}
                color={AstraColors.textPrimary}
              />
            </Pressable>
            <Text style={styles.headerTitle}>Bluetooth Details</Text>
            <View style={styles.headerSpacer} />
          </View>

          <View style={styles.identityCard}>
            <LinearGradient
              colors={["rgba(139, 124, 255, 0.28)", "rgba(255, 154, 98, 0.10)"]}
              style={styles.identityIcon}
            >
              <Ionicons
                name={device.isConnectable === true ? "bluetooth" : "radio-outline"}
                size={28}
                color={AstraColors.textPrimary}
              />
            </LinearGradient>

            <View style={styles.identityCopy}>
              <Text style={styles.identityTitle}>
                {getBluetoothDeviceTitle(device)}
              </Text>
              <Text style={styles.identitySubtitle}>
                {getBluetoothDeviceSubtitle(device)}
              </Text>
              <View style={styles.statusPill}>
                <Text style={styles.statusPillText}>
                  {getBluetoothSignalLabel(device.rssi)}
                </Text>
              </View>
            </View>
          </View>

          <View style={styles.sectionCard}>
            <Text style={styles.sectionTitle}>Signal snapshot</Text>
            <FactRow
              label="Identifier"
              value={device.id}
              onCopy={() => copy("Identifier", device.id)}
            />
            <FactRow
              label="Connectable"
              value={
                device.isConnectable == null
                  ? "Unknown"
                  : device.isConnectable
                  ? "Yes"
                  : "No"
              }
            />
            <FactRow label="RSSI" value={formatBluetoothRssi(device.rssi)} />
            <FactRow
              label="Tx power"
              value={
                device.txPowerLevel == null
                  ? "Unavailable"
                  : `${device.txPowerLevel} dBm`
              }
            />
            <FactRow
              label="First seen"
              value={formatBluetoothSeenTime(device.discoveredAt)}
            />
            <FactRow
              label="Last seen"
              value={formatBluetoothSeenTime(device.lastSeenAt)}
            />
          </View>

          <View style={styles.sectionCard}>
            <Text style={styles.sectionTitle}>Advertised data</Text>

            {tags.length ? (
              <View style={styles.chipRow}>
                {tags.map((tag) => (
                  <View key={tag} style={styles.chip}>
                    <Text style={styles.chipText}>{tag}</Text>
                  </View>
                ))}
              </View>
            ) : (
              <Text style={styles.sectionBody}>
                Astra did not capture extra advertised-data hints for this
                signal in the latest scan.
              </Text>
            )}

            <FactRow
              label="Manufacturer data"
              value={device.hasManufacturerData ? "Present" : "Not seen"}
            />
            <FactRow
              label="Manufacturer company"
              value={
                device.manufacturerCompanyId == null
                  ? "Unavailable"
                  : `0x${device.manufacturerCompanyId
                      .toString(16)
                      .toUpperCase()
                      .padStart(4, "0")}`
              }
            />
            <FactRow
              label="Service data blocks"
              value={String(device.serviceDataCount)}
            />
            <FactRow
              label="Raw scan record"
              value={device.rawScanRecordHex ? "Captured" : "Unavailable"}
            />
          </View>

          {classification ? (
            <>
              <View style={styles.sectionCard}>
                <Text style={styles.sectionTitle}>Deterministic label</Text>
                <View style={styles.classificationGrid}>
                  <SummaryTile
                    label="Likely category"
                    value={formatLabel(classification.likely_category.likely)}
                  />
                  <SummaryTile
                    label="Likely vendor"
                    value={classification.likely_vendor.likely}
                  />
                  <SummaryTile
                    label="Confidence"
                    value={`${classification.confidenceLabel.toUpperCase()} (${Math.round(
                      classification.confidence * 100
                    )}%)`}
                  />
                </View>

                {classification.flags.length ? (
                  <View style={styles.flagWrap}>
                    {classification.flags.map((flag) => (
                      <View key={flag} style={styles.flagChip}>
                        <Text style={styles.flagChipText}>
                          {formatLabel(flag)}
                        </Text>
                      </View>
                    ))}
                  </View>
                ) : null}

                {categoryEvidence.length ? (
                  <EvidenceList
                    title="Why Astra thinks this"
                    items={categoryEvidence}
                  />
                ) : null}

                {vendorEvidence.length ? (
                  <EvidenceList
                    title="Vendor evidence"
                    items={vendorEvidence}
                  />
                ) : null}

                {classification.uncertainty.length ? (
                  <>
                    <Text style={styles.subTitle}>Uncertainty</Text>
                    {classification.uncertainty.map((note, index) => (
                      <Text key={`${note}-${index}`} style={styles.bullet}>
                        - {note}
                      </Text>
                    ))}
                  </>
                ) : null}
              </View>

              {classification.advice.length ? (
                <View style={styles.sectionCard}>
                  <Text style={styles.sectionTitle}>Grounded advice</Text>
                  {classification.advice.map((item) => (
                    <AdviceCard key={item.id} advice={item} />
                  ))}
                </View>
              ) : null}
            </>
          ) : null}

          <AstraAssistantPromptCard
            title="Ask Astra About This Signal"
            body="Launch the assistant with prompts tailored to this BLE device and its advertised data."
            prompts={[
              `What might ${getBluetoothDeviceTitle(device)} be?`,
              "Is this Bluetooth signal suspicious?",
              "How should I interpret this advertised data?",
            ]}
          />

          <ValueList
            title="Advertised service UUIDs"
            values={device.serviceUUIDs}
            emptyText="No advertised service UUIDs were surfaced for this device."
            onCopy={copy}
          />

          <ValueList
            title="Service data UUIDs"
            values={device.serviceDataKeys}
            emptyText="No service data UUIDs were captured in the latest scan."
            onCopy={copy}
          />

          <ValueList
            title="Service data payloads"
            values={serviceDataPayloads}
            emptyText="No service data payload bytes were captured in the latest scan."
            onCopy={copy}
          />

          <ValueList
            title="Solicited service UUIDs"
            values={device.solicitedServiceUUIDs}
            emptyText="No solicited service UUIDs were reported."
            onCopy={copy}
          />

          <ValueList
            title="Overflow service UUIDs"
            values={device.overflowServiceUUIDs}
            emptyText="No overflow service UUIDs were reported."
            onCopy={copy}
          />

          <View style={styles.sectionCard}>
            <Text style={styles.sectionTitle}>What comes next</Text>
            <Text style={styles.sectionBody}>
              These deterministic BLE labels now ground Astra's Bluetooth
              explanations. The next layer is cross-correlating this signal
              with WiFi observations when there is enough evidence.
            </Text>
          </View>
        </ScrollView>
      </SafeAreaView>
    </LinearGradient>
  );
}

function SummaryTile({ label, value }: { label: string; value: string }) {
  return (
    <View style={styles.summaryTile}>
      <Text style={styles.summaryLabel}>{label}</Text>
      <Text style={styles.summaryValue}>{value}</Text>
    </View>
  );
}

function EvidenceList({
  title,
  items,
}: {
  title: string;
  items: BleEvidence[];
}) {
  return (
    <View style={styles.evidenceWrap}>
      <Text style={styles.subTitle}>{title}</Text>
      {items.map((item) => (
        <Text key={item.ruleId} style={styles.bullet}>
          - {item.claim}
        </Text>
      ))}
    </View>
  );
}

function AdviceCard({ advice }: { advice: BleAdvice }) {
  return (
    <View
      style={[
        styles.adviceCard,
        advice.severity === "attention"
          ? styles.adviceCardAttention
          : styles.adviceCardInfo,
      ]}
    >
      <View style={styles.adviceHeader}>
        <Text style={styles.adviceTitle}>{advice.title}</Text>
        <Text style={styles.adviceSeverity}>
          {advice.severity === "attention" ? "ATTENTION" : "INFO"}
        </Text>
      </View>
      <Text style={styles.sectionBody}>{advice.text}</Text>
    </View>
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

function formatLabel(value: string): string {
  return value
    .split(/[_\s]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function ValueList({
  title,
  values,
  emptyText,
  onCopy,
}: {
  title: string;
  values: string[];
  emptyText: string;
  onCopy: (label: string, value: string) => void;
}) {
  return (
    <View style={styles.sectionCard}>
      <Text style={styles.sectionTitle}>{title}</Text>
      {values.length ? (
        values.map((value) => (
          <FactRow
            key={`${title}-${value}`}
            label="Value"
            value={value}
            onCopy={() => onCopy(title, value)}
          />
        ))
      ) : (
        <Text style={styles.sectionBody}>{emptyText}</Text>
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  screen: { flex: 1 },
  safeArea: { flex: 1 },
  scroll: { flex: 1 },
  content: { paddingHorizontal: 20, paddingBottom: 36, gap: 16 },
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
    backgroundColor: "rgba(139,124,255,0.18)",
  },
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
  classificationGrid: { flexDirection: "row", flexWrap: "wrap", gap: 10 },
  summaryTile: {
    minWidth: 140,
    flexGrow: 1,
    borderRadius: 18,
    padding: 14,
    backgroundColor: AstraColors.panelStrong,
    gap: 6,
  },
  summaryLabel: {
    color: AstraColors.textMuted,
    fontSize: 12,
    textTransform: "uppercase",
    letterSpacing: 1.1,
  },
  summaryValue: {
    color: AstraColors.textPrimary,
    fontSize: 15,
    fontWeight: "700",
  },
  flagWrap: { flexDirection: "row", flexWrap: "wrap", gap: 8 },
  flagChip: {
    borderRadius: 999,
    paddingHorizontal: 10,
    paddingVertical: 6,
    backgroundColor: "rgba(139,124,255,0.18)",
  },
  flagChipText: {
    color: AstraColors.textPrimary,
    fontSize: 12,
    fontWeight: "600",
  },
  evidenceWrap: { gap: 8 },
  subTitle: {
    color: AstraColors.textSecondary,
    fontSize: 14,
    fontWeight: "700",
  },
  bullet: { color: AstraColors.textSecondary, fontSize: 14, lineHeight: 20 },
  adviceCard: {
    borderRadius: 18,
    padding: 14,
    gap: 8,
  },
  adviceCardInfo: { backgroundColor: AstraColors.panelStrong },
  adviceCardAttention: { backgroundColor: AstraColors.warningMuted },
  adviceHeader: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "space-between",
    gap: 12,
  },
  adviceTitle: {
    color: AstraColors.textPrimary,
    fontSize: 15,
    fontWeight: "700",
    flex: 1,
  },
  adviceSeverity: {
    color: AstraColors.textMuted,
    fontSize: 11,
    fontWeight: "700",
    letterSpacing: 1.2,
  },
  emptyCard: {
    borderRadius: 24,
    padding: 24,
    alignItems: "center",
    gap: 10,
    backgroundColor: "rgba(255,255,255,0.04)",
    borderWidth: 1,
    borderColor: AstraColors.border,
  },
  emptyTitle: {
    color: AstraColors.textPrimary,
    fontSize: 18,
    fontWeight: "700",
  },
  emptyBody: {
    color: AstraColors.textSecondary,
    fontSize: 14,
    lineHeight: 20,
    textAlign: "center",
  },
});
