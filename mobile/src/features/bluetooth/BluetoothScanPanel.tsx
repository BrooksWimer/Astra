import React from "react";
import {
  ActivityIndicator,
  Linking,
  Platform,
  Pressable,
  StyleSheet,
  Text,
  View,
} from "react-native";
import { LinearGradient } from "expo-linear-gradient";
import { Ionicons } from "@expo/vector-icons";
import { useNavigation } from "@react-navigation/native";
import type { NativeStackNavigationProp } from "@react-navigation/native-stack";
import { State } from "react-native-ble-plx";
import {
  formatBluetoothRssi,
  formatBluetoothSeenTime,
  getBluetoothDeviceSubtitle,
  getBluetoothDeviceTags,
  getBluetoothDeviceTitle,
  getBluetoothPermissionLabel,
  getBluetoothSignalLabel,
  getBluetoothSignalTone,
  sortBluetoothDevices,
  type BluetoothScanDevice,
} from "./bluetoothPresentation";
import { useBluetoothScanner } from "./useBluetoothScanner";
import { AstraColors, AstraShadow } from "../../theme/astra";
import type { RootStackParamList } from "../../navigation/RootStack";

type Nav = NativeStackNavigationProp<RootStackParamList, "Dashboard">;

function getBluetoothStateLabel(state: State | null): string {
  switch (state) {
    case State.PoweredOn:
      return "On";
    case State.PoweredOff:
      return "Off";
    case State.Unauthorized:
      return "Blocked";
    case State.Unsupported:
      return "Unsupported";
    case State.Resetting:
      return "Resetting";
    default:
      return "Checking";
  }
}

function getPrimaryCopy(scanner: ReturnType<typeof useBluetoothScanner>): string {
  if (scanner.isScanning) {
    return "Astra is listening for nearby BLE advertisements for up to 12 seconds and will keep discovered devices on screen.";
  }

  if (scanner.permissionStatus === "denied") {
    return "Bluetooth access is blocked for Astra. Re-enable it in Settings, then come back here to scan your physical space.";
  }

  if (scanner.permissionStatus === "needs-permission") {
    return "The first scan will request Bluetooth access. Astra only asks when you use Bluetooth Scan.";
  }

  if (scanner.bluetoothState === State.PoweredOff) {
    return "Turn Bluetooth on, then run a foreground scan to map nearby BLE devices around you.";
  }

  return "Run a foreground scan to see nearby Bluetooth devices, estimate proximity from signal strength, and inspect advertised data.";
}

export function BluetoothScanPanel() {
  const scanner = useBluetoothScanner();
  const devices = sortBluetoothDevices(scanner.devices);
  const navigation = useNavigation<Nav>();
  const namedCount = devices.filter((device) => device.name || device.localName).length;
  const connectableCount = devices.filter(
    (device) => device.isConnectable === true
  ).length;
  const namedDevices = devices.filter((device) => device.name || device.localName);
  const unnamedDevices = devices.filter((device) => !device.name && !device.localName);

  return (
    <View style={styles.section}>
      <LinearGradient
        colors={["rgba(139,124,255,0.22)", "rgba(12,14,26,0.95)"]}
        start={{ x: 0, y: 0 }}
        end={{ x: 1, y: 1 }}
        style={styles.heroCard}
      >
        <View style={styles.heroHeader}>
          <View style={styles.heroIconWrap}>
            <Ionicons
              name="bluetooth"
              size={24}
              color={AstraColors.textPrimary}
            />
          </View>
          <View style={styles.heroCopy}>
            <Text style={styles.heroEyebrow}>Bluetooth Scan</Text>
            <Text style={styles.heroTitle}>
              {devices.length} nearby device{devices.length === 1 ? "" : "s"}
            </Text>
          </View>
          <View
            style={[
              styles.statePill,
              scanner.isScanning ? styles.statePillActive : styles.statePillIdle,
            ]}
          >
            <Text style={styles.statePillText}>
              {scanner.isScanning ? "Scanning" : "Idle"}
            </Text>
          </View>
        </View>

        <Text style={styles.heroBody}>{getPrimaryCopy(scanner)}</Text>

        <View style={styles.metricRow}>
          <MetricTile
            label="Bluetooth"
            value={getBluetoothStateLabel(scanner.bluetoothState)}
          />
          <MetricTile
            label="Permission"
            value={getBluetoothPermissionLabel(scanner.permissionStatus)}
          />
          <MetricTile label="Named" value={String(namedCount)} />
          <MetricTile label="Connectable" value={String(connectableCount)} />
        </View>

        <View style={styles.actionRow}>
          <Pressable
            style={[
              styles.primaryButton,
              scanner.isScanning && styles.primaryButtonStop,
            ]}
            onPress={() => {
              if (scanner.isScanning) {
                scanner.stopScan();
                return;
              }

              void scanner.startScan();
            }}
          >
            {scanner.isScanning ? (
              <ActivityIndicator color={AstraColors.textPrimary} />
            ) : (
              <Ionicons
                name="scan-outline"
                size={18}
                color={AstraColors.textPrimary}
              />
            )}
            <Text style={styles.primaryButtonText}>
              {scanner.isScanning ? "Stop Scan" : "Start Bluetooth Scan"}
            </Text>
          </Pressable>

          {scanner.permissionStatus === "denied" ? (
            <Pressable
              style={styles.secondaryButton}
              onPress={() => {
                void Linking.openSettings();
              }}
            >
              <Ionicons
                name="settings-outline"
                size={16}
                color={AstraColors.textSecondary}
              />
              <Text style={styles.secondaryButtonText}>Open Settings</Text>
            </Pressable>
          ) : null}
        </View>

        <Text style={styles.captionText}>
          Last scan{" "}
          {scanner.lastScanEndedAt
            ? formatBluetoothSeenTime(scanner.lastScanEndedAt)
            : scanner.lastScanStartedAt
            ? "in progress"
            : "has not run yet"}
          .
        </Text>
      </LinearGradient>

      {scanner.error ? (
        <View style={styles.errorCard}>
          <View style={styles.errorRow}>
            <Ionicons
              name="warning-outline"
              size={18}
              color={AstraColors.warning}
            />
            <Text style={styles.errorText}>{scanner.error}</Text>
          </View>
          <Pressable onPress={scanner.clearError}>
            <Text style={styles.errorAction}>Dismiss</Text>
          </Pressable>
        </View>
      ) : null}

      <View style={styles.listHeader}>
        <Text style={styles.sectionTitle}>Discovered devices</Text>
        <Text style={styles.sectionCaption}>{devices.length} seen</Text>
      </View>

      {scanner.isScanning && !devices.length ? (
        <View style={styles.emptyCard}>
          <ActivityIndicator size="large" color={AstraColors.accentSoft} />
          <Text style={styles.emptyTitle}>Listening for advertisements</Text>
          <Text style={styles.emptyBody}>
            Keep this screen open while Astra scans. BLE devices appear here as
            they advertise themselves.
          </Text>
        </View>
      ) : devices.length ? (
        <View style={styles.sectionListWrap}>
          <BluetoothDeviceSection
            title="Named devices"
            count={namedDevices.length}
            devices={namedDevices}
            onPress={(deviceId) =>
              navigation.navigate("BluetoothDeviceDetail", { deviceId })
            }
          />
          <BluetoothDeviceSection
            title="Unnamed signals"
            count={unnamedDevices.length}
            devices={unnamedDevices}
            emptyMessage="No anonymous BLE advertisements surfaced in the latest scan."
            onPress={(deviceId) =>
              navigation.navigate("BluetoothDeviceDetail", { deviceId })
            }
          />
        </View>
      ) : (
        <View style={styles.emptyCard}>
          <Ionicons
            name="radio-outline"
            size={28}
            color={AstraColors.textMuted}
          />
          <Text style={styles.emptyTitle}>No Bluetooth devices yet</Text>
          <Text style={styles.emptyBody}>
            Start a scan to discover nearby BLE devices. Named devices and
            stronger signals will rise to the top.
          </Text>
          {Platform.OS === "ios" ? (
            <Text style={styles.emptyFootnote}>
              iPhone tip: the first scan may trigger the Bluetooth permission
              prompt for Astra.
            </Text>
          ) : null}
        </View>
      )}
    </View>
  );
}

function BluetoothDeviceSection({
  title,
  count,
  devices,
  emptyMessage,
  onPress,
}: {
  title: string;
  count: number;
  devices: BluetoothScanDevice[];
  emptyMessage?: string;
  onPress: (deviceId: string) => void;
}) {
  return (
    <View style={styles.deviceSection}>
      <View style={styles.deviceSectionHeader}>
        <Text style={styles.deviceSectionTitle}>{title}</Text>
        <Text style={styles.deviceSectionCount}>{count}</Text>
      </View>

      {devices.length ? (
        devices.map((device) => (
          <BluetoothDeviceCard
            key={device.id}
            device={device}
            onPress={() => onPress(device.id)}
          />
        ))
      ) : emptyMessage ? (
        <Text style={styles.deviceSectionEmpty}>{emptyMessage}</Text>
      ) : null}
    </View>
  );
}

function MetricTile({ label, value }: { label: string; value: string }) {
  return (
    <View style={styles.metricTile}>
      <Text style={styles.metricLabel}>{label}</Text>
      <Text style={styles.metricValue}>{value}</Text>
    </View>
  );
}

function BluetoothDeviceCard({
  device,
  onPress,
}: {
  device: BluetoothScanDevice;
  onPress: () => void;
}) {
  const tags = getBluetoothDeviceTags(device);
  const signalTone = getBluetoothSignalTone(device.rssi);

  return (
    <Pressable style={styles.deviceCard} onPress={onPress}>
      <View style={styles.deviceHeader}>
        <View style={styles.deviceIconWrap}>
          <Ionicons
            name={device.isConnectable === true ? "bluetooth" : "radio-outline"}
            size={20}
            color={AstraColors.textPrimary}
          />
        </View>

        <View style={styles.deviceCopy}>
          <Text style={styles.deviceTitle}>{getBluetoothDeviceTitle(device)}</Text>
          <Text style={styles.deviceSubtitle}>
            {getBluetoothDeviceSubtitle(device)}
          </Text>
        </View>

        <View style={styles.deviceHeaderRight}>
          <View
            style={[
              styles.signalPill,
              signalTone === "strong"
                ? styles.signalPillStrong
                : signalTone === "medium"
                ? styles.signalPillMedium
                : signalTone === "weak"
                ? styles.signalPillWeak
                : styles.signalPillUnknown,
            ]}
          >
            <Text style={styles.signalPillText}>
              {getBluetoothSignalLabel(device.rssi)}
            </Text>
          </View>
          <Ionicons
            name="chevron-forward"
            size={18}
            color={AstraColors.textMuted}
          />
        </View>
      </View>

      <Text style={styles.deviceId}>{device.id}</Text>
      <Text style={styles.deviceMeta}>
        {formatBluetoothRssi(device.rssi)} | Last seen{" "}
        {formatBluetoothSeenTime(device.lastSeenAt)}
      </Text>

      {tags.length ? (
        <View style={styles.tagRow}>
          {tags.map((tag) => (
            <View key={`${device.id}-${tag}`} style={styles.tag}>
              <Text style={styles.tagText}>{tag}</Text>
            </View>
          ))}
        </View>
      ) : null}
    </Pressable>
  );
}

const styles = StyleSheet.create({
  section: { gap: 16 },
  heroCard: {
    borderRadius: 28,
    padding: 20,
    gap: 16,
    borderWidth: 1,
    borderColor: AstraColors.border,
    ...AstraShadow,
  },
  heroHeader: {
    flexDirection: "row",
    alignItems: "center",
    gap: 14,
  },
  heroIconWrap: {
    width: 52,
    height: 52,
    borderRadius: 18,
    alignItems: "center",
    justifyContent: "center",
    backgroundColor: "rgba(255,255,255,0.08)",
    borderWidth: 1,
    borderColor: AstraColors.borderStrong,
  },
  heroCopy: { flex: 1, gap: 4 },
  heroEyebrow: {
    color: AstraColors.accentSoft,
    fontSize: 12,
    fontWeight: "700",
    textTransform: "uppercase",
    letterSpacing: 1.4,
  },
  heroTitle: {
    color: AstraColors.textPrimary,
    fontSize: 24,
    fontWeight: "700",
  },
  statePill: {
    borderRadius: 999,
    paddingHorizontal: 12,
    paddingVertical: 8,
  },
  statePillIdle: {
    backgroundColor: "rgba(255,255,255,0.08)",
  },
  statePillActive: {
    backgroundColor: "rgba(52,211,153,0.18)",
  },
  statePillText: {
    color: AstraColors.textPrimary,
    fontSize: 12,
    fontWeight: "700",
  },
  heroBody: {
    color: AstraColors.textSecondary,
    fontSize: 14,
    lineHeight: 21,
  },
  metricRow: {
    flexDirection: "row",
    flexWrap: "wrap",
    gap: 10,
  },
  metricTile: {
    minWidth: 120,
    flexGrow: 1,
    borderRadius: 18,
    padding: 14,
    backgroundColor: "rgba(255,255,255,0.05)",
    borderWidth: 1,
    borderColor: AstraColors.border,
    gap: 6,
  },
  metricLabel: {
    color: AstraColors.textMuted,
    fontSize: 12,
    textTransform: "uppercase",
    letterSpacing: 1.2,
  },
  metricValue: {
    color: AstraColors.textPrimary,
    fontSize: 15,
    fontWeight: "700",
  },
  actionRow: {
    flexDirection: "row",
    flexWrap: "wrap",
    gap: 10,
  },
  primaryButton: {
    borderRadius: 18,
    paddingHorizontal: 16,
    paddingVertical: 13,
    backgroundColor: AstraColors.accent,
    flexDirection: "row",
    alignItems: "center",
    gap: 8,
  },
  primaryButtonStop: {
    backgroundColor: AstraColors.accentWarm,
  },
  primaryButtonText: {
    color: AstraColors.textPrimary,
    fontSize: 14,
    fontWeight: "700",
  },
  secondaryButton: {
    borderRadius: 18,
    paddingHorizontal: 14,
    paddingVertical: 13,
    borderWidth: 1,
    borderColor: AstraColors.borderStrong,
    backgroundColor: "rgba(255,255,255,0.05)",
    flexDirection: "row",
    alignItems: "center",
    gap: 8,
  },
  secondaryButtonText: {
    color: AstraColors.textSecondary,
    fontSize: 14,
    fontWeight: "700",
  },
  captionText: {
    color: AstraColors.textMuted,
    fontSize: 12,
    lineHeight: 18,
  },
  errorCard: {
    borderRadius: 22,
    padding: 16,
    backgroundColor: AstraColors.warningMuted,
    borderWidth: 1,
    borderColor: "rgba(255,175,111,0.26)",
    gap: 10,
  },
  errorRow: {
    flexDirection: "row",
    gap: 10,
    alignItems: "flex-start",
  },
  errorText: {
    flex: 1,
    color: AstraColors.textPrimary,
    fontSize: 14,
    lineHeight: 20,
  },
  errorAction: {
    color: AstraColors.textPrimary,
    fontSize: 13,
    fontWeight: "700",
  },
  listHeader: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "space-between",
  },
  sectionListWrap: {
    gap: 18,
  },
  sectionTitle: {
    color: AstraColors.textPrimary,
    fontSize: 20,
    fontWeight: "700",
  },
  sectionCaption: {
    color: AstraColors.textMuted,
    fontSize: 13,
    fontWeight: "600",
  },
  deviceSection: {
    gap: 10,
  },
  deviceSectionHeader: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "space-between",
  },
  deviceSectionTitle: {
    color: AstraColors.textSecondary,
    fontSize: 15,
    fontWeight: "700",
  },
  deviceSectionCount: {
    color: AstraColors.textMuted,
    fontSize: 12,
    fontWeight: "700",
  },
  deviceSectionEmpty: {
    color: AstraColors.textMuted,
    fontSize: 13,
    lineHeight: 19,
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
  emptyFootnote: {
    color: AstraColors.textMuted,
    fontSize: 12,
    lineHeight: 18,
    textAlign: "center",
  },
  deviceCard: {
    borderRadius: 24,
    padding: 16,
    borderWidth: 1,
    borderColor: AstraColors.border,
    backgroundColor: "rgba(255,255,255,0.05)",
    gap: 8,
  },
  deviceHeader: {
    flexDirection: "row",
    alignItems: "center",
    gap: 12,
  },
  deviceHeaderRight: {
    alignItems: "center",
    gap: 8,
  },
  deviceIconWrap: {
    width: 42,
    height: 42,
    borderRadius: 16,
    alignItems: "center",
    justifyContent: "center",
    backgroundColor: "rgba(139,124,255,0.16)",
  },
  deviceCopy: {
    flex: 1,
    gap: 2,
  },
  deviceTitle: {
    color: AstraColors.textPrimary,
    fontSize: 16,
    fontWeight: "700",
  },
  deviceSubtitle: {
    color: AstraColors.textSecondary,
    fontSize: 13,
    fontWeight: "600",
  },
  signalPill: {
    borderRadius: 999,
    paddingHorizontal: 10,
    paddingVertical: 7,
  },
  signalPillStrong: {
    backgroundColor: AstraColors.safeMuted,
  },
  signalPillMedium: {
    backgroundColor: "rgba(139,124,255,0.18)",
  },
  signalPillWeak: {
    backgroundColor: AstraColors.warningMuted,
  },
  signalPillUnknown: {
    backgroundColor: "rgba(255,255,255,0.08)",
  },
  signalPillText: {
    color: AstraColors.textPrimary,
    fontSize: 11,
    fontWeight: "700",
  },
  deviceId: {
    color: AstraColors.textMuted,
    fontSize: 12,
    lineHeight: 18,
  },
  deviceMeta: {
    color: AstraColors.textSecondary,
    fontSize: 13,
    lineHeight: 18,
  },
  tagRow: {
    flexDirection: "row",
    flexWrap: "wrap",
    gap: 8,
    marginTop: 2,
  },
  tag: {
    borderRadius: 999,
    paddingHorizontal: 10,
    paddingVertical: 6,
    backgroundColor: "rgba(255,255,255,0.07)",
  },
  tagText: {
    color: AstraColors.textPrimary,
    fontSize: 11,
    fontWeight: "600",
  },
});
