/**
 * Network-level insight aggregator.
 *
 * The per-device advice engine in src/advice/engine.ts answers "what should
 * the user do about *this* device". This module answers the bigger
 * question: "what does the *shape* of the network tell us?".
 *
 * Examples:
 *   - "You have 14 devices, 6 of them classified as IoT — consider a guest
 *     network."
 *   - "3 devices have SMB (port 445) open. On a home network that's usually
 *     more exposure than you need."
 *   - "Two cameras are present. Cameras default to vendor-cloud relays;
 *     make sure each one is on its current firmware."
 *   - "Half the devices are still `unknown`. The desktop agent would label
 *     more of them."
 *
 * Each insight cites the device IDs it draws from (`evidence`) so the UI
 * can let the user drill into "which devices triggered this".
 */

import type { Device, RiskLevel } from "@netwise/shared";

export type InsightSeverity = "info" | "warn" | "critical";

export interface NetworkInsight {
  id: string;
  severity: InsightSeverity;
  title: string;
  summary: string;
  evidence: string[]; // device IDs the insight is based on
}

export interface NetworkInsightReport {
  generatedAt: string;
  deviceCount: number;
  byDeviceType: Record<string, number>;
  riskLevel: RiskLevel;
  insights: NetworkInsight[];
}

const HIGH_RISK_HOME_PORTS = new Set([445, 3389]);

export function summarizeNetwork(devices: Device[]): NetworkInsightReport {
  const insights: NetworkInsight[] = [];
  const byDeviceType: Record<string, number> = {};
  for (const device of devices) {
    byDeviceType[device.device_type] = (byDeviceType[device.device_type] ?? 0) + 1;
  }

  // ----- Camera presence -----
  const cameras = devices.filter((d) => d.device_type === "camera");
  if (cameras.length > 0) {
    insights.push({
      id: "cameras-present",
      severity: "critical",
      title:
        cameras.length === 1
          ? "A network camera is on this network"
          : `${cameras.length} network cameras are on this network`,
      summary:
        "Network cameras default to vendor-cloud relays and are one of the most-commonly-" +
        "compromised classes on home networks. Confirm each one has a non-default password, " +
        "a current firmware, and is on a guest/IoT VLAN if your router supports one.",
      evidence: cameras.map((d) => d.id),
    });
  }

  // ----- IoT density -----
  const iot = devices.filter((d) => d.device_type === "iot");
  if (iot.length >= 3) {
    insights.push({
      id: "iot-density",
      severity: "warn",
      title: `${iot.length} IoT devices on this network`,
      summary:
        "Smart-home devices rarely get firmware updates and often phone home over plaintext " +
        "protocols. Moving them onto a guest or IoT-only Wi-Fi network limits how far an " +
        "outdated one could reach if it ever got compromised.",
      evidence: iot.map((d) => d.id),
    });
  }

  // ----- Risky ports across the whole network -----
  const riskyDevices = devices.filter((d) =>
    (d.ports_open ?? []).some((port) => HIGH_RISK_HOME_PORTS.has(port)),
  );
  if (riskyDevices.length > 0) {
    insights.push({
      id: "smb-rdp-exposure",
      severity: "warn",
      title:
        riskyDevices.length === 1
          ? "1 device exposes SMB or RDP"
          : `${riskyDevices.length} devices expose SMB or RDP`,
      summary:
        "Ports 445 (SMB file sharing) and 3389 (Remote Desktop) are useful on a managed " +
        "office network and almost always more exposure than you need at home. Restrict " +
        "with firewall or router rules unless you specifically use them.",
      evidence: riskyDevices.map((d) => d.id),
    });
  }

  // ----- Unknown coverage -----
  const unknowns = devices.filter((d) => d.device_type === "unknown");
  const unknownRatio = devices.length > 0 ? unknowns.length / devices.length : 0;
  if (devices.length >= 5 && unknownRatio >= 0.4) {
    insights.push({
      id: "unknown-coverage",
      severity: "info",
      title: `${unknowns.length} of ${devices.length} devices are still unclassified`,
      summary:
        "Astra labels devices by inferring from vendor + protocols. When the desktop agent " +
        "runs against the same network it can probe more broadly and usually gets the " +
        "unknown count below 10%. If you only have the mobile app today, installing the " +
        "desktop agent and syncing through the same handle would fill these in.",
      evidence: unknowns.map((d) => d.id),
    });
  }

  // ----- New devices flagged by the scanner -----
  const newlySeen = devices.filter((d) => d.flags?.includes("new_device"));
  if (newlySeen.length > 0) {
    insights.push({
      id: "new-devices",
      severity: "info",
      title:
        newlySeen.length === 1
          ? "1 device is new since the last scan"
          : `${newlySeen.length} devices are new since the last scan`,
      summary:
        "Verify each new device is something you recognize. If any of them aren't yours, " +
        "consider rotating your Wi-Fi password and reconnecting only known devices.",
      evidence: newlySeen.map((d) => d.id),
    });
  }

  // ----- Network-level risk roll-up -----
  // The roll-up reflects the worst single insight; "no insights" means low.
  let riskLevel: RiskLevel = "low";
  for (const insight of insights) {
    if (insight.severity === "critical") {
      riskLevel = "high";
      break;
    }
    if (insight.severity === "warn" && riskLevel === "low") {
      riskLevel = "medium";
    }
  }

  return {
    generatedAt: new Date().toISOString(),
    deviceCount: devices.length,
    byDeviceType,
    riskLevel,
    insights,
  };
}
