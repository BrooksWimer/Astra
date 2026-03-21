import type { Device } from "@netwise/shared";

const DEVICE_TYPE_LABELS: Record<string, string> = {
  phone: "Phone",
  laptop: "Laptop",
  router: "Router",
  printer: "Printer",
  tv: "TV",
  speaker: "Speaker",
  camera: "Camera",
  iot: "Smart Device",
  unknown: "Unknown Device",
};

export function getDeviceTitle(device: Device): string {
  return device.hostname || device.vendor || device.ip;
}

export function getDeviceTypeLabel(deviceType: string): string {
  return DEVICE_TYPE_LABELS[deviceType] ?? "Unknown Device";
}

export function deviceNeedsReview(device: Device): boolean {
  return (
    device.flags.includes("risky_ports") ||
    device.flags.includes("new_device") ||
    device.device_type === "unknown" ||
    device.confidence < 0.35
  );
}

export function getDeviceSubtitle(device: Device): string {
  return deviceNeedsReview(device) ? "Needs Review" : getDeviceTypeLabel(device.device_type);
}

export function getDeviceStatusLabel(device: Device): string {
  return deviceNeedsReview(device) ? "Needs Review" : "Known Device";
}

export function getDeviceTags(device: Device): string[] {
  const tags: string[] = [];

  if (device.flags.includes("new_device")) tags.push("New");
  if (device.flags.includes("risky_ports")) tags.push("Risky Ports");
  if (device.flags.includes("changed_ip")) tags.push("IP Changed");
  if (device.device_type === "unknown") tags.push("Unknown");
  if (device.confidence < 0.35) tags.push("Low Confidence");
  if (device.protocols_seen.ssdp.length > 0) tags.push("SSDP");
  if (device.protocols_seen.mdns.length > 0) tags.push("mDNS");
  if (device.protocols_seen.netbios.length > 0) tags.push("NetBIOS");

  return tags.slice(0, 4);
}

export function sortDevicesForDashboard(devices: Device[]): Device[] {
  return [...devices].sort((left, right) => {
    const reviewDelta = Number(deviceNeedsReview(right)) - Number(deviceNeedsReview(left));
    if (reviewDelta !== 0) return reviewDelta;

    const rightSeen = Date.parse(right.last_seen) || 0;
    const leftSeen = Date.parse(left.last_seen) || 0;
    return rightSeen - leftSeen;
  });
}

export function formatRelativeTime(isoTimestamp: string): string {
  const parsed = Date.parse(isoTimestamp);
  if (Number.isNaN(parsed)) return "unknown";

  const deltaMs = Date.now() - parsed;
  const minute = 60 * 1000;
  const hour = 60 * minute;
  const day = 24 * hour;
  const month = 30 * day;
  const year = 365 * day;

  if (deltaMs < minute) return "just now";
  if (deltaMs < hour) return `${Math.max(1, Math.round(deltaMs / minute))}m ago`;
  if (deltaMs < day) return `${Math.max(1, Math.round(deltaMs / hour))}h ago`;
  if (deltaMs < month) return `${Math.max(1, Math.round(deltaMs / day))}d ago`;
  if (deltaMs < year) return `${Math.max(1, Math.round(deltaMs / month))}mo ago`;
  return `${Math.max(1, Math.round(deltaMs / year))}y ago`;
}

export function formatConfidence(confidence: number): string {
  return `${Math.round(confidence * 100)}% confident`;
}
