import {
  classifyBleDevice,
  normalizeBleUuid,
  parseManufacturerCompanyId,
  type BluetoothScanDeviceContext,
} from "@netwise/shared";
import type { Device } from "react-native-ble-plx";

export type BluetoothPermissionStatus =
  | "unknown"
  | "ready"
  | "needs-permission"
  | "denied"
  | "unavailable";

export type BluetoothScanDevice = BluetoothScanDeviceContext;

const BASE64_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

function base64ToBytes(value: string): number[] {
  const clean = value.replace(/[\r\n\s]/g, "").replace(/-/g, "+").replace(/_/g, "/");
  let buffer = 0;
  let bits = 0;
  const bytes: number[] = [];

  for (const char of clean) {
    if (char === "=") {
      break;
    }

    const index = BASE64_ALPHABET.indexOf(char);
    if (index === -1) {
      continue;
    }

    buffer = (buffer << 6) | index;
    bits += 6;

    while (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >> bits) & 0xff);
    }
  }

  return bytes;
}

function bytesToHex(bytes: number[]): string | null {
  if (!bytes.length) {
    return null;
  }

  return bytes.map((value) => value.toString(16).padStart(2, "0")).join("");
}

function base64ToHex(value: string | null | undefined): string | null {
  if (!value) {
    return null;
  }

  return bytesToHex(base64ToBytes(value));
}

function normalizeUuidList(values: string[] | null | undefined): string[] {
  return [
    ...new Set(
      (values ?? [])
        .map(normalizeBleUuid)
        .filter((value): value is string => Boolean(value))
    ),
  ];
}

function normalizeServiceData(
  serviceData: Record<string, string> | null | undefined
): Record<string, string> {
  if (!serviceData) {
    return {};
  }

  return Object.fromEntries(
    Object.entries(serviceData)
      .map(([uuid, value]) => [normalizeBleUuid(uuid), base64ToHex(value)])
      .filter((entry): entry is [string, string] => Boolean(entry[1]))
  );
}

export function mapBleDevice(device: Device): BluetoothScanDevice {
  const now = Date.now();
  const serviceDataHexByUuid = normalizeServiceData(device.serviceData ?? undefined);
  const manufacturerDataHex = base64ToHex(device.manufacturerData);
  const mapped: BluetoothScanDevice = {
    id: device.id,
    name: device.name,
    localName: device.localName,
    rssi: device.rssi,
    txPowerLevel: device.txPowerLevel,
    isConnectable: device.isConnectable,
    serviceUUIDs: normalizeUuidList(device.serviceUUIDs),
    solicitedServiceUUIDs: normalizeUuidList(device.solicitedServiceUUIDs),
    overflowServiceUUIDs: normalizeUuidList(device.overflowServiceUUIDs),
    serviceDataKeys: Object.keys(serviceDataHexByUuid),
    serviceDataCount: Object.keys(serviceDataHexByUuid).length,
    hasManufacturerData: Boolean(device.manufacturerData),
    manufacturerCompanyId: parseManufacturerCompanyId(manufacturerDataHex),
    manufacturerDataHex,
    rawScanRecordHex: base64ToHex(device.rawScanRecord),
    serviceDataHexByUuid,
    discoveredAt: now,
    lastSeenAt: now,
    classification: null,
  };

  mapped.classification = classifyBleDevice(mapped);
  return mapped;
}

export function upsertBluetoothDevice(
  devices: BluetoothScanDevice[],
  incoming: Device
): BluetoothScanDevice[] {
  const next = mapBleDevice(incoming);
  const index = devices.findIndex((device) => device.id === next.id);

  if (index === -1) {
    return [...devices, next];
  }

  const current = devices[index];
  const merged: BluetoothScanDevice = {
    ...current,
    ...next,
    name: next.name ?? current.name,
    localName: next.localName ?? current.localName,
    rssi: next.rssi ?? current.rssi,
    txPowerLevel: next.txPowerLevel ?? current.txPowerLevel,
    isConnectable: next.isConnectable ?? current.isConnectable,
    serviceUUIDs: next.serviceUUIDs.length ? next.serviceUUIDs : current.serviceUUIDs,
    solicitedServiceUUIDs: next.solicitedServiceUUIDs.length
      ? next.solicitedServiceUUIDs
      : current.solicitedServiceUUIDs,
    overflowServiceUUIDs: next.overflowServiceUUIDs.length
      ? next.overflowServiceUUIDs
      : current.overflowServiceUUIDs,
    serviceDataKeys: next.serviceDataKeys.length
      ? next.serviceDataKeys
      : current.serviceDataKeys,
    serviceDataCount: next.serviceDataCount || current.serviceDataCount,
    hasManufacturerData: next.hasManufacturerData || current.hasManufacturerData,
    manufacturerCompanyId:
      next.manufacturerCompanyId ?? current.manufacturerCompanyId,
    manufacturerDataHex: next.manufacturerDataHex ?? current.manufacturerDataHex,
    rawScanRecordHex: next.rawScanRecordHex ?? current.rawScanRecordHex,
    serviceDataHexByUuid: {
      ...current.serviceDataHexByUuid,
      ...next.serviceDataHexByUuid,
    },
    discoveredAt: current.discoveredAt,
    lastSeenAt: next.lastSeenAt,
    classification: null,
  };

  merged.classification = classifyBleDevice(merged);

  const updated = devices.slice();
  updated[index] = merged;
  return updated;
}

export function sortBluetoothDevices(devices: BluetoothScanDevice[]): BluetoothScanDevice[] {
  return [...devices].sort((left, right) => {
    const leftSignal = left.rssi ?? Number.NEGATIVE_INFINITY;
    const rightSignal = right.rssi ?? Number.NEGATIVE_INFINITY;

    if (rightSignal !== leftSignal) {
      return rightSignal - leftSignal;
    }

    return right.lastSeenAt - left.lastSeenAt;
  });
}

export function getBluetoothDeviceTitle(device: BluetoothScanDevice): string {
  return device.name || device.localName || "Unnamed device";
}

export function getBluetoothDeviceSubtitle(device: BluetoothScanDevice): string {
  if (device.name && device.localName && device.name !== device.localName) {
    return device.localName;
  }

  if (device.isConnectable === true) {
    return "Connectable BLE peripheral";
  }

  if (device.isConnectable === false) {
    return "Advertising nearby";
  }

  return "Nearby Bluetooth signal";
}

export function formatBluetoothSeenTime(timestamp: number | null): string {
  if (!timestamp) {
    return "Not yet";
  }

  const seconds = Math.max(Math.floor((Date.now() - timestamp) / 1000), 0);

  if (seconds < 5) {
    return "just now";
  }

  if (seconds < 60) {
    return `${seconds}s ago`;
  }

  const minutes = Math.floor(seconds / 60);

  if (minutes < 60) {
    return `${minutes}m ago`;
  }

  const hours = Math.floor(minutes / 60);
  return `${hours}h ago`;
}

export function formatBluetoothRssi(rssi: number | null): string {
  if (rssi == null) {
    return "RSSI unavailable";
  }

  return `${rssi} dBm`;
}

export function getBluetoothSignalLabel(rssi: number | null): string {
  if (rssi == null) {
    return "Unknown signal";
  }

  if (rssi >= -55) {
    return "Very close";
  }

  if (rssi >= -67) {
    return "Nearby";
  }

  if (rssi >= -80) {
    return "In range";
  }

  return "Farther away";
}

export function getBluetoothSignalTone(
  rssi: number | null
): "strong" | "medium" | "weak" | "unknown" {
  if (rssi == null) {
    return "unknown";
  }

  if (rssi >= -60) {
    return "strong";
  }

  if (rssi >= -78) {
    return "medium";
  }

  return "weak";
}

export function getBluetoothDeviceTags(device: BluetoothScanDevice): string[] {
  const tags: string[] = [];

  if (device.isConnectable === true) {
    tags.push("Connectable");
  }

  if (device.serviceUUIDs.length) {
    tags.push(
      `${device.serviceUUIDs.length} advertised service${
        device.serviceUUIDs.length === 1 ? "" : "s"
      }`
    );
  }

  if (device.serviceDataCount) {
    tags.push(
      `${device.serviceDataCount} service data block${
        device.serviceDataCount === 1 ? "" : "s"
      }`
    );
  }

  if (device.hasManufacturerData) {
    tags.push("Manufacturer data");
  }

  return tags;
}

export function getBluetoothPermissionLabel(
  status: BluetoothPermissionStatus
): string {
  switch (status) {
    case "ready":
      return "Ready";
    case "needs-permission":
      return "Needs permission";
    case "denied":
      return "Denied";
    case "unavailable":
      return "Unavailable";
    default:
      return "Checking";
  }
}
