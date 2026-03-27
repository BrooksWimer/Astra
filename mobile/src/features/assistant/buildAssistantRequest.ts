import type {
  AssistantContextPayload,
  AssistantContextSyncRequest,
  AssistantBluetoothClassificationSummary,
  AssistantBluetoothDeviceDetail,
  AssistantBluetoothDeviceSummary,
  BluetoothScanDeviceContext,
} from "@netwise/shared";
import type { AgentInfo } from "../../api/agent";
import type { RootStackParamList } from "../../navigation/RootStack";

type BuildAssistantContextSyncRequestArgs = {
  sessionId: string;
  routeName: keyof RootStackParamList | null;
  routeParams: Record<string, unknown> | null;
  agentInfo: AgentInfo | null;
  agentBaseUrl: string | null;
  adviceBaseUrl: string | null;
  wifiScanInProgress: boolean;
  bluetoothScanInProgress: boolean;
  bluetoothDevices: BluetoothScanDeviceContext[];
  selectedBluetoothDevice: BluetoothScanDeviceContext | null;
};

function mapBluetoothClassification(
  device: BluetoothScanDeviceContext
): AssistantBluetoothClassificationSummary | null {
  const classification = device.classification;

  if (!classification) {
    return null;
  }

  return {
    likely_category: classification.likely_category.likely,
    likely_vendor: classification.likely_vendor.likely,
    confidence: classification.confidence,
    confidenceLabel: classification.confidenceLabel,
    flags: classification.flags,
    evidence: classification.evidence.slice(0, 5).map((entry) => entry.claim),
    uncertainty: classification.uncertainty.slice(0, 3),
    advice: classification.advice.slice(0, 3).map((entry) => entry.text),
  };
}

function mapBluetoothDeviceSummary(
  device: BluetoothScanDeviceContext
): AssistantBluetoothDeviceSummary {
  return {
    id: device.id,
    name: device.name,
    localName: device.localName,
    rssi: device.rssi,
    isConnectable: device.isConnectable,
    serviceUUIDs: device.serviceUUIDs,
    serviceDataKeys: device.serviceDataKeys,
    hasManufacturerData: device.hasManufacturerData,
    manufacturerCompanyId: device.manufacturerCompanyId,
    lastSeenAt: device.lastSeenAt,
    classification: mapBluetoothClassification(device),
  };
}

function mapBluetoothDeviceDetail(
  device: BluetoothScanDeviceContext
): AssistantBluetoothDeviceDetail {
  return {
    ...mapBluetoothDeviceSummary(device),
    txPowerLevel: device.txPowerLevel,
    solicitedServiceUUIDs: device.solicitedServiceUUIDs,
    overflowServiceUUIDs: device.overflowServiceUUIDs,
    serviceDataCount: device.serviceDataCount,
    manufacturerDataHex: device.manufacturerDataHex,
    rawScanRecordHex: device.rawScanRecordHex,
    serviceDataHexByUuid: device.serviceDataHexByUuid,
    discoveredAt: device.discoveredAt,
  };
}

export function buildAssistantContextSyncRequest({
  sessionId,
  routeName,
  routeParams,
  agentInfo,
  agentBaseUrl,
  adviceBaseUrl,
  wifiScanInProgress,
  bluetoothScanInProgress,
  bluetoothDevices,
  selectedBluetoothDevice,
}: BuildAssistantContextSyncRequestArgs): AssistantContextSyncRequest {
  const context: AssistantContextPayload = {
    route_name: routeName ?? "unknown",
    route_params:
      routeParams && typeof routeParams.deviceId === "string"
        ? { device_id: routeParams.deviceId }
        : undefined,
    app: {
      scanner_connected: Boolean(agentBaseUrl),
      advice_server_connected: Boolean(adviceBaseUrl),
      wifi_scan_in_progress: wifiScanInProgress,
      bluetooth_scan_in_progress: bluetoothScanInProgress,
    },
    network: agentInfo
      ? {
          hostname: agentInfo.hostname,
          local_ip: agentInfo.local_ip,
          gateway: agentInfo.gateway,
          subnet: agentInfo.subnet,
          cidr: agentInfo.cidr,
          interface: agentInfo.interface,
        }
      : null,
    agent_base_url: agentBaseUrl,
    bluetooth:
      bluetoothDevices.length || selectedBluetoothDevice
        ? {
            devices: bluetoothDevices.map(mapBluetoothDeviceSummary),
            selected_device: selectedBluetoothDevice
              ? mapBluetoothDeviceDetail(selectedBluetoothDevice)
              : undefined,
          }
        : null,
  };

  return {
    session_id: sessionId,
    context,
  };
}
