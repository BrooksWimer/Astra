/**
 * Types derived from shared/schema.json - keep in sync with schema.
 */

export type DeviceType =
  | "phone"
  | "laptop"
  | "router"
  | "printer"
  | "tv"
  | "speaker"
  | "camera"
  | "iot"
  | "unknown";

export interface ProtocolsSeen {
  mdns: string[];
  ssdp: string[];
  netbios: string[];
}

export interface Device {
  id: string;
  ip: string;
  mac: string;
  vendor: string;
  hostname: string | null;
  protocols_seen: ProtocolsSeen;
  ports_open?: number[];
  first_seen: string;
  last_seen: string;
  flags: string[];
  confidence: number;
  device_type: DeviceType;
}

export interface NetworkInfo {
  subnet?: string;
  gateway_ip?: string;
  local_ip?: string;
  interface_name?: string;
}

export interface ScanResult {
  network: NetworkInfo;
  devices: Device[];
  scan_started_at: string;
  scan_finished_at: string | null;
  scan_id: string;
}

export type UserContext = "home" | "airbnb" | "office" | "unknown";

export interface AdviceRequest {
  scan_id: string;
  device_id: string;
  device: Device;
  network: NetworkInfo;
  user_context: UserContext;
}

export type RiskLevel = "low" | "medium" | "high";

export type Urgency = "now" | "soon" | "nice_to_have";

export interface AdviceAction {
  title: string;
  steps: string[];
  urgency: Urgency;
}

export interface AdviceResponse {
  summary: string;
  risk_level: RiskLevel;
  reasons: string[];
  actions: AdviceAction[];
  uncertainty_notes: string[];
}

export type AssistantRole = "user" | "assistant";

export interface AssistantChatMessage {
  role: AssistantRole;
  text: string;
}

export type AssistantRoute =
  | "Connect"
  | "Dashboard"
  | "DeviceDetail"
  | "BluetoothDeviceDetail"
  | "unknown";

export type BleEvidenceStrength = "strong" | "medium" | "weak";

export type BleConfidenceLabel = "high" | "medium" | "low";

export type BleEvidenceDimension = "vendor" | "category" | "flag";

export type BleEvidenceSourceFamily =
  | "company_identifier"
  | "sig_adopted_service"
  | "sig_member_uuid"
  | "eddystone"
  | "ibeacon"
  | "name_heuristic"
  | "connectability_heuristic";

export type BleCategoryId =
  | "beacon"
  | "tag_or_tracker"
  | "wearable_fitness"
  | "medical_device"
  | "audio_device"
  | "hearing_assist"
  | "input_device"
  | "smart_home_mesh"
  | "smart_home_sensor"
  | "vehicle_system"
  | "computer_or_phone"
  | "industrial_or_enterprise"
  | "unknown";

export type BleDeterministicFlag =
  | "broadcast_only"
  | "connectable"
  | "sparse_advertisement"
  | "rotating_identifier_likely"
  | "has_manufacturer_data_unparsed"
  | "has_service_data_unparsed"
  | "multi_role_signals"
  | "health_data_context"
  | "input_device_context"
  | "nearby_high_rssi"
  | "persistently_nearby";

export interface BleCandidateScore {
  id: string;
  points: number;
}

export interface BleEvidence {
  ruleId: string;
  strength: BleEvidenceStrength;
  dimension: BleEvidenceDimension;
  candidateId?: string;
  claim: string;
  points: number;
  dataUsed: Record<string, unknown>;
  sourceFamily: BleEvidenceSourceFamily;
}

export interface BleAdvice {
  id: string;
  title: string;
  text: string;
  severity: "info" | "attention";
  relatedFlags: BleDeterministicFlag[];
}

export interface BleDimensionResult {
  likely: string;
  confidence: number;
  confidenceLabel: BleConfidenceLabel;
  candidates: BleCandidateScore[];
  evidence: BleEvidence[];
  uncertainty: string[];
}

export interface BleObservedDevice {
  id: string;
  name: string | null;
  localName: string | null;
  rssi: number | null;
  txPowerLevel: number | null;
  isConnectable: boolean | null;
  serviceUUIDs: string[];
  solicitedServiceUUIDs: string[];
  overflowServiceUUIDs: string[];
  serviceDataKeys: string[];
  serviceDataCount: number;
  hasManufacturerData: boolean;
  manufacturerCompanyId: number | null;
  manufacturerDataHex: string | null;
  rawScanRecordHex: string | null;
  serviceDataHexByUuid: Record<string, string>;
  discoveredAt: number;
  lastSeenAt: number;
}

export interface BleDeviceClassification {
  likely_vendor: BleDimensionResult;
  likely_category: BleDimensionResult;
  confidence: number;
  confidenceLabel: BleConfidenceLabel;
  evidence: BleEvidence[];
  uncertainty: string[];
  flags: BleDeterministicFlag[];
  advice: BleAdvice[];
}

export interface BluetoothScanDeviceContext extends BleObservedDevice {
  classification?: BleDeviceClassification | null;
}

export interface AssistantAppState {
  scanner_connected: boolean;
  advice_server_connected: boolean;
  wifi_scan_in_progress: boolean;
  bluetooth_scan_in_progress: boolean;
}

export interface AssistantNetworkSnapshot {
  hostname?: string;
  local_ip?: string;
  gateway?: string;
  subnet?: string;
  cidr?: string;
  interface?: string;
}

export interface AssistantRouteParams {
  device_id?: string;
}

export interface AssistantBluetoothClassificationSummary {
  likely_category: string;
  likely_vendor: string;
  confidence: number;
  confidenceLabel: BleConfidenceLabel;
  flags: BleDeterministicFlag[];
  evidence: string[];
  uncertainty: string[];
  advice: string[];
}

export interface AssistantBluetoothDeviceSummary {
  id: string;
  name: string | null;
  localName: string | null;
  rssi: number | null;
  isConnectable: boolean | null;
  serviceUUIDs: string[];
  serviceDataKeys: string[];
  hasManufacturerData: boolean;
  manufacturerCompanyId: number | null;
  lastSeenAt: number;
  classification?: AssistantBluetoothClassificationSummary | null;
}

export interface AssistantBluetoothDeviceDetail
  extends AssistantBluetoothDeviceSummary {
  txPowerLevel: number | null;
  solicitedServiceUUIDs: string[];
  overflowServiceUUIDs: string[];
  serviceDataCount: number;
  manufacturerDataHex: string | null;
  rawScanRecordHex: string | null;
  serviceDataHexByUuid: Record<string, string>;
  discoveredAt: number;
}

export interface AssistantContextPayload {
  route_name: AssistantRoute;
  route_params?: AssistantRouteParams;
  app: AssistantAppState;
  network: AssistantNetworkSnapshot | null;
  agent_base_url: string | null;
  bluetooth: {
    devices: AssistantBluetoothDeviceSummary[];
    selected_device?: AssistantBluetoothDeviceDetail | null;
  } | null;
}

export interface AssistantContextSyncRequest {
  session_id: string;
  context: AssistantContextPayload;
}

export interface AssistantContextSyncResponse {
  ok: true;
  synced_at: string;
}

export interface AssistantRequest {
  session_id: string;
  message: string;
}

export type AssistantMode = "ai" | "fallback";

export interface AssistantResponse {
  reply: string;
  suggestions: string[];
  mode: AssistantMode;
  model?: string;
}
