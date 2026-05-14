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
  // `hostname` is NOT in the JSON schema's `required[]` list, so the field
  // may be absent entirely (undefined), present as null when no hostname
  // was resolved, or present as a real string. Modeling it as `string | null`
  // alone broke server-side type-check against Zod's `.nullable().optional()`.
  hostname?: string | null;
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
