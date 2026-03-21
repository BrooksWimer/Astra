import type { Device, ScanResult } from "@netwise/shared";

const TIMEOUT_MS = 15000;

export interface AgentInfo {
  version: string;
  hostname: string;
  local_ip: string;
  subnet?: string;
  cidr?: string;
  netmask?: string;
  broadcast?: string;
  gateway?: string;
  interface?: string;
  iface_mac?: string;
  large_subnet?: boolean;
}

async function fetchWithTimeout(
  url: string,
  options: RequestInit = {},
  ms: number = TIMEOUT_MS
): Promise<Response> {
  const ctrl = new AbortController();
  const id = setTimeout(() => ctrl.abort(), ms);
  try {
    const res = await fetch(url, { ...options, signal: ctrl.signal });
    clearTimeout(id);
    return res;
  } catch (e) {
    clearTimeout(id);
    throw e;
  }
}

export async function health(baseUrl: string): Promise<boolean> {
  try {
    const res = await fetchWithTimeout(base(baseUrl, "health"), {}, 5000);
    const data = await res.json();
    return data?.status === "ok";
  } catch {
    return false;
  }
}

export async function getInfo(baseUrl: string): Promise<AgentInfo> {
  const res = await fetchWithTimeout(base(baseUrl, "info"));
  if (!res.ok) throw new Error("Failed to get agent info");
  return res.json();
}

function base(baseUrl: string, path: string): string {
  const u = baseUrl.replace(/\/+$/, "");
  return path.startsWith("/") ? `${u}${path}` : `${u}/${path}`;
}

export async function startScan(baseUrl: string): Promise<{ scan_id: string }> {
  const res = await fetchWithTimeout(base(baseUrl, "scan/start"), { method: "POST" });
  if (!res.ok) throw new Error(`Failed to start scan: ${res.status}`);
  return res.json();
}

export async function getScanResult(baseUrl: string, scanId: string): Promise<ScanResult | null> {
  const res = await fetchWithTimeout(base(baseUrl, `scan/${encodeURIComponent(scanId)}`));
  if (!res.ok) return null;
  return res.json();
}

export async function getDevices(baseUrl: string): Promise<Device[]> {
  const res = await fetchWithTimeout(base(baseUrl, "devices"));
  if (!res.ok) throw new Error("Failed to get devices");
  const data = await res.json();
  return data?.devices ?? [];
}

export async function getDevice(baseUrl: string, deviceId: string): Promise<Device | null> {
  const res = await fetchWithTimeout(base(baseUrl, `devices/${encodeURIComponent(deviceId)}`));
  if (!res.ok) return null;
  return res.json();
}
