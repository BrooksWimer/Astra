import { Platform } from "react-native";

export type LocalWifiScanStatus = "disabled" | "unavailable" | "blocked" | "ready";

export function getLocalWifiScanStatus(): LocalWifiScanStatus {
  if (Platform.OS !== "ios") {
    return "unavailable";
  }

  return "disabled";
}

export async function startLocalWifiScan(): Promise<never> {
  throw new Error(
    "Local iOS Wi-Fi scan is not implemented yet. The app is still using the remote agent path."
  );
}

