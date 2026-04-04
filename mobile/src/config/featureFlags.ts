function isEnabled(value: string | undefined): boolean {
  return value === "1" || value === "true" || value === "yes";
}

export const featureFlags = {
  localWifiScan: isEnabled(process.env.EXPO_PUBLIC_ENABLE_LOCAL_WIFI_SCAN),
} as const;

