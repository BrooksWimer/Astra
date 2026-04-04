# iOS Wi-Fi Research

Current conclusion:

- iOS does not provide a general-purpose API for scanning nearby Wi-Fi access points in third-party apps.
- The feasible App Store-safe path today is usually limited to:
  - reading details about the currently connected network
  - joining a known network with user consent
  - discovering local devices over Bonjour / multicast when privacy permissions allow it

Relevant Apple requirements to account for:

- `NSLocalNetworkUsageDescription` in `Info.plist` for local network access prompts.
- `NSBonjourServices` when browsing specific Bonjour service types.
- `com.apple.developer.networking.wifi-info` entitlement for connected Wi-Fi info such as SSID/BSSID in the approved cases.
- `com.apple.developer.networking.HotspotConfiguration` entitlement for joining/configuring Wi-Fi networks with `NEHotspotConfiguration`.

Operational constraints:

- These APIs do not expose a full list of nearby Wi-Fi networks the way Android can.
- Anything that needs `NEHotspotConfiguration` or `wifi-info` may require Apple signing/provisioning changes.
- A real on-device Wi-Fi scanner will likely need a native module, not pure Expo JS.

Expo / React Native implication:

- Expo dev builds can carry the `Info.plist` usage strings immediately.
- Entitlements must be validated against the provisioning profile before we rely on them.
- If the next step is a native on-device scan path, stop and confirm the Apple provisioning details first.

