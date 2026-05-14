import type { AdviceRequest, AdviceResponse, AdviceAction } from "@netwise/shared";

// SMB (445) and RDP (3389) are the high-signal "exposed on a home LAN
// and probably shouldn't be" ports. 22 (SSH) is risky on the wider
// internet but routinely fine inside a home (servers, NAS, dev boxes),
// so it stays out of the "risky home" set even though it's in the
// broader "risky" set kept for future use.
const RISKY_HOME_PORTS = [445, 3389];

type RiskLevel = "low" | "medium" | "high";

function bump(current: RiskLevel, to: RiskLevel): RiskLevel {
  const order: RiskLevel[] = ["low", "medium", "high"];
  return order[Math.max(order.indexOf(current), order.indexOf(to))];
}

export function getAdvice(req: AdviceRequest): AdviceResponse {
  const reasons: string[] = [];
  const actions: AdviceAction[] = [];
  const uncertainty: string[] = [];
  let riskLevel: RiskLevel = "low";

  const { device, user_context: context } = req;

  // ---------------------------------------------------------------------
  // Device-type rules — grounded in the classified device_type only. Each
  // rule must reference the type in its `reasons` entry so the operator
  // can audit why the advice fired.
  // ---------------------------------------------------------------------

  if (device.device_type === "router") {
    reasons.push("Device is identified as a router (from vendor/hostname).");
    actions.push({
      title: "Secure your router",
      steps: [
        "Change default admin password.",
        "Disable UPnP if you don't need it.",
        "Keep firmware updated.",
      ],
      urgency: "soon",
    });
    riskLevel = bump(riskLevel, "medium");
  }

  if (device.device_type === "camera") {
    // Network cameras are one of the most-commonly-compromised classes of
    // device on home networks: default credentials, vendor cloud relay
    // turned on out of the box, public ONVIF endpoints. Treat as high risk
    // until the operator confirms the camera is on a guest/IoT segment.
    reasons.push("Device is identified as a network camera — a frequently-exploited class on home networks.");
    actions.push({
      title: "Lock down camera defaults",
      steps: [
        "Change default admin password and disable any factory accounts.",
        "Turn off vendor cloud relay or remote viewing unless you actively use it.",
        "Apply the latest firmware update.",
        "Confirm UPnP / port forwarding to the camera is disabled on the router.",
      ],
      urgency: "now",
    });
    actions.push({
      title: "Segment cameras off the main network",
      steps: [
        "If your router supports a guest or IoT VLAN, move the camera there so it can't reach your laptop / phone / NAS.",
        "Block outbound internet for the camera if you only stream locally.",
      ],
      urgency: "soon",
    });
    riskLevel = bump(riskLevel, "high");
  }

  if (device.device_type === "iot") {
    // Smart plugs, hubs, thermostats — generally low-blast-radius alone
    // but cumulatively a risk because they rarely get firmware updates
    // and often phone home over plaintext protocols.
    reasons.push("Device is classified as IoT (smart-home / sensor / appliance).");
    actions.push({
      title: "Keep IoT devices isolated",
      steps: [
        "Move IoT devices to a guest or IoT-only Wi-Fi network if your router supports one.",
        "Disable UPnP so the device can't open inbound holes by itself.",
        "Apply firmware updates when the vendor app prompts you.",
      ],
      urgency: "soon",
    });
    riskLevel = bump(riskLevel, "medium");
  }

  if (device.device_type === "printer") {
    // Printers are low-risk on a home LAN — main concern is firmware lag
    // and the fact that some leak via mDNS to the wider internet if UPnP
    // is on. Not urgent.
    reasons.push("Device is identified as a printer.");
    actions.push({
      title: "Keep printer firmware current",
      steps: [
        "Check the printer's admin page or vendor app for firmware updates.",
        "Disable internet-facing services (e.g. ePrint / Cloud Print) if you don't use them.",
      ],
      urgency: "nice_to_have",
    });
  }

  if (device.device_type === "tv") {
    // Smart TVs are mostly a privacy concern (telemetry, ACR) rather than
    // a security risk on the LAN itself.
    reasons.push("Device is identified as a smart TV.");
    actions.push({
      title: "Review smart-TV privacy + updates",
      steps: [
        "Disable ACR (automatic content recognition) in the TV's settings if you don't want viewing telemetry sent to the vendor.",
        "Check for firmware updates in the TV's settings menu.",
      ],
      urgency: "nice_to_have",
    });
  }

  if (device.device_type === "speaker") {
    // Voice-enabled speakers carry a privacy concern around always-on
    // microphones; non-voice speakers don't. Keep advice generic since
    // device_type alone doesn't say which it is.
    reasons.push("Device is identified as a network or voice-enabled speaker.");
    actions.push({
      title: "Review voice-assistant privacy",
      steps: [
        "If this is a voice-enabled speaker, review the vendor app for stored recordings and mic privacy settings.",
        "Apply firmware updates from the vendor app.",
      ],
      urgency: "nice_to_have",
    });
  }

  if (device.device_type === "unknown") {
    uncertainty.push("Device type could not be inferred from vendor or hostname.");
    actions.push({
      title: "Verify unknown device",
      steps: [
        "Confirm the device belongs to you or your network.",
        "Check MAC address against device labels or manufacturer lookup.",
      ],
      urgency: "soon",
    });
    riskLevel = bump(riskLevel, "medium");
  }

  // ---------------------------------------------------------------------
  // Port-based rules — cite the actual open ports observed by the scanner.
  // ---------------------------------------------------------------------

  const openPorts = device.ports_open ?? [];
  const riskyOpen = openPorts.filter((p) => RISKY_HOME_PORTS.includes(p));
  if (riskyOpen.length > 0) {
    reasons.push(
      `Open ports ${riskyOpen.join(", ")} are often used for file sharing (445) or remote desktop (3389); on a home network this can increase exposure.`,
    );
    actions.push({
      title: "Review open high-risk ports",
      steps: [
        "Ensure only trusted devices need SMB (445) or RDP (3389).",
        "Use a firewall or router rules to restrict access if possible.",
      ],
      urgency: context === "home" ? "soon" : "nice_to_have",
    });
    if (context === "home") riskLevel = "high";
    else riskLevel = bump(riskLevel, "medium");
  }

  // ---------------------------------------------------------------------
  // Flag-based rules — surface scanner-observed signals like "this is
  // the first time we've ever seen this MAC on the network."
  // ---------------------------------------------------------------------

  if (device.flags?.includes("new_device")) {
    reasons.push("This device was first seen in the latest scan.");
    actions.push({
      title: "Confirm new device",
      steps: [
        "Verify you recognize this device (vendor, MAC, IP).",
        "If not, consider changing Wi-Fi password and reconnecting only known devices.",
      ],
      urgency: "nice_to_have",
    });
  }

  // ---------------------------------------------------------------------
  // Summary + response shape.
  // ---------------------------------------------------------------------

  let summary =
    reasons.length > 0
      ? reasons.join(" ")
      : "No specific risks identified from the provided device and network facts.";
  if (uncertainty.length > 0) {
    summary += " " + uncertainty.join(" ");
  }

  return {
    summary,
    risk_level: riskLevel,
    reasons,
    actions,
    uncertainty_notes: uncertainty,
  };
}
