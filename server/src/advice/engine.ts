import type { AdviceRequest, AdviceResponse, AdviceAction } from "@netwise/shared";

const RISKY_PORTS = [445, 3389, 22];
const RISKY_HOME_PORTS = [445, 3389];

export function getAdvice(req: AdviceRequest): AdviceResponse {
  const reasons: string[] = [];
  const actions: AdviceAction[] = [];
  const uncertainty: string[] = [];
  let riskLevel: "low" | "medium" | "high" = "low";

  const { device, user_context: context } = req;

  // Device type–based advice (grounded to facts)
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
    riskLevel = riskLevel === "low" ? "medium" : riskLevel;
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
    riskLevel = "medium";
  }

  // Risky ports (cite facts)
  const openPorts = device.ports_open ?? [];
  const riskyOpen = openPorts.filter((p) => RISKY_HOME_PORTS.includes(p));
  if (riskyOpen.length > 0) {
    reasons.push(`Open ports ${riskyOpen.join(", ")} are often used for file sharing (445) or remote desktop (3389); on a home network this can increase exposure.`);
    actions.push({
      title: "Review open high-risk ports",
      steps: [
        "Ensure only trusted devices need SMB (445) or RDP (3389).",
        "Use a firewall or router rules to restrict access if possible.",
      ],
      urgency: context === "home" ? "soon" : "nice_to_have",
    });
    if (context === "home") riskLevel = "high";
    else if (riskLevel === "low") riskLevel = "medium";
  }

  // New device flag
  if (device.flags?.includes("new_device")) {
    reasons.push("This device was first seen in the latest scan.");
    actions.push({
      title: "Confirm new device",
      steps: ["Verify you recognize this device (vendor, MAC, IP).", "If not, consider changing Wi‑Fi password and reconnecting only known devices."],
      urgency: "nice_to_have",
    });
  }

  // Build summary from reasons
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
