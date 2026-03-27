import type { RootStackParamList } from "../../navigation/RootStack";

type AssistantContext = {
  title: string;
  subtitle: string;
  prompts: string[];
};

export function getAssistantContext(
  routeName: keyof RootStackParamList | null
): AssistantContext {
  switch (routeName) {
    case "Dashboard":
      return {
        title: "Astra Assistant",
        subtitle: "Grounded help for your current network and Bluetooth scans.",
        prompts: [
          "What stands out in this scan?",
          "What should I review first?",
          "How should I think about these unnamed Bluetooth signals?",
        ],
      };
    case "DeviceDetail":
      return {
        title: "Ask About This WiFi Device",
        subtitle: "Grounded help using this device's current scanner facts.",
        prompts: [
          "What should I know about this device?",
          "Does this device look risky?",
          "What should I do next?",
        ],
      };
    case "BluetoothDeviceDetail":
      return {
        title: "Ask About This Bluetooth Device",
        subtitle: "Grounded help using this BLE signal and its advertised data.",
        prompts: [
          "What might this Bluetooth device be?",
          "Is this signal suspicious?",
          "How should I interpret this advertised data?",
        ],
      };
    case "Connect":
      return {
        title: "Astra Assistant",
        subtitle: "Get help connecting scanners and understanding what Astra can see.",
        prompts: [
          "How do I connect my scanner?",
          "What data will Astra use?",
          "What can I do without connecting anything yet?",
        ],
      };
    default:
      return {
        title: "Astra Assistant",
        subtitle: "A context-aware assistant for your scan data.",
        prompts: [
          "What stands out here?",
          "What should I look at first?",
          "What can Astra help me understand?",
        ],
      };
  }
}
