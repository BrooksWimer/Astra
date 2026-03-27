import type {
  AdviceRequest,
  AssistantBluetoothDeviceDetail,
  AssistantBluetoothDeviceSummary,
  AssistantContextPayload,
  AssistantContextSyncRequest,
  AssistantRequest,
  AssistantResponse,
  Device,
} from "@netwise/shared";
import { getAdvice } from "../advice/engine.js";
import {
  getAssistantSession,
  setAssistantSessionResponseId,
  syncAssistantSessionContext,
  type AssistantSession,
} from "./sessionStore.js";

const OPENAI_API_URL = "https://api.openai.com/v1/responses";
const OPENAI_MODEL = process.env.OPENAI_MODEL || "gpt-5-mini";
const AGENT_TIMEOUT_MS = 12000;

type OpenAIResponse = {
  id?: string;
  status?: string;
  incomplete_details?: {
    reason?: string;
  } | null;
  output?: Array<{
    type?: string;
    name?: string;
    arguments?: string;
    call_id?: string;
    content?: Array<{
      type?: string;
      text?: string;
      refusal?: string;
    }>;
  }>;
  output_text?: string;
};

type ToolExecutionCache = {
  wifiDevices?: Device[] | null;
};

type ToolCall = {
  callId: string;
  name: string;
  argumentsText: string;
};

const assistantTools = [
  {
    type: "function",
    name: "get_session_overview",
    description:
      "Get the current Astra screen, connection state, selected device ids, and scan counts for this session.",
    parameters: {
      type: "object",
      properties: {},
      additionalProperties: false,
    },
  },
  {
    type: "function",
    name: "get_wifi_scan_summary",
    description:
      "Fetch a compact live summary of the current WiFi scanner results from the scanner agent.",
    parameters: {
      type: "object",
      properties: {
        limit: {
          type: "number",
          description: "How many devices to include in the summary list.",
        },
        review_only: {
          type: "boolean",
          description:
            "If true, return only devices that likely need user attention.",
        },
      },
      additionalProperties: false,
    },
  },
  {
    type: "function",
    name: "get_wifi_device",
    description:
      "Fetch live WiFi details for one device. Omit device_id to use the WiFi device selected on the current screen.",
    parameters: {
      type: "object",
      properties: {
        device_id: {
          type: "string",
          description: "The WiFi device id to inspect.",
        },
      },
      additionalProperties: false,
    },
  },
  {
    type: "function",
    name: "get_bluetooth_scan_summary",
    description:
      "Get a compact summary of the Bluetooth devices most recently synced from the phone.",
    parameters: {
      type: "object",
      properties: {
        limit: {
          type: "number",
          description: "How many Bluetooth devices to include in the summary list.",
        },
        named_only: {
          type: "boolean",
          description: "If true, return only Bluetooth devices with names.",
        },
      },
      additionalProperties: false,
    },
  },
  {
    type: "function",
    name: "get_bluetooth_device",
    description:
      "Get Bluetooth details for one synced signal. Omit device_id to use the Bluetooth device selected on the current screen.",
    parameters: {
      type: "object",
      properties: {
        device_id: {
          type: "string",
          description: "The Bluetooth device id to inspect.",
        },
      },
      additionalProperties: false,
    },
  },
] as const;

function getFollowUpSuggestions(
  routeName: AssistantContextPayload["route_name"] | undefined
): string[] {
  switch (routeName) {
    case "Dashboard":
      return [
        "What deserves attention first?",
        "Give me a calmer summary of this scan.",
        "What should I ignore for now?",
      ];
    case "DeviceDetail":
      return [
        "What should I do next with this device?",
        "Why did Astra focus on this device?",
        "What questions should I ask about it?",
      ];
    case "BluetoothDeviceDetail":
      return [
        "What could this Bluetooth signal be?",
        "How confident can we be about this signal?",
        "What else would help identify it?",
      ];
    case "Connect":
      return [
        "What do I need to connect first?",
        "Can Astra work without the scanner?",
        "What data powers the assistant?",
      ];
    default:
      return [
        "What stands out here?",
        "What should I check first?",
        "What can Astra explain from this screen?",
      ];
  }
}

function base(baseUrl: string, path: string): string {
  const trimmed = baseUrl.replace(/\/+$/, "");
  return path.startsWith("/") ? `${trimmed}${path}` : `${trimmed}/${path}`;
}

async function fetchWithTimeout(
  url: string,
  options: RequestInit = {},
  timeoutMs: number = AGENT_TIMEOUT_MS
): Promise<Response> {
  const ctrl = new AbortController();
  const id = setTimeout(() => ctrl.abort(), timeoutMs);

  try {
    const res = await fetch(url, { ...options, signal: ctrl.signal });
    clearTimeout(id);
    return res;
  } catch (error) {
    clearTimeout(id);
    throw error;
  }
}

function getSelectedWifiDeviceId(
  context: AssistantContextPayload | null
): string | null {
  if (!context || context.route_name !== "DeviceDetail") {
    return null;
  }

  return context.route_params?.device_id ?? null;
}

function getSelectedBluetoothDeviceId(
  context: AssistantContextPayload | null
): string | null {
  if (!context) {
    return null;
  }

  if (context.route_name === "BluetoothDeviceDetail") {
    return context.route_params?.device_id ?? context.bluetooth?.selected_device?.id ?? null;
  }

  return context.bluetooth?.selected_device?.id ?? null;
}

function deviceNeedsReview(device: Device): boolean {
  return (
    device.flags.includes("new_device") ||
    device.device_type === "unknown" ||
    (device.ports_open ?? []).some((port) => [445, 3389, 22].includes(port)) ||
    device.confidence < 0.35
  );
}

function summarizeWifiDevice(device: Device) {
  return {
    id: device.id,
    title: device.hostname || device.vendor || device.ip,
    ip: device.ip,
    mac: device.mac,
    vendor: device.vendor,
    device_type: device.device_type,
    confidence: device.confidence,
    flags: device.flags,
    open_ports: device.ports_open ?? [],
    first_seen: device.first_seen,
    last_seen: device.last_seen,
  };
}

function buildWifiDeviceDetail(device: Device) {
  return {
    ...summarizeWifiDevice(device),
    hostname: device.hostname,
    protocols_seen: device.protocols_seen,
  };
}

function summarizeBluetoothDevice(
  device: AssistantBluetoothDeviceSummary | AssistantBluetoothDeviceDetail
) {
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
    classification: device.classification
      ? {
          likely_category: device.classification.likely_category,
          likely_vendor: device.classification.likely_vendor,
          confidence: device.classification.confidence,
          confidenceLabel: device.classification.confidenceLabel,
          flags: device.classification.flags,
          evidence: device.classification.evidence,
          uncertainty: device.classification.uncertainty,
          advice: device.classification.advice,
        }
      : null,
  };
}

function buildBluetoothDeviceDetail(device: AssistantBluetoothDeviceDetail) {
  return {
    ...summarizeBluetoothDevice(device),
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

function buildBluetoothCategoryCounts(
  devices: AssistantBluetoothDeviceSummary[]
): Record<string, number> {
  return devices.reduce<Record<string, number>>((counts, device) => {
    const category = device.classification?.likely_category;

    if (!category || category === "unknown") {
      return counts;
    }

    counts[category] = (counts[category] ?? 0) + 1;
    return counts;
  }, {});
}

function sortBluetoothDevices(
  devices: AssistantBluetoothDeviceSummary[]
): AssistantBluetoothDeviceSummary[] {
  return [...devices].sort((left, right) => {
    const leftNamed = left.name || left.localName ? 1 : 0;
    const rightNamed = right.name || right.localName ? 1 : 0;

    if (leftNamed !== rightNamed) {
      return rightNamed - leftNamed;
    }

    return (right.rssi ?? -999) - (left.rssi ?? -999);
  });
}

function clampLimit(value: unknown, fallback: number, max: number): number {
  if (typeof value !== "number" || Number.isNaN(value)) {
    return fallback;
  }

  return Math.max(1, Math.min(max, Math.round(value)));
}

function parseToolArgs(argumentsText: string): Record<string, unknown> {
  if (!argumentsText.trim()) {
    return {};
  }

  try {
    const parsed = JSON.parse(argumentsText);
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

async function fetchWifiDevices(
  session: AssistantSession,
  cache: ToolExecutionCache
): Promise<Device[] | null> {
  if (cache.wifiDevices !== undefined) {
    return cache.wifiDevices;
  }

  const baseUrl = session.context?.agent_base_url;

  if (!baseUrl) {
    cache.wifiDevices = null;
    return null;
  }

  try {
    const response = await fetchWithTimeout(base(baseUrl, "devices"));
    if (!response.ok) {
      cache.wifiDevices = null;
      return null;
    }

    const payload = await response.json();
    const devices: Device[] = payload?.devices ?? [];
    cache.wifiDevices = devices;
    return devices;
  } catch {
    cache.wifiDevices = null;
    return null;
  }
}

async function fetchWifiDevice(
  session: AssistantSession,
  cache: ToolExecutionCache,
  deviceId: string
): Promise<Device | null> {
  const cachedDevices = await fetchWifiDevices(session, cache);
  const cachedMatch = cachedDevices?.find((device) => device.id === deviceId);

  if (cachedMatch) {
    return cachedMatch;
  }

  const baseUrl = session.context?.agent_base_url;

  if (!baseUrl) {
    return null;
  }

  try {
    const response = await fetchWithTimeout(
      base(baseUrl, `devices/${encodeURIComponent(deviceId)}`)
    );
    if (!response.ok) {
      return null;
    }

    return response.json();
  } catch {
    return null;
  }
}

function buildWifiAdvice(
  session: AssistantSession,
  device: Device
): ReturnType<typeof getAdvice> {
  const context = session.context;
  const adviceRequest: AdviceRequest = {
    scan_id: "assistant_context",
    device_id: device.id,
    device,
    network: {
      subnet: context?.network?.cidr || context?.network?.subnet,
      gateway_ip: context?.network?.gateway,
      local_ip: context?.network?.local_ip,
      interface_name: context?.network?.interface,
    },
    user_context: "home",
  };

  return getAdvice(adviceRequest);
}

async function toolGetSessionOverview(session: AssistantSession) {
  const context = session.context;

  if (!context) {
    return {
      status: "unavailable",
      reason: "no_context_synced",
    };
  }

  const bluetoothDevices = context.bluetooth?.devices ?? [];

  return {
    status: "ok",
    route: {
      name: context.route_name,
      params: context.route_params ?? null,
    },
    app: context.app,
    network: context.network,
    scanner: {
      connected: Boolean(context.agent_base_url),
      agent_base_url: context.agent_base_url,
      selected_wifi_device_id: getSelectedWifiDeviceId(context),
    },
    bluetooth: {
      total_devices: bluetoothDevices.length,
      named_devices: bluetoothDevices.filter((device) => device.name || device.localName)
        .length,
      unnamed_devices: bluetoothDevices.filter(
        (device) => !device.name && !device.localName
      ).length,
      category_counts: buildBluetoothCategoryCounts(bluetoothDevices),
      selected_device_id: getSelectedBluetoothDeviceId(context),
    },
  };
}

async function toolGetWifiScanSummary(
  session: AssistantSession,
  cache: ToolExecutionCache,
  args: Record<string, unknown>
) {
  const devices = await fetchWifiDevices(session, cache);

  if (!devices) {
    return {
      status: "unavailable",
      reason: session.context?.agent_base_url
        ? "scanner_unreachable"
        : "scanner_not_connected",
    };
  }

  const reviewDevices = devices.filter(deviceNeedsReview);
  const reviewOnly = args.review_only === true;
  const limit = clampLimit(args.limit, 8, 12);
  const chosenDevices = reviewOnly ? reviewDevices : devices;

  return {
    status: "ok",
    total_devices: devices.length,
    review_count: reviewDevices.length,
    devices: chosenDevices.slice(0, limit).map(summarizeWifiDevice),
  };
}

async function toolGetWifiDevice(
  session: AssistantSession,
  cache: ToolExecutionCache,
  args: Record<string, unknown>
) {
  const deviceId =
    (typeof args.device_id === "string" ? args.device_id : null) ||
    getSelectedWifiDeviceId(session.context);

  if (!deviceId) {
    return {
      status: "unavailable",
      reason: "no_selected_wifi_device",
    };
  }

  const device = await fetchWifiDevice(session, cache, deviceId);

  if (!device) {
    return {
      status: "not_found",
      device_id: deviceId,
    };
  }

  return {
    status: "ok",
    device: buildWifiDeviceDetail(device),
    deterministic_advice: buildWifiAdvice(session, device),
  };
}

async function toolGetBluetoothScanSummary(
  session: AssistantSession,
  args: Record<string, unknown>
) {
  const devices = sortBluetoothDevices(session.context?.bluetooth?.devices ?? []);
  const namedOnly = args.named_only === true;
  const limit = clampLimit(args.limit, 8, 12);
  const filteredDevices = namedOnly
    ? devices.filter((device) => device.name || device.localName)
    : devices;

  return {
    status: "ok",
    total_devices: devices.length,
    named_devices: devices.filter((device) => device.name || device.localName)
      .length,
    unnamed_devices: devices.filter((device) => !device.name && !device.localName)
      .length,
    category_counts: buildBluetoothCategoryCounts(devices),
    devices: filteredDevices.slice(0, limit).map(summarizeBluetoothDevice),
  };
}

async function toolGetBluetoothDevice(
  session: AssistantSession,
  args: Record<string, unknown>
) {
  const context = session.context;
  const requestedId =
    (typeof args.device_id === "string" ? args.device_id : null) ||
    getSelectedBluetoothDeviceId(context);

  if (!requestedId) {
    return {
      status: "unavailable",
      reason: "no_selected_bluetooth_device",
    };
  }

  const selectedDevice = context?.bluetooth?.selected_device;

  if (selectedDevice?.id === requestedId) {
    return {
      status: "ok",
      device: buildBluetoothDeviceDetail(selectedDevice),
    };
  }

  const summaryDevice = context?.bluetooth?.devices.find(
    (device) => device.id === requestedId
  );

  if (summaryDevice) {
    return {
      status: "ok",
      device: summarizeBluetoothDevice(summaryDevice),
    };
  }

  return {
    status: "not_found",
    device_id: requestedId,
  };
}

async function executeToolCall(
  session: AssistantSession,
  cache: ToolExecutionCache,
  toolName: string,
  argumentsText: string
) {
  const args = parseToolArgs(argumentsText);

  switch (toolName) {
    case "get_session_overview":
      return toolGetSessionOverview(session);
    case "get_wifi_scan_summary":
      return toolGetWifiScanSummary(session, cache, args);
    case "get_wifi_device":
      return toolGetWifiDevice(session, cache, args);
    case "get_bluetooth_scan_summary":
      return toolGetBluetoothScanSummary(session, args);
    case "get_bluetooth_device":
      return toolGetBluetoothDevice(session, args);
    default:
      return {
        status: "error",
        reason: "unknown_tool",
        tool_name: toolName,
      };
  }
}

function buildInstructions(context: AssistantContextPayload | null): string {
  return [
    "You are Astra, a calm and practical assistant inside a network and Bluetooth scanning app.",
    "Use tools to inspect current scan data instead of guessing from memory.",
    "Prefer live tool results over any earlier conversational assumption.",
    "For WiFi questions, call get_wifi_scan_summary and get_wifi_device as needed.",
    "For Bluetooth questions, call get_bluetooth_scan_summary and get_bluetooth_device as needed.",
    "If a tool says data is unavailable, explain that plainly and say what would unblock you.",
    "Be concise, grounded, and specific. Do not be alarmist.",
    "Do not mention internal tool names in the final answer.",
    `Current route: ${context?.route_name ?? "unknown"}`,
    `Selected WiFi device id: ${getSelectedWifiDeviceId(context) ?? "none"}`,
    `Selected Bluetooth device id: ${getSelectedBluetoothDeviceId(context) ?? "none"}`,
  ].join("\n");
}

function extractResponseText(data: OpenAIResponse): string | null {
  if (typeof data.output_text === "string" && data.output_text.trim()) {
    return data.output_text.trim();
  }

  const outputs = Array.isArray(data.output) ? data.output : [];

  for (const item of outputs) {
    if (item?.type !== "message" || !Array.isArray(item?.content)) {
      continue;
    }

    const text = item.content
      .filter(
        (content) =>
          content?.type === "output_text" || content?.type === "refusal"
      )
      .map((content) =>
        content?.type === "refusal"
          ? content?.refusal ?? ""
          : content?.text ?? ""
      )
      .join("")
      .trim();

    if (text) {
      return text;
    }
  }

  return null;
}

function summarizeOpenAIResponse(data: OpenAIResponse) {
  const outputs = Array.isArray(data.output) ? data.output : [];

  return {
    id: data.id ?? null,
    status: data.status ?? null,
    incomplete_reason: data.incomplete_details?.reason ?? null,
    output_types: outputs.map((item) => item?.type ?? "unknown"),
    message_content_types: outputs
      .filter((item) => item?.type === "message" && Array.isArray(item.content))
      .flatMap((item) => item.content?.map((content) => content?.type ?? "unknown") ?? []),
  };
}

function extractToolCalls(data: OpenAIResponse): ToolCall[] {
  const outputs = Array.isArray(data.output) ? data.output : [];

  return outputs
    .filter((item): item is Required<Pick<ToolCall, never>> & {
      type: string;
      call_id: string;
      name: string;
      arguments: string;
    } => item?.type === "function_call" && !!item.call_id && !!item.name)
    .map((item) => ({
      callId: item.call_id,
      name: item.name,
      argumentsText: item.arguments ?? "",
    }));
}

async function finalizeTextReply(
  apiKey: string,
  session: AssistantSession,
  previousResponseId: string
): Promise<OpenAIResponse> {
  const response = await fetch(OPENAI_API_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model: OPENAI_MODEL,
      instructions: buildInstructions(session.context),
      max_output_tokens: 900,
      store: true,
      previous_response_id: previousResponseId,
      tool_choice: "none",
      input: [
        {
          role: "user",
          content: [
            {
              type: "input_text",
              text:
                "Answer the user's last question directly in plain text now using the tool results already gathered. Do not call any more tools.",
            },
          ],
        },
      ],
    }),
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`OpenAI assistant finalize call failed: ${response.status} ${body}`);
  }

  return (await response.json()) as OpenAIResponse;
}

async function getOpenAIReply(
  req: AssistantRequest,
  session: AssistantSession
): Promise<AssistantResponse | null> {
  const apiKey = process.env.OPENAI_API_KEY;

  if (!apiKey) {
    return null;
  }

  let previousResponseId = session.lastResponseId ?? undefined;
  let nextInput: unknown[] = [
    {
      role: "user",
      content: [{ type: "input_text", text: req.message }],
    },
  ];
  const cache: ToolExecutionCache = {};

  for (let round = 0; round < 6; round += 1) {
    const response = await fetch(OPENAI_API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model: OPENAI_MODEL,
        instructions: buildInstructions(session.context),
        tools: assistantTools,
        tool_choice: "auto",
        parallel_tool_calls: false,
        max_output_tokens: 700,
        store: true,
        previous_response_id: previousResponseId,
        input: nextInput,
      }),
    });

    if (!response.ok) {
      const body = await response.text();
      throw new Error(`OpenAI assistant call failed: ${response.status} ${body}`);
    }

    const data = (await response.json()) as OpenAIResponse;
    const toolCalls = extractToolCalls(data);

    if (!toolCalls.length) {
      let reply = extractResponseText(data);

      if (!reply && data.id) {
        const finalized = await finalizeTextReply(apiKey, session, data.id);
        reply = extractResponseText(finalized);

        if (reply) {
          setAssistantSessionResponseId(
            req.session_id,
            finalized.id ?? data.id ?? previousResponseId ?? null
          );
          return {
            reply,
            suggestions: getFollowUpSuggestions(session.context?.route_name),
            mode: "ai",
            model: OPENAI_MODEL,
          };
        }

        console.warn(
          "[assistant] finalize produced no text output",
          summarizeOpenAIResponse(finalized)
        );
      }

      if (!reply) {
        console.warn(
          "[assistant] response produced no text output",
          summarizeOpenAIResponse(data)
        );
        throw new Error("OpenAI assistant call returned no text output");
      }

      setAssistantSessionResponseId(req.session_id, data.id ?? previousResponseId ?? null);
      return {
        reply,
        suggestions: getFollowUpSuggestions(session.context?.route_name),
        mode: "ai",
        model: OPENAI_MODEL,
      };
    }

    nextInput = [];
    previousResponseId = data.id ?? previousResponseId;

    for (const call of toolCalls) {
      const output = await executeToolCall(
        session,
        cache,
        call.name,
        call.argumentsText
      );
      nextInput.push({
        type: "function_call_output",
        call_id: call.callId,
        output: JSON.stringify(output),
      });
    }
  }

  throw new Error("OpenAI assistant tool loop exceeded the maximum number of rounds");
}

async function buildFallbackReply(
  session: AssistantSession
): Promise<string> {
  const context = session.context;

  if (!context) {
    return "Astra fallback mode: no live app context has been synced yet, so there is nothing grounded to answer from.";
  }

  const bluetoothDevices = context.bluetooth?.devices ?? [];
  const cache: ToolExecutionCache = {};

  switch (context.route_name) {
    case "Dashboard": {
      const wifiDevices = await fetchWifiDevices(session, cache);
      const reviewCount = (wifiDevices ?? []).filter(deviceNeedsReview).length;
      const namedBluetooth = bluetoothDevices.filter(
        (device) => device.name || device.localName
      ).length;

      return `Astra fallback mode: your dashboard currently shows ${wifiDevices?.length ?? 0} WiFi device${
        wifiDevices?.length === 1 ? "" : "s"
      }, with ${reviewCount} that likely deserve a second look. Bluetooth scan state currently has ${
        bluetoothDevices.length
      } signal${bluetoothDevices.length === 1 ? "" : "s"}, including ${namedBluetooth} named device${
        namedBluetooth === 1 ? "" : "s"
      }. Configure OPENAI_API_KEY on the server to upgrade this from grounded fallback summaries to full AI responses.`;
    }
    case "DeviceDetail": {
      const selectedId = getSelectedWifiDeviceId(context);
      const device = selectedId
        ? await fetchWifiDevice(session, cache, selectedId)
        : null;

      if (!device) {
        return "Astra fallback mode: this WiFi device is not available from the current scanner connection.";
      }

      const advice = buildWifiAdvice(session, device);
      return `Astra fallback mode: this WiFi device looks like ${device.device_type} with ${Math.round(
        device.confidence * 100
      )}% confidence. Deterministic advice summary: ${advice.summary}`;
    }
    case "BluetoothDeviceDetail": {
      const selectedId = getSelectedBluetoothDeviceId(context);
      const selectedDevice =
        (selectedId && context.bluetooth?.selected_device?.id === selectedId
          ? context.bluetooth.selected_device
          : null) ??
        context.bluetooth?.devices.find((device) => device.id === selectedId) ??
        null;

      if (!selectedDevice) {
        return "Astra fallback mode: this Bluetooth signal is not available in the current synced Bluetooth context.";
      }

      const displayName =
        selectedDevice.name || selectedDevice.localName || "this unnamed Bluetooth signal";
      const category = selectedDevice.classification?.likely_category;
      const vendor = selectedDevice.classification?.likely_vendor;
      const confidenceLabel = selectedDevice.classification?.confidenceLabel;
      const summaryBits = [
        `${displayName} was last seen with ${selectedDevice.rssi ?? "unknown"} dBm RSSI`,
        `${selectedDevice.serviceUUIDs.length} advertised service UUID${
          selectedDevice.serviceUUIDs.length === 1 ? "" : "s"
        }`,
      ];

      if (category && category !== "unknown") {
        summaryBits.push(
          `Astra's deterministic BLE layer currently leans ${category}${
            vendor && vendor !== "Unknown" ? ` from ${vendor}` : ""
          }${confidenceLabel ? ` (${confidenceLabel} confidence)` : ""}`
        );
      }

      return `Astra fallback mode: ${summaryBits.join(
        ", "
      )}. The assistant is receiving the selected signal context correctly.`;
    }
    case "Connect":
      return `Astra fallback mode: scanner connected is ${
        context.app.scanner_connected ? "on" : "off"
      } and advice server configured is ${
        context.app.advice_server_connected ? "on" : "off"
      }. Once OPENAI_API_KEY is set on the server, this assistant can answer setup questions using your live app state.`;
    default:
      return "Astra fallback mode: the assistant is receiving contextual app state, but OPENAI_API_KEY is not configured yet.";
  }
}

export function syncAssistantContext(
  req: AssistantContextSyncRequest
): { ok: true; synced_at: string } {
  syncAssistantSessionContext(req.session_id, req.context);
  return {
    ok: true,
    synced_at: new Date().toISOString(),
  };
}

export async function getAssistantReply(
  req: AssistantRequest
): Promise<AssistantResponse> {
  const session = getAssistantSession(req.session_id);

  if (!session) {
    return {
      reply:
        "Astra does not have a synced session yet. Open the assistant again after the app has synced its current screen state.",
      suggestions: getFollowUpSuggestions(undefined),
      mode: "fallback",
    };
  }

  try {
    const aiResponse = await getOpenAIReply(req, session);

    if (aiResponse) {
      return aiResponse;
    }
  } catch (error) {
    console.error("[assistant] Falling back after AI error", error);
  }

  return {
    reply: await buildFallbackReply(session),
    suggestions: getFollowUpSuggestions(session.context?.route_name),
    mode: "fallback",
  };
}
