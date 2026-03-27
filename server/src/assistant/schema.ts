import { z } from "zod";

const bluetoothClassificationSummarySchema = z.object({
  likely_category: z.string(),
  likely_vendor: z.string(),
  confidence: z.number(),
  confidenceLabel: z.enum(["high", "medium", "low"]),
  flags: z.array(
    z.enum([
      "broadcast_only",
      "connectable",
      "sparse_advertisement",
      "rotating_identifier_likely",
      "has_manufacturer_data_unparsed",
      "has_service_data_unparsed",
      "multi_role_signals",
      "health_data_context",
      "input_device_context",
      "nearby_high_rssi",
      "persistently_nearby",
    ])
  ),
  evidence: z.array(z.string()),
  uncertainty: z.array(z.string()),
  advice: z.array(z.string()),
});

const bluetoothDeviceSummarySchema = z.object({
  id: z.string(),
  name: z.string().nullable(),
  localName: z.string().nullable(),
  rssi: z.number().nullable(),
  isConnectable: z.boolean().nullable(),
  serviceUUIDs: z.array(z.string()),
  serviceDataKeys: z.array(z.string()),
  hasManufacturerData: z.boolean(),
  manufacturerCompanyId: z.number().nullable(),
  lastSeenAt: z.number(),
  classification: bluetoothClassificationSummarySchema.nullable().optional(),
});

const bluetoothDeviceDetailSchema = bluetoothDeviceSummarySchema.extend({
  txPowerLevel: z.number().nullable(),
  solicitedServiceUUIDs: z.array(z.string()),
  overflowServiceUUIDs: z.array(z.string()),
  serviceDataCount: z.number(),
  manufacturerDataHex: z.string().nullable(),
  rawScanRecordHex: z.string().nullable(),
  serviceDataHexByUuid: z.record(z.string(), z.string()),
  discoveredAt: z.number(),
});

export const assistantContextSyncRequestSchema = z.object({
  session_id: z.string().min(1),
  context: z.object({
    route_name: z.enum([
      "Connect",
      "Dashboard",
      "DeviceDetail",
      "BluetoothDeviceDetail",
      "unknown",
    ]),
    route_params: z
      .object({
        device_id: z.string().optional(),
      })
      .optional(),
    app: z.object({
      scanner_connected: z.boolean(),
      advice_server_connected: z.boolean(),
      wifi_scan_in_progress: z.boolean(),
      bluetooth_scan_in_progress: z.boolean(),
    }),
    network: z
      .object({
        hostname: z.string().optional(),
        local_ip: z.string().optional(),
        gateway: z.string().optional(),
        subnet: z.string().optional(),
        cidr: z.string().optional(),
        interface: z.string().optional(),
      })
      .nullable(),
    agent_base_url: z.string().nullable(),
    bluetooth: z
      .object({
        devices: z.array(bluetoothDeviceSummarySchema),
        selected_device: bluetoothDeviceDetailSchema.nullable().optional(),
      })
      .nullable(),
  }),
});

export const assistantRequestSchema = z.object({
  session_id: z.string().min(1),
  message: z.string().min(1),
});
