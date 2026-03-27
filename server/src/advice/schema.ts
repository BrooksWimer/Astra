import { z } from "zod";

const protocolsSeenSchema = z.object({
  mdns: z.array(z.string()).default([]),
  ssdp: z.array(z.string()).default([]),
  netbios: z.array(z.string()).default([]),
});

const deviceSchema = z.object({
  id: z.string(),
  ip: z.string(),
  mac: z.string(),
  vendor: z.string(),
  hostname: z.string().nullable(),
  protocols_seen: protocolsSeenSchema,
  ports_open: z.array(z.number()).optional(),
  first_seen: z.string(),
  last_seen: z.string(),
  flags: z.array(z.string()),
  confidence: z.number().min(0).max(1),
  device_type: z.enum([
    "phone",
    "laptop",
    "router",
    "printer",
    "tv",
    "speaker",
    "camera",
    "iot",
    "unknown",
  ]),
});

const networkSchema = z.object({
  subnet: z.string().optional(),
  gateway_ip: z.string().optional(),
  local_ip: z.string().optional(),
  interface_name: z.string().optional(),
});

export const adviceRequestSchema = z.object({
  scan_id: z.string(),
  device_id: z.string(),
  device: deviceSchema,
  network: networkSchema,
  user_context: z.enum(["home", "airbnb", "office", "unknown"]),
});

export type AdviceRequest = z.infer<typeof adviceRequestSchema>;
