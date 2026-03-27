import type {
  BleAdvice,
  BleCandidateScore,
  BleCategoryId,
  BleConfidenceLabel,
  BleDeterministicFlag,
  BleDeviceClassification,
  BleDimensionResult,
  BleEvidence,
  BleObservedDevice,
} from "./types";

type CategoryHint = {
  category: BleCategoryId;
  points: number;
  note: string;
};

type VendorHint = {
  vendor: string;
  points: number;
  note: string;
};

type TokenRule = {
  id: string;
  dimension: "vendor" | "category";
  value: string;
  tokensAny: string[];
  points: number;
};

const UNKNOWN_VENDOR = "Unknown";
const UNKNOWN_CATEGORY: BleCategoryId = "unknown";
const LOW_CONFIDENCE_CAP = 0.4;

const SIG_ADOPTED_SERVICE_HINTS: Record<string, CategoryHint> = {
  "1812": {
    category: "input_device",
    points: 80,
    note: "Human Interface Device Service",
  },
  "1827": {
    category: "smart_home_mesh",
    points: 85,
    note: "Mesh Provisioning Service",
  },
  "1828": {
    category: "smart_home_mesh",
    points: 85,
    note: "Mesh Proxy Service",
  },
  "1859": {
    category: "smart_home_mesh",
    points: 70,
    note: "Mesh Proxy Solicitation Service",
  },
  "1808": {
    category: "medical_device",
    points: 85,
    note: "Glucose Service",
  },
  "1810": {
    category: "medical_device",
    points: 80,
    note: "Blood Pressure Service",
  },
  "1809": {
    category: "medical_device",
    points: 70,
    note: "Health Thermometer Service",
  },
  "183a": {
    category: "medical_device",
    points: 90,
    note: "Insulin Delivery Service",
  },
  "1822": {
    category: "medical_device",
    points: 80,
    note: "Pulse Oximeter Service",
  },
  "180d": {
    category: "wearable_fitness",
    points: 80,
    note: "Heart Rate Service",
  },
  "1814": {
    category: "wearable_fitness",
    points: 60,
    note: "Running Speed and Cadence Service",
  },
  "1816": {
    category: "wearable_fitness",
    points: 60,
    note: "Cycling Speed and Cadence Service",
  },
  "1826": {
    category: "wearable_fitness",
    points: 70,
    note: "Fitness Machine Service",
  },
  "1854": {
    category: "hearing_assist",
    points: 90,
    note: "Hearing Access Service",
  },
  "184e": {
    category: "audio_device",
    points: 75,
    note: "Audio Stream Control Service",
  },
  "1844": {
    category: "audio_device",
    points: 65,
    note: "Volume Control Service",
  },
  "1850": {
    category: "audio_device",
    points: 65,
    note: "Published Audio Capabilities Service",
  },
  "181a": {
    category: "smart_home_sensor",
    points: 35,
    note: "Environmental Sensing Service",
  },
  "1819": {
    category: "smart_home_sensor",
    points: 25,
    note: "Location and Navigation Service",
  },
};

const SIG_MEMBER_UUID_VENDOR_HINTS: Record<string, VendorHint> = {
  feaa: {
    vendor: "Google",
    points: 65,
    note: "Member UUID 0xFEAA assigned to Google; used by Eddystone",
  },
  fd84: {
    vendor: "Tile",
    points: 60,
    note: "Member UUID 0xFD84 assigned to Tile",
  },
  fe33: {
    vendor: "CHIPOLO",
    points: 55,
    note: "Member UUID 0xFE33 assigned to CHIPOLO",
  },
  fe96: {
    vendor: "Tesla",
    points: 60,
    note: "Member UUID 0xFE96 assigned to Tesla",
  },
  fe97: {
    vendor: "Tesla",
    points: 60,
    note: "Member UUID 0xFE97 assigned to Tesla",
  },
  fe47: {
    vendor: "General Motors",
    points: 60,
    note: "Member UUID 0xFE47 assigned to General Motors",
  },
  fe4c: {
    vendor: "Volkswagen",
    points: 60,
    note: "Member UUID 0xFE4C assigned to Volkswagen",
  },
};

const SIG_MEMBER_UUID_CATEGORY_HINTS: Record<string, CategoryHint> = {
  feaa: {
    category: "beacon",
    points: 70,
    note: "Google member UUID 0xFEAA is commonly used for Eddystone beacons",
  },
  fd84: {
    category: "tag_or_tracker",
    points: 65,
    note: "Tile member UUID indicates an item-finding or tracker context",
  },
  fe33: {
    category: "tag_or_tracker",
    points: 60,
    note: "CHIPOLO member UUID indicates an item-finding or tracker context",
  },
  fe96: {
    category: "vehicle_system",
    points: 60,
    note: "Tesla member UUID suggests an automotive device context",
  },
  fe97: {
    category: "vehicle_system",
    points: 60,
    note: "Tesla member UUID suggests an automotive device context",
  },
  fe47: {
    category: "vehicle_system",
    points: 60,
    note: "General Motors member UUID suggests an automotive device context",
  },
  fe4c: {
    category: "vehicle_system",
    points: 60,
    note: "Volkswagen member UUID suggests an automotive device context",
  },
};

const COMPANY_ID_HINTS: Record<number, { vendor: string; points: number }> = {
  0x004c: { vendor: "Apple", points: 80 },
  0x0006: { vendor: "Microsoft", points: 70 },
  0x000d: { vendor: "Texas Instruments", points: 55 },
};

const NAME_TOKEN_RULES: TokenRule[] = [
  {
    id: "name:vendor:apple_airpods",
    dimension: "vendor",
    value: "Apple",
    tokensAny: ["airpods", "iphone", "ipad", "macbook", "watch"],
    points: 20,
  },
  {
    id: "name:cat:computer_or_phone",
    dimension: "category",
    value: "computer_or_phone",
    tokensAny: ["iphone", "ipad", "macbook", "pixel", "galaxy", "phone", "laptop"],
    points: 15,
  },
  {
    id: "name:cat:audio",
    dimension: "category",
    value: "audio_device",
    tokensAny: ["airpods", "earbuds", "headphones", "speaker", "beats", "bose", "sonos"],
    points: 15,
  },
  {
    id: "name:vendor:tile",
    dimension: "vendor",
    value: "Tile",
    tokensAny: ["tile"],
    points: 20,
  },
  {
    id: "name:vendor:chipolo",
    dimension: "vendor",
    value: "CHIPOLO",
    tokensAny: ["chipolo"],
    points: 20,
  },
  {
    id: "name:cat:tracker",
    dimension: "category",
    value: "tag_or_tracker",
    tokensAny: ["tile", "chipolo", "tracker", "tag"],
    points: 15,
  },
  {
    id: "name:vendor:tesla",
    dimension: "vendor",
    value: "Tesla",
    tokensAny: ["tesla"],
    points: 20,
  },
  {
    id: "name:cat:vehicle",
    dimension: "category",
    value: "vehicle_system",
    tokensAny: ["tesla", "bmw", "vw", "volkswagen"],
    points: 15,
  },
  {
    id: "name:cat:wearable",
    dimension: "category",
    value: "wearable_fitness",
    tokensAny: ["fitbit", "garmin", "oura", "watch"],
    points: 15,
  },
  {
    id: "name:cat:input",
    dimension: "category",
    value: "input_device",
    tokensAny: ["keyboard", "mouse", "trackpad", "stylus"],
    points: 15,
  },
  {
    id: "name:cat:sensor",
    dimension: "category",
    value: "smart_home_sensor",
    tokensAny: ["sensor", "hue", "nest"],
    points: 15,
  },
];

export function normalizeBleUuid(uuid: string): string {
  return uuid.trim().toLowerCase();
}

export function toSig16(uuid: string): string | null {
  const normalized = normalizeBleUuid(uuid);

  if (/^[0-9a-f]{4}$/.test(normalized)) {
    return normalized;
  }

  const match = normalized.match(
    /^0000([0-9a-f]{4})-0000-1000-8000-00805f9b34fb$/
  );
  return match ? match[1] : null;
}

export function normalizeBleNameKey(name?: string | null): string {
  return (name ?? "").trim().toLowerCase();
}

export function parseManufacturerCompanyId(
  manufacturerDataHex: string | null | undefined
): number | null {
  if (!manufacturerDataHex || manufacturerDataHex.length < 4) {
    return null;
  }

  const lower = manufacturerDataHex.toLowerCase();
  const byte0 = Number.parseInt(lower.slice(0, 2), 16);
  const byte1 = Number.parseInt(lower.slice(2, 4), 16);

  if (Number.isNaN(byte0) || Number.isNaN(byte1)) {
    return null;
  }

  return byte0 | (byte1 << 8);
}

function clamp01(value: number): number {
  return Math.max(0, Math.min(1, value));
}

export function getBleConfidenceLabel(confidence: number): BleConfidenceLabel {
  if (confidence >= 0.75) {
    return "high";
  }

  if (confidence >= 0.45) {
    return "medium";
  }

  return "low";
}

export function computeConfidence(
  topPoints: number,
  secondPoints: number,
  sparsityPenalty: number,
  conflictPenalty: number
): number {
  const base = clamp01(topPoints / 100);
  const margin = clamp01((topPoints - secondPoints) / 30);
  const marginFactor = 0.4 + 0.6 * margin;
  return clamp01(
    base * marginFactor * (1 - sparsityPenalty) * (1 - conflictPenalty)
  );
}

function normalizeUuidList(values: string[] | null | undefined): string[] {
  return [...new Set((values ?? []).map(normalizeBleUuid).filter(Boolean))];
}

function tokenizeName(value: string): string[] {
  return value
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

function hasUuid16(list: string[] | null | undefined, uuid16: string): boolean {
  const target = uuid16.toLowerCase();
  return (list ?? []).some((value) => toSig16(value) === target);
}

function getServiceDataHexBySig16(
  serviceDataHexByUuid: Record<string, string>,
  uuid16: string
): string | null {
  const target = uuid16.toLowerCase();

  for (const [uuid, value] of Object.entries(serviceDataHexByUuid)) {
    if (toSig16(uuid) === target) {
      return value.toLowerCase();
    }
  }

  return null;
}

function ruleEddystone(input: BleObservedDevice): BleEvidence[] {
  const evidence: BleEvidence[] = [];
  const hasFeaa = hasUuid16(input.serviceUUIDs, "feaa");
  const hasFeaaServiceData = hasUuid16(input.serviceDataKeys, "feaa");

  if (!hasFeaa && !hasFeaaServiceData) {
    return evidence;
  }

  evidence.push({
    ruleId: "proto:eddystone:feaa",
    strength: "strong",
    dimension: "category",
    candidateId: "beacon",
    claim: "Likely Eddystone beacon (service UUID 0xFEAA present).",
    points: 85,
    dataUsed: {
      serviceUUIDs: input.serviceUUIDs,
      serviceDataKeys: input.serviceDataKeys,
    },
    sourceFamily: "eddystone",
  });

  const serviceData = getServiceDataHexBySig16(input.serviceDataHexByUuid, "feaa");
  if (serviceData && serviceData.length >= 2) {
    const firstByte = Number.parseInt(serviceData.slice(0, 2), 16);
    if (!Number.isNaN(firstByte)) {
      evidence.push({
        ruleId: "proto:eddystone:frame_type",
        strength: "medium",
        dimension: "flag",
        claim: `Eddystone frame type nibble detected: ${(
          (firstByte & 0xf0) >>
          4
        ).toString(16)}.`,
        points: 10,
        dataUsed: { serviceDataHexPrefix: serviceData.slice(0, 4) },
        sourceFamily: "eddystone",
      });
    }
  }

  if (input.isConnectable === false) {
    evidence.push({
      ruleId: "heur:beacon:non_connectable",
      strength: "medium",
      dimension: "flag",
      claim: "Broadcast-only behavior aligns with common beacon advertising.",
      points: 20,
      dataUsed: { isConnectable: input.isConnectable },
      sourceFamily: "connectability_heuristic",
    });
  }

  return evidence;
}

function ruleIBeacon(input: BleObservedDevice): BleEvidence[] {
  const evidence: BleEvidence[] = [];
  const manufacturerData = (input.manufacturerDataHex ?? "").toLowerCase();
  const matchesAppleCompany = input.manufacturerCompanyId === 0x004c;
  const matchesPrefix = manufacturerData.startsWith("4c000215");

  if (!matchesAppleCompany || !matchesPrefix) {
    return evidence;
  }

  evidence.push({
    ruleId: "proto:ibeacon:apple_4c_0215",
    strength: "strong",
    dimension: "category",
    candidateId: "beacon",
    claim: "Likely Apple iBeacon / Proximity Beacon frame detected.",
    points: 90,
    dataUsed: {
      manufacturerCompanyId: input.manufacturerCompanyId,
      manufacturerDataPrefix: manufacturerData.slice(0, 8),
    },
    sourceFamily: "ibeacon",
  });

  if (input.isConnectable === false) {
    evidence.push({
      ruleId: "proto:ibeacon:non_connectable_expected",
      strength: "medium",
      dimension: "flag",
      claim: "Non-connectable advertising aligns with the expected iBeacon pattern.",
      points: 15,
      dataUsed: { isConnectable: input.isConnectable },
      sourceFamily: "ibeacon",
    });
  }

  return evidence;
}

function ruleSigServices(input: BleObservedDevice): BleEvidence[] {
  const allUuids = [
    ...normalizeUuidList(input.serviceUUIDs),
    ...normalizeUuidList(input.solicitedServiceUUIDs),
    ...normalizeUuidList(input.overflowServiceUUIDs),
    ...normalizeUuidList(input.serviceDataKeys),
  ];

  const evidence: BleEvidence[] = [];
  for (const uuid of allUuids) {
    const uuid16 = toSig16(uuid);
    if (!uuid16) {
      continue;
    }

    const hint = SIG_ADOPTED_SERVICE_HINTS[uuid16];
    if (!hint) {
      continue;
    }

    evidence.push({
      ruleId: `sig:gatt_service:${uuid16}`,
      strength:
        hint.points >= 75 ? "strong" : hint.points >= 50 ? "medium" : "weak",
      dimension: "category",
      candidateId: hint.category,
      claim: `Adopted service indicates category: ${hint.note}.`,
      points: hint.points,
      dataUsed: { matchedUuid: uuid, sig16: uuid16 },
      sourceFamily: "sig_adopted_service",
    });
  }

  return evidence;
}

function ruleCompanyIdVendor(input: BleObservedDevice): BleEvidence[] {
  const companyId = input.manufacturerCompanyId;
  if (companyId == null) {
    return [];
  }

  const hint = COMPANY_ID_HINTS[companyId];
  if (!hint) {
    return [];
  }

  return [
    {
      ruleId: `sig:company_id:${companyId.toString(16)}`,
      strength: "strong",
      dimension: "vendor",
      candidateId: hint.vendor,
      claim: `Manufacturer Company ID suggests vendor: ${hint.vendor}.`,
      points: hint.points,
      dataUsed: { manufacturerCompanyId: companyId },
      sourceFamily: "company_identifier",
    },
  ];
}

function ruleMemberUuidVendor(input: BleObservedDevice): BleEvidence[] {
  const allUuids = [
    ...normalizeUuidList(input.serviceUUIDs),
    ...normalizeUuidList(input.serviceDataKeys),
    ...normalizeUuidList(input.solicitedServiceUUIDs),
  ];

  const evidence: BleEvidence[] = [];
  for (const uuid of allUuids) {
    const uuid16 = toSig16(uuid);
    if (!uuid16) {
      continue;
    }

    const hint = SIG_MEMBER_UUID_VENDOR_HINTS[uuid16];
    if (!hint) {
      continue;
    }

    evidence.push({
      ruleId: `sig:member_uuid:${uuid16}`,
      strength: "medium",
      dimension: "vendor",
      candidateId: hint.vendor,
      claim: `Member UUID suggests vendor: ${hint.vendor}.`,
      points: hint.points,
      dataUsed: { matchedUuid: uuid, sig16: uuid16, note: hint.note },
      sourceFamily: "sig_member_uuid",
    });
  }

  return evidence;
}

function ruleMemberUuidCategory(input: BleObservedDevice): BleEvidence[] {
  const allUuids = [
    ...normalizeUuidList(input.serviceUUIDs),
    ...normalizeUuidList(input.serviceDataKeys),
    ...normalizeUuidList(input.solicitedServiceUUIDs),
  ];

  const evidence: BleEvidence[] = [];
  for (const uuid of allUuids) {
    const uuid16 = toSig16(uuid);
    if (!uuid16) {
      continue;
    }

    const hint = SIG_MEMBER_UUID_CATEGORY_HINTS[uuid16];
    if (!hint) {
      continue;
    }

    evidence.push({
      ruleId: `sig:member_uuid_category:${uuid16}`,
      strength: "medium",
      dimension: "category",
      candidateId: hint.category,
      claim: hint.note,
      points: hint.points,
      dataUsed: { matchedUuid: uuid, sig16: uuid16 },
      sourceFamily: "sig_member_uuid",
    });
  }

  return evidence;
}

function ruleNameTokens(input: BleObservedDevice): BleEvidence[] {
  const name = normalizeBleNameKey(input.localName || input.name);
  if (!name) {
    return [];
  }

  const tokens = new Set(tokenizeName(name));
  const evidence: BleEvidence[] = [];

  for (const rule of NAME_TOKEN_RULES) {
    const matchedTokens = rule.tokensAny.filter((token) => tokens.has(token));
    if (!matchedTokens.length) {
      continue;
    }

    evidence.push({
      ruleId: rule.id,
      strength: "weak",
      dimension: rule.dimension,
      candidateId: rule.value,
      claim: `Name token match suggests ${rule.dimension}: ${rule.value}.`,
      points: rule.points,
      dataUsed: {
        name: input.localName || input.name,
        matchedTokens,
      },
      sourceFamily: "name_heuristic",
    });
  }

  return evidence;
}

function getSparsityPenalty(input: BleObservedDevice): number {
  let penalty = 0;

  if (input.hasManufacturerData && !input.manufacturerDataHex) {
    penalty += 0.2;
  }

  if (input.serviceDataCount > 0 && !Object.keys(input.serviceDataHexByUuid).length) {
    penalty += 0.15;
  }

  if (
    !input.name &&
    !input.localName &&
    input.serviceUUIDs.length === 0 &&
    input.serviceDataKeys.length === 0
  ) {
    penalty += 0.1;
  }

  return Math.min(penalty, 0.4);
}

function getConflictPenalty(
  evidence: BleEvidence[],
  topPoints: number,
  secondPoints: number
): number {
  const strongCandidates = new Set(
    evidence
      .filter(
        (entry) =>
          entry.dimension !== "flag" &&
          entry.strength === "strong" &&
          entry.candidateId
      )
      .map((entry) => entry.candidateId as string)
  );

  let penalty = strongCandidates.size > 1 ? 0.25 : 0;

  if (topPoints > 0 && secondPoints > 0 && topPoints - secondPoints <= 10) {
    penalty += 0.1;
  }

  return Math.min(penalty, 0.3);
}

function aggregateCandidates(
  evidence: BleEvidence[],
  dimension: "vendor" | "category"
): BleCandidateScore[] {
  const totals = new Map<string, number>();

  for (const entry of evidence) {
    if (entry.dimension !== dimension || !entry.candidateId) {
      continue;
    }

    totals.set(entry.candidateId, (totals.get(entry.candidateId) ?? 0) + entry.points);
  }

  return [...totals.entries()]
    .map(([id, points]) => ({ id, points }))
    .sort((left, right) => right.points - left.points);
}

function buildDimensionUncertainty(
  input: BleObservedDevice,
  dimension: "vendor" | "category",
  likely: string,
  candidates: BleCandidateScore[],
  confidence: number
): string[] {
  const uncertainty: string[] = [];

  if (!candidates.length) {
    uncertainty.push(
      dimension === "vendor"
        ? "No strong vendor-specific evidence was present."
        : "No strong category-specific evidence was present."
    );
  }

  if (
    candidates.length > 1 &&
    candidates[0] &&
    candidates[1] &&
    candidates[0].points - candidates[1].points <= 10
  ) {
    uncertainty.push(
      dimension === "vendor"
        ? "Multiple vendor candidates are close, so Astra is keeping confidence capped."
        : "Multiple category candidates are close, so Astra is keeping confidence capped."
    );
  }

  if (confidence < 0.3) {
    uncertainty.push(
      dimension === "vendor"
        ? "Vendor confidence is low because the advertisement does not expose enough deterministic vendor data."
        : "Category confidence is low because the advertisement does not expose enough deterministic category data."
    );
  }

  if (
    dimension === "vendor" &&
    input.manufacturerCompanyId != null &&
    !COMPANY_ID_HINTS[input.manufacturerCompanyId] &&
    likely === UNKNOWN_VENDOR
  ) {
    uncertainty.push(
      `A manufacturer company ID was present (${input.manufacturerCompanyId}), but Astra's local vendor mapping does not include it yet.`
    );
  }

  return [...new Set(uncertainty)];
}

function evaluateDimension(
  input: BleObservedDevice,
  evidence: BleEvidence[],
  dimension: "vendor" | "category"
): BleDimensionResult {
  const candidates = aggregateCandidates(evidence, dimension);
  const top = candidates[0];
  const second = candidates[1];
  const sparsityPenalty = getSparsityPenalty(input);
  const conflictPenalty = getConflictPenalty(
    evidence.filter((entry) => entry.dimension === dimension),
    top?.points ?? 0,
    second?.points ?? 0
  );

  let likely = dimension === "vendor" ? UNKNOWN_VENDOR : UNKNOWN_CATEGORY;
  let confidence = 0;

  if (top) {
    likely = top.id;
    confidence = computeConfidence(
      top.points,
      second?.points ?? 0,
      sparsityPenalty,
      conflictPenalty
    );

    const strongestEvidence = evidence.filter(
      (entry) =>
        entry.dimension === dimension &&
        entry.candidateId &&
        entry.candidateId !== top.id &&
        entry.strength === "strong"
    );

    if (strongestEvidence.length > 0 && conflictPenalty >= 0.25) {
      likely = dimension === "vendor" ? UNKNOWN_VENDOR : UNKNOWN_CATEGORY;
      confidence = Math.min(confidence, 0.25);
    }

    if (
      evidence.every((entry) => entry.dimension !== dimension || entry.strength === "weak")
    ) {
      confidence = Math.min(confidence, LOW_CONFIDENCE_CAP);
    }
  }

  const filteredEvidence =
    likely === UNKNOWN_VENDOR || likely === UNKNOWN_CATEGORY
      ? evidence.filter((entry) => entry.dimension === dimension).slice(0, 6)
      : evidence.filter(
          (entry) =>
            entry.dimension === dimension &&
            entry.candidateId &&
            entry.candidateId === likely
        );

  const uncertainty = buildDimensionUncertainty(
    input,
    dimension,
    likely,
    candidates,
    confidence
  );

  return {
    likely,
    confidence,
    confidenceLabel: getBleConfidenceLabel(confidence),
    candidates,
    evidence: filteredEvidence.sort((left, right) => right.points - left.points),
    uncertainty,
  };
}

function buildFlags(
  input: BleObservedDevice,
  categoryResult: BleDimensionResult
): BleDeterministicFlag[] {
  const flags = new Set<BleDeterministicFlag>();

  if (input.isConnectable === false) {
    flags.add("broadcast_only");
  }

  if (input.isConnectable === true) {
    flags.add("connectable");
  }

  if (
    !input.name &&
    !input.localName &&
    input.serviceUUIDs.length === 0 &&
    input.serviceDataKeys.length === 0 &&
    !input.hasManufacturerData
  ) {
    flags.add("sparse_advertisement");
  }

  if (input.hasManufacturerData && !input.manufacturerDataHex) {
    flags.add("has_manufacturer_data_unparsed");
  }

  if (input.serviceDataCount > 0 && !Object.keys(input.serviceDataHexByUuid).length) {
    flags.add("has_service_data_unparsed");
  }

  if (input.rssi != null && input.rssi >= -60) {
    flags.add("nearby_high_rssi");
  }

  if (categoryResult.likely === "medical_device") {
    flags.add("health_data_context");
  }

  if (categoryResult.likely === "input_device") {
    flags.add("input_device_context");
  }

  if (
    categoryResult.candidates[0] &&
    categoryResult.candidates[1] &&
    categoryResult.candidates[0].points - categoryResult.candidates[1].points <= 10
  ) {
    flags.add("multi_role_signals");
  }

  return [...flags];
}

function buildAdvice(
  categoryResult: BleDimensionResult,
  flags: BleDeterministicFlag[]
): BleAdvice[] {
  const advice: BleAdvice[] = [];

  if (
    categoryResult.likely === UNKNOWN_CATEGORY &&
    flags.includes("connectable")
  ) {
    advice.push({
      id: "unknown-connectable",
      title: "Treat unknown connectable devices cautiously",
      text: "If you do not recognize this device, avoid pairing or connecting to it directly. Prefer pairing through your phone or computer's Bluetooth settings when you trust the device.",
      severity: "attention",
      relatedFlags: ["connectable"],
    });
  }

  if (categoryResult.likely === "beacon") {
    advice.push({
      id: "beacon-context",
      title: "Beacon-style broadcast detected",
      text: "This looks like a beacon broadcasting identifiers for location or automation. If you expected nearby infrastructure, that is usually normal.",
      severity: "info",
      relatedFlags: ["broadcast_only"],
    });
  }

  if (categoryResult.likely === "medical_device") {
    advice.push({
      id: "medical-context",
      title: "Health-related BLE service",
      text: "This advertisement includes medical or health-service signals. Only connect if you trust it, because it may expose sensitive measurements.",
      severity: "attention",
      relatedFlags: ["health_data_context"],
    });
  }

  if (categoryResult.likely === "tag_or_tracker") {
    advice.push({
      id: "tracker-context",
      title: "Possible item-finding tag",
      text: "This signal matches patterns commonly used for item-finding devices. That does not prove unwanted tracking, but it is worth checking whether you recognize it.",
      severity: "info",
      relatedFlags: [],
    });
  }

  if (flags.includes("sparse_advertisement")) {
    advice.push({
      id: "sparse-advertisement",
      title: "Very little advertisement data",
      text: "This device is advertising very little, so Astra is staying conservative. A future scan may reveal more if the device changes what it broadcasts.",
      severity: "info",
      relatedFlags: ["sparse_advertisement"],
    });
  }

  if (
    flags.includes("has_manufacturer_data_unparsed") ||
    flags.includes("has_service_data_unparsed")
  ) {
    advice.push({
      id: "richer-bytes-needed",
      title: "More raw advertisement bytes would improve labeling",
      text: "Astra detected richer manufacturer or service data but could not fully use it yet. Capturing those payloads helps vendor and beacon detection significantly.",
      severity: "info",
      relatedFlags: flags.filter(
        (flag) =>
          flag === "has_manufacturer_data_unparsed" ||
          flag === "has_service_data_unparsed"
      ) as BleDeterministicFlag[],
    });
  }

  if (flags.includes("multi_role_signals")) {
    advice.push({
      id: "multi-role",
      title: "Multiple plausible interpretations",
      text: "The advertisement contains signals that point in more than one direction, so Astra is intentionally keeping confidence conservative.",
      severity: "info",
      relatedFlags: ["multi_role_signals"],
    });
  }

  return advice;
}

function buildGlobalUncertainty(
  input: BleObservedDevice,
  categoryResult: BleDimensionResult,
  vendorResult: BleDimensionResult,
  flags: BleDeterministicFlag[]
): string[] {
  const uncertainty = new Set<string>([
    ...categoryResult.uncertainty,
    ...vendorResult.uncertainty,
  ]);

  if (flags.includes("has_manufacturer_data_unparsed")) {
    uncertainty.add(
      "Manufacturer data exists, but Astra could not fully parse the bytes."
    );
  }

  if (flags.includes("has_service_data_unparsed")) {
    uncertainty.add(
      "Service data exists, but Astra did not capture enough payload bytes to decode protocol details."
    );
  }

  if (flags.includes("sparse_advertisement")) {
    uncertainty.add(
      "This advertisement is sparse, so Astra is staying conservative."
    );
  }

  if (
    input.manufacturerCompanyId != null &&
    !COMPANY_ID_HINTS[input.manufacturerCompanyId]
  ) {
    uncertainty.add(
      `Manufacturer company ID ${input.manufacturerCompanyId} is present, but it is not yet in Astra's local vendor map.`
    );
  }

  return [...uncertainty];
}

export function classifyBleDevice(input: BleObservedDevice): BleDeviceClassification {
  const normalizedInput: BleObservedDevice = {
    ...input,
    serviceUUIDs: normalizeUuidList(input.serviceUUIDs),
    solicitedServiceUUIDs: normalizeUuidList(input.solicitedServiceUUIDs),
    overflowServiceUUIDs: normalizeUuidList(input.overflowServiceUUIDs),
    serviceDataKeys: normalizeUuidList(input.serviceDataKeys),
    serviceDataHexByUuid: Object.fromEntries(
      Object.entries(input.serviceDataHexByUuid).map(([uuid, value]) => [
        normalizeBleUuid(uuid),
        value.toLowerCase(),
      ])
    ),
    manufacturerDataHex: input.manufacturerDataHex?.toLowerCase() ?? null,
    rawScanRecordHex: input.rawScanRecordHex?.toLowerCase() ?? null,
    manufacturerCompanyId:
      input.manufacturerCompanyId ??
      parseManufacturerCompanyId(input.manufacturerDataHex),
  };

  const evidence = [
    ...ruleIBeacon(normalizedInput),
    ...ruleEddystone(normalizedInput),
    ...ruleSigServices(normalizedInput),
    ...ruleCompanyIdVendor(normalizedInput),
    ...ruleMemberUuidVendor(normalizedInput),
    ...ruleMemberUuidCategory(normalizedInput),
    ...ruleNameTokens(normalizedInput),
  ];

  const likely_category = evaluateDimension(normalizedInput, evidence, "category");
  const likely_vendor = evaluateDimension(normalizedInput, evidence, "vendor");
  const flags = buildFlags(normalizedInput, likely_category);
  const uncertainty = buildGlobalUncertainty(
    normalizedInput,
    likely_category,
    likely_vendor,
    flags
  );
  const advice = buildAdvice(likely_category, flags);
  const relevantEvidence = [
    ...likely_category.evidence,
    ...likely_vendor.evidence,
  ].sort((left, right) => right.points - left.points);

  return {
    likely_vendor,
    likely_category,
    confidence: likely_category.confidence,
    confidenceLabel: likely_category.confidenceLabel,
    evidence: relevantEvidence,
    uncertainty,
    flags,
    advice,
  };
}
