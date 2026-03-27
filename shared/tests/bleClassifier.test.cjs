const assert = require("node:assert/strict");
const {
  classifyBleDevice,
  parseManufacturerCompanyId,
  toSig16,
} = require("../dist/index.js");

function makeObservedDevice(overrides = {}) {
  return {
    id: "ble-1",
    name: null,
    localName: null,
    rssi: -68,
    txPowerLevel: null,
    isConnectable: null,
    serviceUUIDs: [],
    solicitedServiceUUIDs: [],
    overflowServiceUUIDs: [],
    serviceDataKeys: [],
    serviceDataCount: 0,
    hasManufacturerData: false,
    manufacturerCompanyId: null,
    manufacturerDataHex: null,
    rawScanRecordHex: null,
    serviceDataHexByUuid: {},
    discoveredAt: 1,
    lastSeenAt: 1,
    ...overrides,
  };
}

const tests = [
  {
    name: "toSig16 normalizes SIG UUIDs",
    run() {
      assert.equal(toSig16("0000180D-0000-1000-8000-00805F9B34FB"), "180d");
      assert.equal(toSig16("1812"), "1812");
      assert.equal(toSig16("f000aa65-0451-4000-b000-000000000000"), null);
    },
  },
  {
    name: "parseManufacturerCompanyId reads little-endian company IDs",
    run() {
      assert.equal(parseManufacturerCompanyId("4c000215abcd"), 0x004c);
      assert.equal(parseManufacturerCompanyId(null), null);
    },
  },
  {
    name: "classifies an Eddystone beacon with Google vendor hints",
    run() {
      const result = classifyBleDevice(
        makeObservedDevice({
          serviceUUIDs: ["0000FEAA-0000-1000-8000-00805F9B34FB"],
          serviceDataKeys: ["feaa"],
          serviceDataCount: 1,
          serviceDataHexByUuid: { feaa: "00aabbcc" },
          isConnectable: false,
        })
      );

      assert.equal(result.likely_category.likely, "beacon");
      assert.equal(result.likely_vendor.likely, "Google");
      assert.ok(result.flags.includes("broadcast_only"));
      assert.ok(result.confidence >= 0.6);
    },
  },
  {
    name: "classifies an iBeacon-style advertisement as Apple beacon",
    run() {
      const manufacturerDataHex =
        "4c00021500112233445566778899aabbccddeeff00010002c5";
      const result = classifyBleDevice(
        makeObservedDevice({
          hasManufacturerData: true,
          manufacturerCompanyId: parseManufacturerCompanyId(manufacturerDataHex),
          manufacturerDataHex,
          isConnectable: false,
        })
      );

      assert.equal(result.likely_category.likely, "beacon");
      assert.equal(result.likely_vendor.likely, "Apple");
      assert.ok(result.flags.includes("broadcast_only"));
    },
  },
  {
    name: "classifies heart rate devices as wearable fitness",
    run() {
      const result = classifyBleDevice(
        makeObservedDevice({
          serviceUUIDs: ["180D"],
          isConnectable: true,
        })
      );

      assert.equal(result.likely_category.likely, "wearable_fitness");
      assert.equal(result.confidenceLabel, "high");
    },
  },
  {
    name: "classifies HID devices as input devices and sets the input flag",
    run() {
      const result = classifyBleDevice(
        makeObservedDevice({
          serviceUUIDs: ["1812"],
          isConnectable: true,
          name: "Keyboard 87",
        })
      );

      assert.equal(result.likely_category.likely, "input_device");
      assert.ok(result.flags.includes("input_device_context"));
    },
  },
  {
    name: "classifies mesh services as smart home mesh",
    run() {
      const result = classifyBleDevice(
        makeObservedDevice({
          serviceUUIDs: ["1828"],
        })
      );

      assert.equal(result.likely_category.likely, "smart_home_mesh");
    },
  },
  {
    name: "classifies Tile-like advertisements conservatively as trackers",
    run() {
      const result = classifyBleDevice(
        makeObservedDevice({
          serviceUUIDs: ["FD84"],
          name: "Tile Slim",
        })
      );

      assert.equal(result.likely_category.likely, "tag_or_tracker");
      assert.equal(result.likely_vendor.likely, "Tile");
      assert.ok(result.advice.some((entry) => entry.id === "tracker-context"));
    },
  },
  {
    name: "keeps sparse anonymous advertisements as unknown",
    run() {
      const result = classifyBleDevice(makeObservedDevice());

      assert.equal(result.likely_category.likely, "unknown");
      assert.ok(result.flags.includes("sparse_advertisement"));
      assert.equal(result.confidenceLabel, "low");
    },
  },
  {
    name: "caps weak name-only matches at low confidence",
    run() {
      const result = classifyBleDevice(
        makeObservedDevice({
          name: "AirPods",
        })
      );

      assert.equal(result.likely_vendor.likely, "Apple");
      assert.equal(result.likely_category.likely, "audio_device");
      assert.ok(result.confidence <= 0.4);
    },
  },
  {
    name: "adds penalties when manufacturer and service data exist without bytes",
    run() {
      const result = classifyBleDevice(
        makeObservedDevice({
          name: "Unknown Peripheral",
          hasManufacturerData: true,
          serviceDataCount: 1,
          serviceDataKeys: ["180d"],
        })
      );

      assert.ok(result.flags.includes("has_manufacturer_data_unparsed"));
      assert.ok(result.flags.includes("has_service_data_unparsed"));
      assert.ok(
        result.uncertainty.some((entry) => entry.includes("Manufacturer data"))
      );
    },
  },
  {
    name: "falls back to unknown when strong category signals conflict",
    run() {
      const result = classifyBleDevice(
        makeObservedDevice({
          serviceUUIDs: ["180D", "1812"],
          isConnectable: true,
        })
      );

      assert.equal(result.likely_category.likely, "unknown");
      assert.ok(result.flags.includes("multi_role_signals"));
    },
  },
];

let failures = 0;

for (const entry of tests) {
  try {
    entry.run();
    console.log(`PASS ${entry.name}`);
  } catch (error) {
    failures += 1;
    console.error(`FAIL ${entry.name}`);
    console.error(error);
  }
}

if (failures > 0) {
  process.exitCode = 1;
} else {
  console.log(`PASS ${tests.length} classifier checks`);
}
