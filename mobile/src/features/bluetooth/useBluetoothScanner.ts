import { startTransition, useEffect, useRef, useState } from "react";
import { PermissionsAndroid, Platform } from "react-native";
import {
  BleError,
  BleErrorCode,
  BleManager,
  ScanMode,
  State,
  type Subscription,
} from "react-native-ble-plx";
import {
  type BluetoothPermissionStatus,
  type BluetoothScanDevice,
  upsertBluetoothDevice,
} from "./bluetoothPresentation";
import { useBluetoothStore } from "../../store/bluetoothStore";

const SCAN_WINDOW_MS = 12000;

type BluetoothScannerState = {
  bluetoothState: State | null;
  permissionStatus: BluetoothPermissionStatus;
  devices: BluetoothScanDevice[];
  isScanning: boolean;
  error: string | null;
  lastScanStartedAt: number | null;
  lastScanEndedAt: number | null;
  startScan: () => Promise<void>;
  stopScan: () => void;
  clearError: () => void;
};

function getAndroidApiLevel(): number {
  if (typeof Platform.Version === "number") {
    return Platform.Version;
  }

  const parsed = Number.parseInt(String(Platform.Version), 10);
  return Number.isNaN(parsed) ? 0 : parsed;
}

function getBleErrorMessage(error: BleError): string {
  switch (error.errorCode) {
    case BleErrorCode.BluetoothUnauthorized:
      return Platform.OS === "ios"
        ? "Bluetooth access is blocked for Astra. Enable it in iPhone Settings and try again."
        : "Bluetooth permission is required before Astra can scan nearby devices.";
    case BleErrorCode.BluetoothPoweredOff:
      return "Bluetooth is turned off. Turn it on and start the scan again.";
    case BleErrorCode.LocationServicesDisabled:
      return "Location services must be enabled on this device before BLE scanning can begin.";
    case BleErrorCode.BluetoothUnsupported:
      return "This device does not support Bluetooth Low Energy scanning.";
    case BleErrorCode.ScanStartFailed:
      return "Astra could not start the BLE scan. Try again in a moment.";
    default:
      return error.reason || error.message || "Bluetooth scanning failed.";
  }
}

export function useBluetoothScanner(): BluetoothScannerState {
  const managerRef = useRef<BleManager | null>(null);
  const stateSubscriptionRef = useRef<Subscription | null>(null);
  const scanTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  if (!managerRef.current) {
    managerRef.current = new BleManager();
  }

  const bluetoothState = useBluetoothStore((state) => state.bluetoothState);
  const permissionStatus = useBluetoothStore((state) => state.permissionStatus);
  const devices = useBluetoothStore((state) => state.devices);
  const isScanning = useBluetoothStore((state) => state.isScanning);
  const error = useBluetoothStore((state) => state.error);
  const lastScanStartedAt = useBluetoothStore((state) => state.lastScanStartedAt);
  const lastScanEndedAt = useBluetoothStore((state) => state.lastScanEndedAt);
  const setBluetoothState = useBluetoothStore((state) => state.setBluetoothState);
  const setPermissionStatus = useBluetoothStore((state) => state.setPermissionStatus);
  const setDevices = useBluetoothStore((state) => state.setDevices);
  const setIsScanning = useBluetoothStore((state) => state.setIsScanning);
  const setError = useBluetoothStore((state) => state.setError);
  const setLastScanStartedAt = useBluetoothStore((state) => state.setLastScanStartedAt);
  const setLastScanEndedAt = useBluetoothStore((state) => state.setLastScanEndedAt);

  function clearScanTimeout() {
    if (scanTimeoutRef.current) {
      clearTimeout(scanTimeoutRef.current);
      scanTimeoutRef.current = null;
    }
  }

  function stopScan(updateFinishedAt = true) {
    clearScanTimeout();
    managerRef.current?.stopDeviceScan();
    setIsScanning(false);

    if (updateFinishedAt) {
      setLastScanEndedAt(Date.now());
    }
  }

  function syncPermissionFromState(nextState: State) {
    setBluetoothState(nextState);

    if (nextState === State.Unsupported) {
      setPermissionStatus("unavailable");
      return;
    }

    if (Platform.OS === "ios") {
      if (nextState === State.Unauthorized) {
        setPermissionStatus("denied");
        return;
      }

      if (
        nextState === State.PoweredOn ||
        nextState === State.PoweredOff ||
        nextState === State.Resetting
      ) {
        setPermissionStatus("ready");
        return;
      }

      setPermissionStatus("unknown");
    }
  }

  async function refreshAndroidPermissionState() {
    if (Platform.OS !== "android") {
      return;
    }

    const apiLevel = getAndroidApiLevel();

    if (apiLevel >= 31) {
      const scanGranted = await PermissionsAndroid.check(
        PermissionsAndroid.PERMISSIONS.BLUETOOTH_SCAN
      );
      const connectGranted = await PermissionsAndroid.check(
        PermissionsAndroid.PERMISSIONS.BLUETOOTH_CONNECT
      );
      const locationGranted = await PermissionsAndroid.check(
        PermissionsAndroid.PERMISSIONS.ACCESS_FINE_LOCATION
      );

      setPermissionStatus(
        scanGranted && connectGranted && locationGranted
          ? "ready"
          : "needs-permission"
      );
      return;
    }

    const locationGranted = await PermissionsAndroid.check(
      PermissionsAndroid.PERMISSIONS.ACCESS_FINE_LOCATION
    );
    setPermissionStatus(locationGranted ? "ready" : "needs-permission");
  }

  async function requestAndroidPermissions() {
    if (Platform.OS !== "android") {
      return true;
    }

    const apiLevel = getAndroidApiLevel();

    if (apiLevel >= 31) {
      const result = await PermissionsAndroid.requestMultiple([
        PermissionsAndroid.PERMISSIONS.BLUETOOTH_SCAN,
        PermissionsAndroid.PERMISSIONS.BLUETOOTH_CONNECT,
        PermissionsAndroid.PERMISSIONS.ACCESS_FINE_LOCATION,
      ]);

      const granted =
        result[PermissionsAndroid.PERMISSIONS.BLUETOOTH_SCAN] ===
          PermissionsAndroid.RESULTS.GRANTED &&
        result[PermissionsAndroid.PERMISSIONS.BLUETOOTH_CONNECT] ===
          PermissionsAndroid.RESULTS.GRANTED &&
        result[PermissionsAndroid.PERMISSIONS.ACCESS_FINE_LOCATION] ===
          PermissionsAndroid.RESULTS.GRANTED;

      setPermissionStatus(granted ? "ready" : "needs-permission");
      return granted;
    }

    const result = await PermissionsAndroid.request(
      PermissionsAndroid.PERMISSIONS.ACCESS_FINE_LOCATION
    );
    const granted = result === PermissionsAndroid.RESULTS.GRANTED;
    setPermissionStatus(granted ? "ready" : "needs-permission");
    return granted;
  }

  async function ensureReadyToScan() {
    const manager = managerRef.current;

    if (!manager) {
      setError("Bluetooth is not ready yet. Reopen the tab and try again.");
      return false;
    }

    if (Platform.OS === "android") {
      const granted = await requestAndroidPermissions();

      if (!granted) {
        setError("Astra needs Bluetooth permission before it can scan nearby devices.");
        return false;
      }
    }

    const nextState = await manager.state();
    syncPermissionFromState(nextState);

    if (nextState === State.PoweredOn) {
      return true;
    }

    if (nextState === State.PoweredOff) {
      setError("Bluetooth is turned off. Turn it on and start the scan again.");
      return false;
    }

    if (nextState === State.Unauthorized) {
      setError("Astra does not have Bluetooth access on this device.");
      return false;
    }

    if (nextState === State.Unsupported) {
      setError("This device does not support Bluetooth Low Energy scanning.");
      return false;
    }

    setError("Bluetooth is still waking up. Give it a moment and try again.");
    return false;
  }

  async function startScan() {
    if (isScanning) {
      return;
    }

    const manager = managerRef.current;

    if (!manager) {
      setError("Bluetooth is not ready yet. Reopen the tab and try again.");
      return;
    }

    setError(null);
    const ready = await ensureReadyToScan();

    if (!ready) {
      return;
    }

    stopScan(false);
    setDevices([]);
    setIsScanning(true);
    setLastScanStartedAt(Date.now());
    setLastScanEndedAt(null);

    scanTimeoutRef.current = setTimeout(() => {
      stopScan();
    }, SCAN_WINDOW_MS);

    manager.startDeviceScan(
      null,
      {
        allowDuplicates: false,
        scanMode: ScanMode.LowLatency,
      },
      (scanError, device) => {
        if (scanError) {
          setError(getBleErrorMessage(scanError));
          stopScan();
          return;
        }

        if (!device) {
          return;
        }

        startTransition(() => {
          setDevices((current) => upsertBluetoothDevice(current, device));
        });
      }
    );
  }

  useEffect(() => {
    const manager = managerRef.current;

    if (!manager) {
      return;
    }

    let isMounted = true;

    void manager.state().then((nextState) => {
      if (!isMounted) {
        return;
      }

      syncPermissionFromState(nextState);
    });

    if (Platform.OS === "android") {
      void refreshAndroidPermissionState();
    }

    stateSubscriptionRef.current = manager.onStateChange((nextState) => {
      syncPermissionFromState(nextState);
    }, true);

    return () => {
      isMounted = false;
      stateSubscriptionRef.current?.remove();
      stateSubscriptionRef.current = null;
      stopScan(false);
      manager.destroy();
      managerRef.current = null;
    };
  }, []);

  return {
    bluetoothState,
    permissionStatus,
    devices,
    isScanning,
    error,
    lastScanStartedAt,
    lastScanEndedAt,
    startScan,
    stopScan,
    clearError: () => setError(null),
  };
}
