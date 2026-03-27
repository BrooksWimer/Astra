import { create } from "zustand";
import type {
  BluetoothPermissionStatus,
  BluetoothScanDevice,
} from "../features/bluetooth/bluetoothPresentation";
import type { State } from "react-native-ble-plx";

type BluetoothStore = {
  bluetoothState: State | null;
  permissionStatus: BluetoothPermissionStatus;
  devices: BluetoothScanDevice[];
  isScanning: boolean;
  error: string | null;
  lastScanStartedAt: number | null;
  lastScanEndedAt: number | null;
  setBluetoothState: (state: State | null) => void;
  setPermissionStatus: (status: BluetoothPermissionStatus) => void;
  setDevices: (
    updater:
      | BluetoothScanDevice[]
      | ((current: BluetoothScanDevice[]) => BluetoothScanDevice[])
  ) => void;
  setIsScanning: (isScanning: boolean) => void;
  setError: (error: string | null) => void;
  setLastScanStartedAt: (timestamp: number | null) => void;
  setLastScanEndedAt: (timestamp: number | null) => void;
};

export const useBluetoothStore = create<BluetoothStore>((set) => ({
  bluetoothState: null,
  permissionStatus: "unknown",
  devices: [],
  isScanning: false,
  error: null,
  lastScanStartedAt: null,
  lastScanEndedAt: null,
  setBluetoothState: (bluetoothState) => set({ bluetoothState }),
  setPermissionStatus: (permissionStatus) => set({ permissionStatus }),
  setDevices: (updater) =>
    set((state) => ({
      devices:
        typeof updater === "function"
          ? updater(state.devices)
          : updater,
    })),
  setIsScanning: (isScanning) => set({ isScanning }),
  setError: (error) => set({ error }),
  setLastScanStartedAt: (lastScanStartedAt) => set({ lastScanStartedAt }),
  setLastScanEndedAt: (lastScanEndedAt) => set({ lastScanEndedAt }),
}));

export function getBluetoothDeviceById(
  deviceId: string
): BluetoothScanDevice | undefined {
  return useBluetoothStore
    .getState()
    .devices.find((device) => device.id === deviceId);
}
