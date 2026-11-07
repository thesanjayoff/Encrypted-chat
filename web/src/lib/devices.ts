import { api } from "./api.js";

export interface DeviceInfo {
  id: string;
  label: string | null;
  is_primary: number;
  created_at: number;
  last_seen_at: number | null;
}

export async function listDevices(): Promise<DeviceInfo[]> {
  const res = await api.get<{ devices: DeviceInfo[] }>("/api/devices");
  return res.devices;
}

export async function revokeDevice(deviceId: string): Promise<void> {
  await api.del(`/api/devices/${deviceId}`);
}
