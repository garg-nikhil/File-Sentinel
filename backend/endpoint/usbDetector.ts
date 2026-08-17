/**
 * FILE-SENTINEL — Phase A: Endpoint Compliance Detection Engine
 * USB Storage Detector with Platform Abstraction & Device Inventory
 *
 * STRICTLY DETECTION ONLY:
 * - NO registry modifications
 * - NO policy changes
 * - NO USB enabling / disabling
 * - NO personal document inspection
 * - NO file name or volume label harvesting
 */

import os from 'node:os';
import { exec } from 'node:child_process';
import { promisify } from 'node:util';
import {
  USBDetectionResult,
  USBDetectorResult,
  USBStorageDevice,
  USBStatus,
  ConfidenceLevel,
  DetectionMethod,
  EndpointPlatform
} from './endpointTypes.js';

export type { USBDetectorResult, USBDetectionResult };

const execAsync = promisify(exec);

export interface USBDetectorConfig {
  platformOverride?: EndpointPlatform;
  mockRunner?: (cmd: string) => Promise<{ stdout: string; stderr: string }>;
  mockResult?: Partial<USBDetectionResult>;
}

export class USBDetector {
  private config: USBDetectorConfig;

  constructor(config: USBDetectorConfig = {}) {
    this.config = config;
  }

  /**
   * Determine the current OS platform
   */
  public getPlatform(): EndpointPlatform {
    if (this.config.platformOverride) {
      return this.config.platformOverride;
    }
    const current = os.platform();
    if (current === 'win32') return 'windows';
    if (current === 'linux') return 'linux';
    if (current === 'darwin') return 'darwin';
    return 'unsupported';
  }

  /**
   * Run USB Storage Compliance and Inventory Detection
   */
  public async detect(): Promise<USBDetectionResult> {
    const timestamp = new Date().toISOString();
    const platform = this.getPlatform();

    // Mock bypass for testing
    if (this.config.mockResult) {
      const devices = this.config.mockResult.connectedStorageDevices || [];
      return {
        category: 'USB_STORAGE',
        status: this.config.mockResult.status || 'ENABLED',
        connectedStorageDevices: devices,
        connectedDeviceCount: this.config.mockResult.connectedDeviceCount !== undefined
          ? this.config.mockResult.connectedDeviceCount
          : devices.length,
        detectionMethod: this.config.mockResult.detectionMethod || 'MOCK_WINDOWS_SYSTEM',
        confidence: this.config.mockResult.confidence || 'HIGH',
        timestamp,
        platform,
        policyDetails: this.config.mockResult.policyDetails,
        errorMessage: this.config.mockResult.errorMessage
      };
    }

    // Platform validation: Windows is the supported platform for Phase A
    if (platform !== 'windows') {
      return {
        category: 'USB_STORAGE',
        status: 'UNSUPPORTED_PLATFORM',
        connectedStorageDevices: [],
        connectedDeviceCount: 0,
        detectionMethod: 'UNSUPPORTED_PLATFORM',
        confidence: 'HIGH',
        timestamp,
        platform,
        errorMessage: `Endpoint compliance USB storage detection is only supported on Windows OS. Current OS: ${platform}.`
      };
    }

    // Windows detection sequence
    try {
      const policyStatus = await this.detectWindowsPolicy();
      const connectedDevices = await this.detectWindowsStorageDevices();

      return {
        category: 'USB_STORAGE',
        status: policyStatus.status,
        connectedStorageDevices: connectedDevices,
        connectedDeviceCount: connectedDevices.length,
        detectionMethod: policyStatus.detectionMethod,
        confidence: policyStatus.confidence,
        timestamp,
        platform: 'windows',
        policyDetails: policyStatus.policyDetails,
        errorMessage: policyStatus.errorMessage
      };
    } catch (err: any) {
      return {
        category: 'USB_STORAGE',
        status: 'UNKNOWN',
        connectedStorageDevices: [],
        connectedDeviceCount: 0,
        detectionMethod: 'WINDOWS_REGISTRY_QUERY',
        confidence: 'LOW',
        timestamp,
        platform: 'windows',
        errorMessage: `Failed to detect USB storage status: ${err?.message || 'Unknown error'}`
      };
    }
  }

  /**
   * Detect Windows USBSTOR Registry and Group Policy settings
   */
  private async detectWindowsPolicy(): Promise<{
    status: USBStatus;
    detectionMethod: DetectionMethod;
    confidence: ConfidenceLevel;
    policyDetails?: USBDetectionResult['policyDetails'];
    errorMessage?: string;
  }> {
    const runner = this.config.mockRunner || (async (cmd: string) => {
      return execAsync(cmd, { timeout: 4000 });
    });

    try {
      // 1. Query USBSTOR service start value:
      // 3 = Enabled (SERVICE_DEMAND_START)
      // 4 = Disabled (SERVICE_DISABLED)
      const regCmd = 'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR" /v Start';
      const { stdout } = await runner(regCmd);

      let startValue: number | undefined;
      const match = stdout.match(/Start\s+REG_DWORD\s+0x([0-9a-fA-F]+)/i);
      if (match && match[1]) {
        startValue = parseInt(match[1], 16);
      }

      // Check Group Policy / StorageDevicePolicies for write protection or Deny_All
      let writeProtect = false;
      let denyAll = false;
      let storagePolicy = 'NOT_CONFIGURED';

      // 2. Query RemovableStorageDevices policy key
      try {
        const policyCmd = 'reg query "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\RemovableStorageDevices" /s';
        const policyOut = await runner(policyCmd);
        if (/Deny_All\s+REG_DWORD\s+0x1/i.test(policyOut.stdout)) {
          denyAll = true;
          storagePolicy = 'DENY_ALL_CONFIGURED';
        }
        if (/WriteProtect\s+REG_DWORD\s+0x1/i.test(policyOut.stdout)) {
          writeProtect = true;
        }
      } catch {
        // StorageDevicePolicies key may not exist by default on unmanaged installations
      }

      // 3. Query StorageDevicePolicies Control key for write protection
      try {
        const ctlCmd = 'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\StorageDevicePolicies" /v WriteProtect';
        const ctlOut = await runner(ctlCmd);
        if (/WriteProtect\s+REG_DWORD\s+0x1/i.test(ctlOut.stdout)) {
          writeProtect = true;
          if (storagePolicy === 'NOT_CONFIGURED') {
            storagePolicy = 'WRITE_PROTECT_CONFIGURED';
          }
        }
      } catch {
        // Key may not exist
      }

      // Evaluate overall status
      if (startValue === 4 || denyAll) {
        return {
          status: 'DISABLED',
          detectionMethod: 'WINDOWS_REGISTRY_QUERY',
          confidence: 'HIGH',
          policyDetails: {
            usbstorServiceStart: startValue,
            storageDevicePolicies: storagePolicy,
            writeProtect,
            denyAll
          }
        };
      }

      if (startValue === 3) {
        return {
          status: 'ENABLED',
          detectionMethod: 'WINDOWS_REGISTRY_QUERY',
          confidence: 'HIGH',
          policyDetails: {
            usbstorServiceStart: startValue,
            storageDevicePolicies: storagePolicy,
            writeProtect,
            denyAll: false
          }
        };
      }

      return {
        status: 'UNKNOWN',
        detectionMethod: 'WINDOWS_REGISTRY_QUERY',
        confidence: 'MEDIUM',
        policyDetails: {
          usbstorServiceStart: startValue,
          storageDevicePolicies: storagePolicy
        },
        errorMessage: `Unexpected USBSTOR Start value: ${startValue}`
      };
    } catch (err: any) {
      const errMsg = err?.stderr || err?.message || '';
      if (/Access is denied|elevation/i.test(errMsg)) {
        return {
          status: 'REQUIRES_ELEVATION',
          detectionMethod: 'ELEVATION_REQUIRED',
          confidence: 'HIGH',
          errorMessage: 'Access denied querying registry policy. Requires elevation.'
        };
      }

      return {
        status: 'UNKNOWN',
        detectionMethod: 'WINDOWS_REGISTRY_QUERY',
        confidence: 'LOW',
        errorMessage: errMsg || 'Unable to query Windows registry'
      };
    }
  }

  /**
   * Detect Connected USB Mass Storage Devices (Excluding Keyboards, Mice, Webcams, HID)
   * Executes PowerShell queries (Get-PnpDevice / Get-CimInstance Win32_DiskDrive)
   * Adheres strictly to privacy guidelines: only hardware metadata collected.
   */
  private async detectWindowsStorageDevices(): Promise<USBStorageDevice[]> {
    const runner = this.config.mockRunner || (async (cmd: string) => {
      return execAsync(cmd, { timeout: 4000 });
    });

    const devices: USBStorageDevice[] = [];

    try {
      // Primary: Query via Get-CimInstance / Get-PnpDevice for USB storage class devices
      const psCmd = `powershell -NoProfile -NonInteractive -Command "try { $d = Get-CimInstance Win32_DiskDrive | Where-Object { $_.InterfaceType -eq 'USB' } | Select-Object Model, Manufacturer, DeviceID, MediaType, Size; if ($d) { $d | ConvertTo-Json -Compress } else { Get-PnpDevice -Class 'DiskDrive' -Status 'OK' | Where-Object { $_.InstanceId -like 'USB*' } | Select-Object @{N='Model';E={$_.FriendlyName}}, @{N='Manufacturer';E={$_.Manufacturer}}, @{N='DeviceID';E={$_.InstanceId}} | ConvertTo-Json -Compress } } catch { @() | ConvertTo-Json }"` ;
      const { stdout } = await runner(psCmd);

      if (!stdout || stdout.trim() === '' || stdout.trim() === 'null') {
        return [];
      }

      let parsed: any;
      try {
        parsed = JSON.parse(stdout.trim());
      } catch {
        return [];
      }

      const items = Array.isArray(parsed) ? parsed : [parsed];

      for (const item of items) {
        if (!item || typeof item !== 'object') continue;

        const model = String(item.Model || item.FriendlyName || 'Generic USB Storage').trim();
        const rawManufacturer = String(item.Manufacturer || '').trim();
        const manufacturer = rawManufacturer && rawManufacturer !== '(Standard disk drives)'
          ? rawManufacturer
          : this.extractManufacturer(model);
        const rawDeviceId = String(item.DeviceID || item.InstanceId || '').trim();

        // Strict Privacy Guard: Sanitize device hardware ID to prevent file system or path leakage
        const sanitizedId = rawDeviceId
          .replace(/\\\\\\.\\/g, '')
          .replace(/[^a-zA-Z0-9_-]/g, '_')
          .substring(0, 64);

        // Exclude non-storage peripherals (keyboards, mice, webcams, audio interfaces, etc.)
        if (this.isNonStoragePeripheral(model) || this.isNonStoragePeripheral(rawManufacturer)) {
          continue;
        }

        devices.push({
          device_type: 'USB Mass Storage',
          manufacturer: manufacturer || 'Generic',
          model: model || 'Removable Storage Device',
          device_id: sanitizedId || undefined,
          connection_status: 'Connected'
        });
      }
    } catch {
      // If PowerShell is blocked or unavailable, fall back to empty list rather than failing whole scan
    }

    return devices;
  }

  /**
   * Helper to identify and reject non-storage peripherals
   */
  public isNonStoragePeripheral(deviceText: string): boolean {
    if (!deviceText) return false;
    const lower = deviceText.toLowerCase();
    const nonStorageKeywords = [
      'keyboard',
      'mouse',
      'pointing device',
      'trackball',
      'touchpad',
      'webcam',
      'camera',
      'printer',
      'scanner',
      'hid',
      'human interface',
      'audio',
      'headset',
      'microphone',
      'speaker',
      'bluetooth adapter',
      'network adapter',
      'ethernet',
      'wi-fi',
      'wireless receiver',
      'dongle receiver',
      'smart card',
      'yubikey',
      'fingerprint'
    ];
    return nonStorageKeywords.some(kw => lower.includes(kw));
  }

  /**
   * Parse vendor/manufacturer name from model string
   */
  public extractManufacturer(model: string): string {
    const knownVendors = [
      'Kingston',
      'SanDisk',
      'Samsung',
      'Crucial',
      'Seagate',
      'Western Digital',
      'WD',
      'Toshiba',
      'Corsair',
      'Transcend',
      'PNY',
      'Lexar',
      'HP',
      'Sony',
      'Verbatim',
      'Kioxia',
      'Patriot',
      'Adata',
      'LaCie',
      'Sabrent',
      'Silicon Power'
    ];

    for (const vendor of knownVendors) {
      if (new RegExp(`\\b${vendor}\\b`, 'i').test(model)) {
        return vendor;
      }
    }
    return 'Generic';
  }
}

