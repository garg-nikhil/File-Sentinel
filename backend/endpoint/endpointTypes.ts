/**
 * FILE-SENTINEL — Phase A: Endpoint Compliance Detection Engine
 * Type Definitions & Model Interfaces
 */

export type EndpointPlatform = 'windows' | 'linux' | 'darwin' | 'unsupported';

export type DetectionCategory =
  | 'USB_STORAGE'
  | 'SOCIAL_MEDIA'
  | 'PERSONAL_EMAIL'
  | 'MESSAGING'
  | 'CLOUD_STORAGE';

export type WebAccessCategory =
  | 'SOCIAL_MEDIA'
  | 'PERSONAL_EMAIL'
  | 'MESSAGING'
  | 'CLOUD_STORAGE';

export type USBStatus =
  | 'ENABLED'
  | 'DISABLED'
  | 'UNKNOWN'
  | 'NOT_PRESENT'
  | 'UNSUPPORTED_PLATFORM'
  | 'REQUIRES_ELEVATION';

export type WebAccessStatus =
  | 'ACCESSIBLE'
  | 'BLOCKED'
  | 'INDETERMINATE'
  | 'UNREACHABLE'
  | 'UNSUPPORTED';

export type ConfidenceLevel = 'HIGH' | 'MEDIUM' | 'LOW';

export type DetectionMethod =
  | 'WINDOWS_REGISTRY_QUERY'
  | 'WINDOWS_WMI_QUERY'
  | 'WINDOWS_POWERSHELL'
  | 'HTTPS_PROBE'
  | 'DNS_TCP_PROBE'
  | 'UNSUPPORTED_PLATFORM'
  | 'ELEVATION_REQUIRED'
  | 'MOCK_WINDOWS_SYSTEM';

export type AssessmentOverallStatus =
  | 'COMPLIANT'
  | 'NON_COMPLIANT'
  | 'ATTENTION_REQUIRED'
  | 'INDETERMINATE';

export interface USBStorageDevice {
  device_type: string; // e.g. "USB Mass Storage"
  manufacturer: string; // e.g. "Kingston", "SanDisk"
  model: string; // e.g. "DataTraveler", "Ultra"
  device_id?: string; // sanitized hardware ID
  connection_status: 'Connected' | 'Disconnected';
}

export interface USBDetectionResult {
  category: 'USB_STORAGE';
  status: USBStatus;
  connectedStorageDevices: USBStorageDevice[];
  connectedDeviceCount: number;
  detectionMethod: DetectionMethod;
  confidence: ConfidenceLevel;
  timestamp: string;
  platform: string;
  policyDetails?: {
    usbstorServiceStart?: number; // 3 = enabled, 4 = disabled
    storageDevicePolicies?: string;
    writeProtect?: boolean;
    denyAll?: boolean;
  };
  errorMessage?: string;
}

export type USBDetectorResult = USBDetectionResult;

export interface WebAccessTarget {
  id: string;
  category: WebAccessCategory;
  service_name: string;
  primary_domain: string;
  probe_url: string;
  expected_identifiers: string[];
  allowed_domains?: string[];
}

export type EndpointRuntimeProviderType = 'LOCAL_WINDOWS_AGENT' | 'SIMULATED_TEST_RUNNER';

export interface EndpointRuntimeProvider {
  type: EndpointRuntimeProviderType;
  platform: EndpointPlatform;
  isLocalExecution: boolean;
  runtimeDescription: string;
}

export interface WebTargetResult {
  category: WebAccessCategory;
  service: string;
  target_domain: string;
  status: WebAccessStatus;
  confidence: ConfidenceLevel;
  detectionMethod: DetectionMethod;
  httpStatusCode?: number;
  reason?: string;
  responseTimeMs?: number;
  timestamp: string;
}

export interface CategorySummary {
  total: number;
  accessible: number;
  blocked: number;
  indeterminate: number;
  enabled?: boolean;
}

export interface EndpointAssessment {
  id: string;
  org_id: string;
  device_id: string;
  user_id: string;
  timestamp: string;
  platform: string;
  application_version: string;
  overall_status: AssessmentOverallStatus;
  usb_result: USBDetectionResult;
  web_results: WebTargetResult[];
  category_summaries: Record<DetectionCategory, CategorySummary>;
  evidence_text: string;
  created_at: string;
}

export interface EndpointDetectorOptions {
  platformOverride?: EndpointPlatform;
  mockWindowsUsbData?: Partial<USBDetectionResult>;
  customWebTargets?: WebAccessTarget[];
  connectionTimeoutMs?: number;
  requestTimeoutMs?: number;
  maxResponseSizeBytes?: number;
  maxRedirects?: number;
  concurrencyLimit?: number;
}
