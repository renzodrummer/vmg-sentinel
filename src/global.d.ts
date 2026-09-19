export interface DesktopSource {
  id: string;
  name: string;
}

export interface MeetingDebugState {
  is_in_meeting: boolean;
  score: number;
  has_session_clue: boolean;
  sessions: Array<{ pid: number; process_name: string; is_capture_active: boolean }>;
  device_running_somewhere: boolean;
  is_available?: boolean;
  unavailable_reason?: string | null;
  timestamp: string;
  ended_by?: string | null;
}

export interface PolicyStatus {
  session_active?: boolean;
  session_reason?: string;
  enforcing?: boolean;
  needs_admin?: boolean;
  needs_service?: boolean;
  policy_loaded?: boolean;
  policy_mode?: string | null;
  filters_added?: number;
  apps_reconciled?: number;
  last_error?: string | null;
  enforcement?: string;
  engine?: string;
  helper_build?: string;
  app_engine?: string;
  mde_present?: boolean;
  privilege?: string;
}

export interface ElectronAPI {
  captureScreen: () => void;
  startAutoCapture: (intervalMinutes: number) => void;
  stopAutoCapture: () => void;
  getScreenCount: () => Promise<number>;
  setAuthCookie: (url: string, name: string, value: string) => Promise<void>;

  captureMultiScreen: () => void;

  captureActiveScreen: () => void;

  getVideoSources: () => Promise<DesktopSource[]>;
  getOperatingSystem: () => Promise<string>;
  startRecordingStream: () => Promise<boolean>;
  saveVideoChunk: (buffer: ArrayBuffer) => void;
  stopAndSaveRecording: () => Promise<boolean>;
  onMeetingState: (callback: (state: MeetingDebugState) => void) => () => void;
  getPolicyStatus: () => Promise<PolicyStatus>;
  setCitadelWorkSession: (payload: { is_tracking: boolean; status: string } | null) => Promise<PolicyStatus | null>;
  refreshCitadelPolicy: (payload: { apiUrl: string }) => Promise<{ ok: boolean; code?: string }>;
  onPolicyStatus: (callback: (status: PolicyStatus) => void) => () => void;
}

declare global {
  interface Window {
    electronAPI: ElectronAPI;
  }
}
