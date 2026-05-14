export interface DesktopSource {
  id: string;
  name: string;
}

export interface ElectronAPI {
  captureScreen: () => void;
  startAutoCapture: (intervalMinutes: number) => void;
  stopAutoCapture: () => void;
  getScreenCount: () => Promise<number>;

  captureMultiScreen: () => void;

  captureActiveScreen: () => void;

  getVideoSources: () => Promise<DesktopSource[]>;
  getOperatingSystem: () => Promise<string>;
  startRecordingStream: () => Promise<boolean>;
  saveVideoChunk: (buffer: ArrayBuffer) => void;
  stopAndSaveRecording: () => Promise<boolean>;
}

declare global {
  interface Window {
    electronAPI: ElectronAPI;
  }
}
