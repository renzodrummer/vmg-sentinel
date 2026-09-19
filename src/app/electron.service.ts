import { Injectable } from '@angular/core';
import { DesktopSource, MeetingDebugState, PolicyStatus } from '../global';

@Injectable({
  providedIn: 'root',
})
export class ElectronService {
  get isElectron(): boolean {
    return !!(window && window.electronAPI);
  }

  captureScreen(): void {
    if (this.isElectron) window.electronAPI.captureScreen();
  }

  startAutoCapture(intervalMinutes: number): void {
    if (this.isElectron) window.electronAPI.startAutoCapture(intervalMinutes);
  }

  stopAutoCapture(): void {
    if (this.isElectron) window.electronAPI.stopAutoCapture();
  }

  async getScreenCount(): Promise<number> {
    if (this.isElectron) {
      return await window.electronAPI.getScreenCount();
    }
    throw new Error('Electron API not found');
  }

  async setAuthCookie(url: string, name: string, value: string): Promise<void> {
    if (this.isElectron) {
      await window.electronAPI.setAuthCookie(url, name, value);
    }
  }

  triggerMultiScreenCapture(): void {
    if (this.isElectron) {
      window.electronAPI.captureMultiScreen();
    }
  }

  triggerActiveScreenCapture(): void {
    if (this.isElectron) {
      window.electronAPI.captureActiveScreen();
    }
  }

  async getVideoSources(): Promise<DesktopSource[]> {
    return this.isElectron ? await window.electronAPI.getVideoSources() : [];
  }

  async getOperatingSystem(): Promise<string> {
    return this.isElectron ? await window.electronAPI.getOperatingSystem() : 'unknown';
  }

  async initRecordingStream(): Promise<boolean> {
    return this.isElectron ? await window.electronAPI.startRecordingStream() : false;
  }

  sendVideoChunk(buffer: ArrayBuffer): void {
    if (this.isElectron) window.electronAPI.saveVideoChunk(buffer);
  }

  async finishAndSaveRecording(): Promise<boolean> {
    return this.isElectron ? await window.electronAPI.stopAndSaveRecording() : false;
  }

  onMeetingState(callback: (state: MeetingDebugState) => void): () => void {
    if (!this.isElectron) {
      return () => undefined;
    }
    return window.electronAPI.onMeetingState(callback);
  }

  async getPolicyStatus(): Promise<PolicyStatus | null> {
    if (!this.isElectron) {
      return null;
    }
    return window.electronAPI.getPolicyStatus();
  }

  async setCitadelWorkSession(
    payload: { is_tracking: boolean; status: string } | null,
  ): Promise<PolicyStatus | null> {
    if (!this.isElectron) {
      return null;
    }
    return window.electronAPI.setCitadelWorkSession(payload);
  }

  async refreshCitadelPolicy(apiUrl: string): Promise<{ ok: boolean; code?: string } | null> {
    if (!this.isElectron) {
      return null;
    }
    return window.electronAPI.refreshCitadelPolicy({ apiUrl });
  }

  onPolicyStatus(callback: (status: PolicyStatus) => void): () => void {
    if (!this.isElectron) {
      return () => undefined;
    }
    return window.electronAPI.onPolicyStatus(callback);
  }
}
