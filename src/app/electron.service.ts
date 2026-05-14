import { Injectable } from '@angular/core';
import { DesktopSource } from '../global';

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
}
