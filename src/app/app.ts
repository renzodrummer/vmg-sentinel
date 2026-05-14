import { Component, OnInit, ChangeDetectorRef, ViewChild, ElementRef } from '@angular/core';
import { ElectronService } from './electron.service';
import { DesktopSource } from '../global';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-root',
  imports: [CommonModule, FormsModule],
  templateUrl: './app.html',
  styleUrl: './app.scss',
})
export class App implements OnInit {
  isTracking = false;
  screenInfoText = 'Loading screen info...';

  @ViewChild('previewVideo') previewVideo!: ElementRef<HTMLVideoElement>;
  availableSources: DesktopSource[] = [];
  selectedSourceId: string = '';
  isRecording = false;
  private mediaRecorder: MediaRecorder | null = null;

  constructor(
    private electronService: ElectronService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit() {
    this.updateScreenCount();
  }

  async updateScreenCount() {
    try {
      const count = await this.electronService.getScreenCount();
      this.screenInfoText = `You have ${count} screen(s) connected.`;

      this.cdr.detectChanges();
    } catch (error) {
      this.screenInfoText = 'Error fetching screen count.';
      this.cdr.detectChanges();
      console.error(error);
    }
  }

  toggleTracking() {
    if (!this.electronService.isElectron) {
      console.warn('Cannot track: Not running in Electron');
      return;
    }

    if (!this.isTracking) {
      const intervalMinutes = 15;
      this.electronService.startAutoCapture(intervalMinutes);
      this.isTracking = true;
    } else {
      this.electronService.stopAutoCapture();
      this.isTracking = false;
    }
  }

  captureAllScreensNow() {
    if (!this.electronService.isElectron) {
      console.warn('Cannot capture: Not running in Electron');
      return;
    }

    console.log('Initiating multi-screen capture...');
    this.electronService.triggerMultiScreenCapture();
  }

  captureActiveScreenNow() {
    if (!this.electronService.isElectron) {
      console.warn('Cannot capture: Not running in Electron');
      return;
    }

    console.log('Initiating active screen capture...');
    this.electronService.triggerActiveScreenCapture();
  }

  // screen recording

  async fetchVideoSources() {
    if (!this.electronService.isElectron) return;

    this.availableSources = await this.electronService.getVideoSources();
    if (this.availableSources.length > 0) {
      this.selectedSourceId = this.availableSources[0].id;
    }
    this.cdr.detectChanges();
  }

  async startRecording() {
    if (!this.selectedSourceId) {
      alert('Please get video sources and select a screen to record first!');
      return;
    }

    const os = await this.electronService.getOperatingSystem();
    const isMac = os === 'darwin';

    const audioConstraint = !isMac ? { mandatory: { chromeMediaSource: 'desktop' } } : false;
    const constraints: any = {
      audio: audioConstraint,
      video: {
        mandatory: {
          chromeMediaSource: 'desktop',
          chromeMediaSourceId: this.selectedSourceId,
        },
      },
    };

    await this.electronService.initRecordingStream();
    this.isRecording = true;
    this.cdr.detectChanges();

    const stream = await (navigator.mediaDevices as any).getUserMedia(constraints);

    const videoEl = this.previewVideo.nativeElement;
    videoEl.srcObject = stream;
    await videoEl.play();

    try {
      await videoEl.requestPictureInPicture();
    } catch (pipError) {
      console.warn('Picture-in-Picture failed or is not supported:', pipError);
    }

    this.mediaRecorder = new MediaRecorder(stream, {
      mimeType: 'video/webm; codecs=h264',
    });

    this.mediaRecorder.ondataavailable = async (e) => {
      if (e.data.size > 0) {
        const buffer = await e.data.arrayBuffer();
        this.electronService.sendVideoChunk(buffer);
      }
    };

    this.mediaRecorder.onstop = async () => {
      videoEl.srcObject = null;
      const saved = await this.electronService.finishAndSaveRecording();

      if (saved) {
        console.log('Video saved successfully!');
      } else {
        console.log('Recording discarded by user.');
      }
    };

    this.mediaRecorder.start(3000);
  }

  async stopRecording() {
    if (this.mediaRecorder && this.mediaRecorder.state !== 'inactive') {
      this.mediaRecorder.stop();
      this.isRecording = false;
      this.cdr.detectChanges();

      if (document.pictureInPictureElement) {
        await document.exitPictureInPicture();
      }
    } else {
      console.log("Nothing to stop! Recording hasn't started.");
    }
  }
}
