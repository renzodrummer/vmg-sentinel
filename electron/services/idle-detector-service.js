const { powerMonitor } = require('electron');

const DEFAULT_IDLE_THRESHOLD_SEC = 60;
const MEETING_IDLE_CAP_SEC = 120 * 60;

class IdleDetectorService {
  constructor({
    thresholdSec = DEFAULT_IDLE_THRESHOLD_SEC,
    onIdle,
    onActive,
    getIdleTime,
  } = {}) {
    this.thresholdSec = thresholdSec;
    this.onIdle = onIdle;
    this.onActive = onActive;
    this.getIdleTime = getIdleTime || (() => powerMonitor.getSystemIdleTime());
    this.paused = false;
    this.isIdle = false;
    this.capTripped = false;
    this.timer = null;
  }

  start() {
    if (this.timer) return;
    this.timer = setInterval(() => this.tick(), 1000);
  }

  stop() {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
    this.paused = false;
    this.isIdle = false;
    this.capTripped = false;
  }

  pauseForMeeting() {
    if (this.capTripped) return;
    this.paused = true;
    if (this.isIdle) {
      this.isIdle = false;
      this.onActive?.();
    }
  }

  resumeFromMeeting() {
    this.paused = false;
    this.capTripped = false;
  }

  tick() {
    const idleSec = this.getIdleTime();

    if (this.paused && idleSec >= MEETING_IDLE_CAP_SEC) {
      this.paused = false;
      this.capTripped = true;
    }

    if (this.paused) return;

    if (!this.isIdle && idleSec >= this.thresholdSec) {
      this.isIdle = true;
      this.onIdle?.({ idle_seconds: idleSec });
    } else if (this.isIdle && idleSec < this.thresholdSec) {
      this.isIdle = false;
      this.onActive?.();
    }
  }
}

module.exports = { IdleDetectorService, MEETING_IDLE_CAP_SEC };