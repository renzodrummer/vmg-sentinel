const path = require('node:path');
const { ScoringEngine } = require('./scoring-engine');
const { WindowContextService } = require('./window-context-service');
const { MeetingLog } = require('./meeting-log');

function unavailableSnapshot(reason) {
  return {
    is_available: false,
    unavailable_reason: reason,
    sessions: [],
    windows: [],
    device_running_somewhere: false,
    captured_at: String(Date.now()),
  };
}

function normalizeSnapshot(raw) {
  if (!raw) return unavailableSnapshot('empty');
  return {
    is_available: raw.is_available ?? raw.isAvailable ?? false,
    unavailable_reason: raw.unavailable_reason ?? raw.unavailableReason ?? null,
    sessions: (raw.sessions || []).map((s) => ({
      pid: s.pid,
      process_name: s.process_name || s.processName || '',
      is_capture_active: !!(s.is_capture_active ?? s.isCaptureActive),
    })),
    windows: (raw.windows || []).map((w) => ({
      pid: w.pid,
      title: w.title || '',
      is_focused: !!(w.is_focused ?? w.isFocused),
    })),
    device_running_somewhere: !!(
      raw.device_running_somewhere ?? raw.deviceRunningSomewhere
    ),
  };
}

function loadNative() {
  try {
    return require(path.join(__dirname, '../../native/meeting-detector'));
  } catch (error) {
    console.warn('meeting-detector native unavailable:', error.message);
    return null;
  }
}

class MeetingDetectorService {
  constructor({ idleDetector, logPath, onState }) {
    this.native = loadNative();
    this.engine = new ScoringEngine();
    this.windows = new WindowContextService();
    this.log = new MeetingLog(logPath);
    this.idleDetector = idleDetector;
    this.onState = onState;
    this.running = false;
    this.timer = null;
    this.lastBroadcast = null;
  }

  start() {
    if (this.running) return;
    this.running = true;
    this.log.open();
    void this.tick();
    this.timer = setInterval(() => {
      void this.tick();
    }, 3000);
  }

  stop({ reason = 'privacy' } = {}) {
    this.running = false;
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }

    const ended = this.engine.endByPrivacy();
    this.idleDetector?.resumeFromMeeting();
    this.windows.clear();

    if (ended.changed) {
      const payload = {
        is_in_meeting: false,
        score: 0,
        has_session_clue: false,
        sessions: [],
        device_running_somewhere: false,
        is_available: false,
        unavailable_reason: null,
        timestamp: new Date().toISOString(),
        ended_by: reason === 'privacy' ? 'privacy' : ended.ended_by,
      };
      this.log.writeTransition({
        is_in_meeting: false,
        timestamp: payload.timestamp,
        score: 0,
        ended_by: payload.ended_by,
      });
      this.broadcast(payload);
    }

    this.log.close();
  }

  async tick() {
    if (!this.running) return;
  
    let snapshot = unavailableSnapshot('native_not_built');
    try {
      const poll =
        this.native?.poll_capture_sessions || this.native?.pollCaptureSessions;
      if (poll) {
        snapshot = normalizeSnapshot(await poll());
      }
    } catch (error) {
      snapshot = unavailableSnapshot(error.message || 'poll_failed');
    }
  
    this.handleSnapshot(snapshot);
  }

  handleSnapshot(snapshot) {
    if (!this.running) return;

    const ctx = this.windows.updateFromSnapshot(snapshot);
    const result = this.engine.evaluate(snapshot, ctx);

    if (result.changed && result.is_in_meeting) {
      this.idleDetector?.pauseForMeeting();
    } else if (result.changed && !result.is_in_meeting) {
      this.idleDetector?.resumeFromMeeting();
    }

    const payload = {
      is_in_meeting: result.is_in_meeting,
      score: result.score,
      has_session_clue: result.has_session_clue,
      sessions: snapshot.sessions || [],
      device_running_somewhere: !!snapshot.device_running_somewhere,
      is_available: snapshot.is_available,
      unavailable_reason: snapshot.unavailable_reason ?? null,
      timestamp: new Date().toISOString(),
      ended_by: result.ended_by,
    };

    if (result.changed) {
      this.log.writeTransition({
        is_in_meeting: payload.is_in_meeting,
        timestamp: payload.timestamp,
        score: payload.score,
        ended_by: payload.ended_by,
      });
    }

    this.broadcast(payload);
  }

  broadcast(payload) {
    this.lastBroadcast = payload;
    this.onState?.(payload);
  }
}

module.exports = { MeetingDetectorService };