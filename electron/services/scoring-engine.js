const {
    isMeetingExe,
    isBrowserExe,
    isRejectExe,
    isMeetingUrlOrTitle,
  } = require('./meeting-allowlists');
  
  const ENTER_SCORE = 60;
  const ENTER_HOLD_MS = 10_000;
  const LEAVE_HOLD_MS = 15_000;
  
  class ScoringEngine {
    constructor() {
      this.is_in_meeting = false;
      this.enter_since = null;
      this.leave_since = null;
      this.last_score = 0;
      this.last_has_session_clue = false;
    }
  
    reset() {
      this.is_in_meeting = false;
      this.enter_since = null;
      this.leave_since = null;
      this.last_score = 0;
      this.last_has_session_clue = false;
    }
  
    evaluate(snapshot, windowContextByPid = {}, nowMs = Date.now()) {
      const scored = this.score(snapshot, windowContextByPid);
      const transition = this.applyHysteresis(scored, nowMs);
      return { ...scored, ...transition };
    }
  
    score(snapshot, windowContextByPid = {}) {
      const sessions = (snapshot.sessions || []).filter((s) => s.is_capture_active);
      let score = 0;
      let has_session_clue = false;
      let has_meeting_or_browser_clue = false;
      let has_reject = false;
      let has_focused_meeting = false;
  
      for (const session of sessions) {
        const ctx = windowContextByPid[session.pid] || {};
        const hint = ctx.url_or_title || '';
  
        if (isMeetingExe(session.process_name)) {
          score += 70;
          has_session_clue = true;
          has_meeting_or_browser_clue = true;
        } else if (isBrowserExe(session.process_name) && isMeetingUrlOrTitle(hint)) {
          score += 70;
          has_session_clue = true;
          has_meeting_or_browser_clue = true;
        }
  
        if (isRejectExe(session.process_name)) {
          has_reject = true;
        }
  
        if (ctx.is_focused && (isMeetingExe(session.process_name) || isMeetingUrlOrTitle(hint))) {
          has_focused_meeting = true;
        }
      }
  
      if (has_focused_meeting) {
        score += 20;
      }
  
      if (!has_meeting_or_browser_clue && snapshot.device_running_somewhere) {
        score += 20;
      }
  
      if (has_reject && !has_meeting_or_browser_clue) {
        score -= 100;
      }
  
      score = Math.max(0, Math.min(100, score));
  
      return {
        score,
        has_session_clue,
        signals: {
          has_meeting_or_browser_clue,
          has_reject,
          has_focused_meeting,
          device_running_somewhere: !!snapshot.device_running_somewhere,
        },
      };
    }
  
    applyHysteresis(scored, nowMs) {
      this.last_score = scored.score;
      this.last_has_session_clue = scored.has_session_clue;
  
      let changed = false;
      let ended_by = null;
  
      if (!this.is_in_meeting) {
        this.leave_since = null;
        if (scored.score >= ENTER_SCORE) {
          if (this.enter_since == null) this.enter_since = nowMs;
          if (nowMs - this.enter_since >= ENTER_HOLD_MS) {
            this.is_in_meeting = true;
            this.enter_since = null;
            changed = true;
          }
        } else {
          this.enter_since = null;
        }
      } else if (!scored.has_session_clue) {
        this.enter_since = null;
        if (this.leave_since == null) this.leave_since = nowMs;
        if (nowMs - this.leave_since >= LEAVE_HOLD_MS) {
          this.is_in_meeting = false;
          this.leave_since = null;
          changed = true;
          ended_by = 'session_lost';
        }
      } else {
        this.leave_since = null;
      }
  
      return {
        is_in_meeting: this.is_in_meeting,
        changed,
        ended_by,
      };
    }
  
    endByPrivacy() {
      const wasInMeeting = this.is_in_meeting;
      this.reset();
      return {
        is_in_meeting: false,
        changed: wasInMeeting,
        ended_by: wasInMeeting ? 'privacy' : null,
        score: 0,
        has_session_clue: false,
      };
    }
  }
  
  module.exports = { ScoringEngine, ENTER_SCORE, ENTER_HOLD_MS, LEAVE_HOLD_MS };