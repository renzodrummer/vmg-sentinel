const { isBrowserExe, isMeetingUrlOrTitle } = require('./meeting-allowlists');

class WindowContextService {
  constructor() {
    this.lastKnown = new Map();
  }

  updateFromSnapshot(snapshot) {
    const focusedPid = (snapshot.windows || []).find((w) => w.is_focused)?.pid;
    const meetingWindows = (snapshot.windows || []).filter((w) =>
      isMeetingUrlOrTitle(w.title),
    );

    for (const win of meetingWindows) {
      if (!win.pid) continue;
      this.lastKnown.set(win.pid, {
        url_or_title: win.title,
        is_focused: win.pid === focusedPid,
        seen_at: Date.now(),
      });
    }

    const fallbackTitle = meetingWindows[0]?.title;
    for (const session of snapshot.sessions || []) {
      if (!isBrowserExe(session.process_name) || !fallbackTitle) continue;
      if (!this.lastKnown.has(session.pid)) {
        this.lastKnown.set(session.pid, {
          url_or_title: fallbackTitle,
          is_focused: session.pid === focusedPid,
          seen_at: Date.now(),
        });
      }
    }

    const byPid = {};
    for (const [pid, value] of this.lastKnown) {
      byPid[pid] = {
        url_or_title: value.url_or_title,
        is_focused: pid === focusedPid,
      };
    }
    return byPid;
  }

  clear() {
    this.lastKnown.clear();
  }
}

module.exports = { WindowContextService };