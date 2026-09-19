function norm(name) {
    return String(name || '').trim().toLowerCase();
  }
  
  const MEETING_EXES = new Set([
    'zoom.exe',
    'zoom.app',
    'teams.exe',
    'ms-teams.exe',
    'slack.exe',
    'slack.app',
    'webex.exe',
  ]);
  
  const BROWSER_EXES = new Set([
    'chrome.exe',
    'firefox.exe',
    'msedge.exe',
    'safari.app',
  ]);
  
  const REJECT_EXES = new Set([
    'discord.exe',
    'discord.app',
    'obs64.exe',
    'obs.app',
    'recorder.exe',
    'camtasia.exe',
  ]);
  
  const MEETING_URLS = [
    'meet.google.com',
    'teams.microsoft.com',
    'zoom.us',
    'zoom.com',
  ];
  
  const MEETING_TITLES = [
    'google meet -',
    'google meet',
    'meet -',
    'zoom meeting',
  ];
  
  function baseName(processName) {
    const n = norm(processName).replace(/\\/g, '/');
    return n.split('/').pop();
  }
  
  function isMeetingExe(processName) {
    return MEETING_EXES.has(baseName(processName));
  }
  
  function isBrowserExe(processName) {
    return BROWSER_EXES.has(baseName(processName));
  }
  
  function isRejectExe(processName) {
    return REJECT_EXES.has(baseName(processName));
  }
  
  function isMeetingUrlOrTitle(value) {
    const text = norm(value);
    if (!text) return false;
    return (
      MEETING_URLS.some((part) => text.includes(part)) ||
      MEETING_TITLES.some((part) => text.includes(part))
    );
  }
  
  module.exports = {
    isMeetingExe,
    isBrowserExe,
    isRejectExe,
    isMeetingUrlOrTitle,
  };