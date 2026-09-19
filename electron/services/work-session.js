const WORKING_STATUSES = new Set([
  'online',
  'busy',
  'in_a_meeting',
  'official_business',
]);

function isWorkSessionActive({ localTracking = false, citadel } = {}) {
  if (localTracking) {
    return true;
  }
  if (!citadel) {
    return false;
  }
  return citadel.is_tracking === true && WORKING_STATUSES.has(citadel.status);
}

function workSessionReason({ localTracking = false, citadel } = {}) {
  if (localTracking) {
    return 'local-tracking';
  }
  if (citadel?.is_tracking && WORKING_STATUSES.has(citadel.status)) {
    return `citadel:${citadel.status}`;
  }
  return 'idle';
}

module.exports = { isWorkSessionActive, workSessionReason, WORKING_STATUSES };
