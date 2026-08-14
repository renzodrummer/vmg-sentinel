export const TIMETRACKER_SOCKET_EVENTS = [
  'timetracker:state',
  'timetracker:started',
  'timetracker:status_changed',
  'timetracker:stopped',
] as const;

export type TimetrackerSocketEvent = (typeof TIMETRACKER_SOCKET_EVENTS)[number];

export const TIMETRACKER_STATUS_LABELS: Record<string, string> = {
  offline: 'Offline',
  not_working: 'Not Working',
  online: 'Online',
  busy: 'Busy',
  bio_break: 'Bio Break',
  lunch_break: 'Lunch Break',
  unpaid_break: 'Unpaid Break',
  in_a_meeting: 'In a Meeting',
  official_business: 'Official Business',
};

export const formatTimetrackerStatus = (status: string): string =>
  TIMETRACKER_STATUS_LABELS[status] ?? status;
