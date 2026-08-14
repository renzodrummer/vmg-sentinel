export type TimetrackerUserStatus =
  | 'offline'
  | 'not_working'
  | 'online'
  | 'busy'
  | 'bio_break'
  | 'lunch_break'
  | 'unpaid_break'
  | 'in_a_meeting'
  | 'official_business'
  | string;

export interface ITimetrackerSocketPayload {
  staff_id: string;
  is_tracking: boolean;
  status: TimetrackerUserStatus;
  timelog_start: string | null;
  staff_timelog_id: string | null;
  timelog_id: string | null;
  status_id: string | null;
  lunch_break_start: string | null;
  bio_break_start: string | null;
  unpaid_break_start: string | null;
  lunch_break_consumed: number;
  bio_break_consumed: number;
  unpaid_break_consumed: number;
}

export interface ITimetrackerStatusNotice {
  event: string;
  message: string;
  at: string;
  status: TimetrackerUserStatus;
  isTracking: boolean;
}
