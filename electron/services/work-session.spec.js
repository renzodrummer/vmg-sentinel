import { isWorkSessionActive, workSessionReason } from './work-session.js';

describe('work-session', () => {
  it('turns on when local tracking starts', () => {
    expect(isWorkSessionActive({ localTracking: true })).toBe(true);
    expect(workSessionReason({ localTracking: true })).toBe('local-tracking');
  });

  it('turns on when Citadel is tracking a working status', () => {
    expect(
      isWorkSessionActive({
        citadel: { is_tracking: true, status: 'online' },
      }),
    ).toBe(true);
  });

  it('stays off on lunch even if a stale tracking flag is set without working status', () => {
    expect(
      isWorkSessionActive({
        localTracking: false,
        citadel: { is_tracking: true, status: 'lunch_break' },
      }),
    ).toBe(false);
  });

  it('stays off when tracker is stopped', () => {
    expect(
      isWorkSessionActive({
        citadel: { is_tracking: false, status: 'offline' },
      }),
    ).toBe(false);
  });
});
