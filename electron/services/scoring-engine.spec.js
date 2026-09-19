import { describe, expect, it } from 'vitest';
import { ScoringEngine } from './scoring-engine.js';

const t0 = 1_000_000;

function session(pid, process_name) {
  return { pid, process_name, is_capture_active: true };
}

describe('ScoringEngine matrix', () => {
  it('1. app open, no call → score 0', () => {
    const engine = new ScoringEngine();
    const result = engine.evaluate({ sessions: [], device_running_somewhere: false }, {}, t0);
    expect(result.score).toBe(0);
    expect(result.is_in_meeting).toBe(false);
  });

  it('2. join from tray → +70, enter after 10s', () => {
    const engine = new ScoringEngine();
    const snap = { sessions: [session(10, 'zoom.exe')], device_running_somewhere: false };
    expect(engine.evaluate(snap, {}, t0).is_in_meeting).toBe(false);
    expect(engine.evaluate(snap, {}, t0 + 9_999).is_in_meeting).toBe(false);
    const entered = engine.evaluate(snap, {}, t0 + 10_000);
    expect(entered.score).toBe(70);
    expect(entered.is_in_meeting).toBe(true);
  });

  it('3. background notes → stays in meeting', () => {
    const engine = new ScoringEngine();
    const snap = { sessions: [session(10, 'zoom.exe')], device_running_somewhere: false };
    engine.evaluate(snap, {}, t0);
    engine.evaluate(snap, {}, t0 + 10_000);
    const notes = engine.evaluate(snap, {}, t0 + 20_000);
    expect(notes.is_in_meeting).toBe(true);
    expect(notes.score).toBe(70);
  });

  it('4. hang up → leave after 15s of lost +70 clue', () => {
    const engine = new ScoringEngine();
    const live = { sessions: [session(10, 'zoom.exe')], device_running_somewhere: false };
    engine.evaluate(live, {}, t0);
    engine.evaluate(live, {}, t0 + 10_000);
    const idle = { sessions: [], device_running_somewhere: true };
    expect(engine.evaluate(idle, {}, t0 + 20_000).is_in_meeting).toBe(true);
    const left = engine.evaluate(idle, {}, t0 + 35_000);
    expect(left.is_in_meeting).toBe(false);
    expect(left.ended_by).toBe('session_lost');
    expect(left.score).toBe(20);
  });

  it('5. Google Meet tab switch keeps last-known title', () => {
    const engine = new ScoringEngine();
    const snap = { sessions: [session(44, 'chrome.exe')], device_running_somewhere: false };
    const ctx = { 44: { url_or_title: 'Google Meet - Standup', is_focused: false } };
    engine.evaluate(snap, ctx, t0);
    const result = engine.evaluate(snap, ctx, t0 + 10_000);
    expect(result.score).toBe(70);
    expect(result.is_in_meeting).toBe(true);
  });

  it('7. AirPods idle → +20, never enters', () => {
    const engine = new ScoringEngine();
    const result = engine.evaluate(
      { sessions: [], device_running_somewhere: true },
      {},
      t0 + 30_000,
    );
    expect(result.score).toBe(20);
    expect(result.is_in_meeting).toBe(false);
  });

  it('8. Zoom + Discord suppresses reject penalty', () => {
    const engine = new ScoringEngine();
    const snap = {
      sessions: [session(10, 'zoom.exe'), session(20, 'discord.exe')],
      device_running_somewhere: false,
    };
    engine.evaluate(snap, {}, t0);
    const result = engine.evaluate(snap, {}, t0 + 10_000);
    expect(result.score).toBe(70);
    expect(result.is_in_meeting).toBe(true);
  });

  it('9. Discord / OBS only → never enters', () => {
    const engine = new ScoringEngine();
    const result = engine.evaluate(
      { sessions: [session(20, 'discord.exe')], device_running_somewhere: false },
      {},
      t0 + 30_000,
    );
    expect(result.score).toBe(0);
    expect(result.is_in_meeting).toBe(false);
  });

  it('11. privacy kill-switch ends meeting', () => {
    const engine = new ScoringEngine();
    const snap = { sessions: [session(10, 'zoom.exe')], device_running_somewhere: false };
    engine.evaluate(snap, {}, t0);
    engine.evaluate(snap, {}, t0 + 10_000);
    const ended = engine.endByPrivacy();
    expect(ended.is_in_meeting).toBe(false);
    expect(ended.ended_by).toBe('privacy');
  });
});