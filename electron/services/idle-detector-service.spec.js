import { describe, expect, it } from 'vitest';
import { IdleDetectorService, MEETING_IDLE_CAP_SEC } from './idle-detector-service.js';

describe('IdleDetectorService meeting cap', () => {
  it('10. 120-minute idle on call ends the pause', () => {
    let idleSec = 10;
    let idleFired = false;
    const service = new IdleDetectorService({
      thresholdSec: 60,
      getIdleTime: () => idleSec,
      onIdle: () => {
        idleFired = true;
      },
    });

    service.pauseForMeeting();
    idleSec = MEETING_IDLE_CAP_SEC;
    service.tick();
    expect(service.paused).toBe(false);
    expect(idleFired).toBe(true);
  });
});