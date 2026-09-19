import {
  shouldApplyLocalDevPolicy,
  shouldSpawnHelper,
  createDefaultWorkPolicy,
} from './dev-block-policy.js';

describe('dev-block-policy safety gates', () => {
  it('applies the local deny list for packaged and unpackaged builds', () => {
    expect(shouldApplyLocalDevPolicy({ isPackaged: true, env: {} })).toBe(true);
    expect(shouldApplyLocalDevPolicy({ isPackaged: false, env: {} })).toBe(true);
    expect(
      shouldApplyLocalDevPolicy({ isPackaged: true, env: { VMG_SENTINEL_DEV_POLICY: '0' } }),
    ).toBe(false);
  });

  it('does not spawn the helper when packaged or on Windows', () => {
    expect(shouldSpawnHelper({ isPackaged: true, env: {}, platform: 'win32' })).toBe(false);
    expect(shouldSpawnHelper({ isPackaged: false, env: {}, platform: 'win32' })).toBe(false);
    expect(shouldSpawnHelper({ isPackaged: false, env: {}, platform: 'darwin' })).toBe(true);
    expect(
      shouldSpawnHelper({
        isPackaged: false,
        env: { VMG_SENTINEL_SPAWN_HELPER: '1' },
        platform: 'win32',
      }),
    ).toBe(true);
  });

  it('signs the local policy in block mode', () => {
    const policy = createDefaultWorkPolicy();
    expect(policy.mode).toBe('block');
    expect(policy.signature).toMatch(/^[0-9a-f]+$/);
  });
});
