import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import {
  PolicyHelperClient,
  encodeFrame,
  decodeResponse,
  connectPath,
  defaultHelperPath,
  EXPECTED_HELPER_BUILD,
} from './policy-helper-client.js';

function listenMock(handler) {
  const pipeName = `vmg-sentinel-test-${process.pid}-${Date.now()}`;
  const storeDir = os.tmpdir();
  const listenTarget = connectPath({ pipeName, storeDir });
  const server = net.createServer((socket) => {
    let buf = Buffer.alloc(0);
    socket.on('data', (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      if (buf.length < 4) {
        return;
      }
      const len = buf.readUInt32LE(0);
      if (buf.length < 4 + len) {
        return;
      }
      const req = JSON.parse(buf.subarray(4, 4 + len).toString('utf8'));
      socket.write(encodeFrame(JSON.stringify(handler(req))));
    });
  });
  return new Promise((resolve) => {
    server.listen(listenTarget, () => {
      resolve({
        pipeName,
        storeDir,
        close: () => new Promise((done) => server.close(done)),
      });
    });
  });
}

describe('policy-helper-client', () => {
  it('GetStatus round-trips over framed JSON', async () => {
    const mock = await listenMock((req) => ({
      id: req.id,
      ok: true,
      result: { policy_loaded: false, enforcement: 'none' },
    }));
    const client = new PolicyHelperClient({
      pipeName: mock.pipeName,
      storeDir: mock.storeDir,
    });
    const res = await client.getStatus();
    expect(res.ok).toBe(true);
    expect(res.result.enforcement).toBe('none');
    await mock.close();
  });

  it('surfaces UNAUTHENTICATED when the helper rejects ApplyPolicy', async () => {
    const mock = await listenMock((req) => ({
      id: req.id,
      ok: false,
      error: { code: 'UNAUTHENTICATED', message: 'unauthenticated' },
    }));
    const client = new PolicyHelperClient({
      pipeName: mock.pipeName,
      storeDir: mock.storeDir,
    });
    const res = await client.applyPolicy({ version: 1 });
    expect(res.ok).toBe(false);
    expect(res.error.code).toBe('UNAUTHENTICATED');
    await mock.close();
  });

  it('never sends RunCommand', () => {
    expect(Object.getOwnPropertyNames(PolicyHelperClient.prototype)).not.toContain(
      'runCommand',
    );
  });

  it('decodeResponse reads the length prefix', () => {
    const payload = encodeFrame(JSON.stringify({ id: 1, ok: true, result: {} }));
    expect(decodeResponse(payload)).toEqual({ id: 1, ok: true, result: {} });
  });

  it('packaged helper path is extraResources/policy-helper', () => {
    const packaged = defaultHelperPath(true, path.join('C:', 'Sentinel', 'resources'));
    expect(packaged.replaceAll('\\', '/')).toContain('resources/policy-helper/vmg-sentinel-helper');
  });

  it('accepts the current helper build and rejects older ones', () => {
    const client = new PolicyHelperClient();
    expect(client.isCurrentBuild({ result: { helper_build: EXPECTED_HELPER_BUILD } })).toBe(true);
    expect(client.isCurrentBuild({ result: { helper_build: 'wfp-old' } })).toBe(false);
    expect(client.isCurrentBuild({ result: {} })).toBe(false);
  });

  it('connectPath uses a named pipe on Windows', () => {
    const target = connectPath({ pipeName: 'vmg-sentinel-helper', storeDir: path.sep });
    if (process.platform === 'win32') {
      expect(target).toBe('\\\\.\\pipe\\vmg-sentinel-helper');
    } else {
      expect(target).toContain('helper.sock');
    }
  });
});
