const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');

const MAX_FRAME = 1_048_576;
const EXPECTED_HELPER_BUILD = 'fw-1';
const HELPER_SERVICE_NAME = 'VMGSentinelHelper';

function connectPath({ pipeName, storeDir }) {
  if (process.platform === 'win32') {
    return `\\\\.\\pipe\\${pipeName}`;
  }
  return path.join(storeDir, 'helper.sock');
}

function encodeFrame(payload) {
  const body = Buffer.from(payload);
  const header = Buffer.alloc(4);
  header.writeUInt32LE(body.length, 0);
  return Buffer.concat([header, body]);
}

function decodeResponse(buf) {
  if (buf.length < 4) {
    throw new Error('short frame');
  }
  const len = buf.readUInt32LE(0);
  if (len > MAX_FRAME) {
    throw new Error('frame too large');
  }
  return JSON.parse(buf.subarray(4, 4 + len).toString('utf8'));
}

function defaultHelperPath(isPackaged = false, resourcesPath = process.resourcesPath) {
  const exe =
    process.platform === 'win32' ? 'vmg-sentinel-helper.exe' : 'vmg-sentinel-helper';
  if (isPackaged) {
    return path.join(resourcesPath, 'policy-helper', exe);
  }
  const helperRoot = path.join(__dirname, '../../native/policy-helper');
  const pinned = path.join(helperRoot, 'bin', exe);
  if (fs.existsSync(pinned)) {
    return pinned;
  }
  const rebuild = path.join(helperRoot, 'target/rebuild/release', exe);
  if (fs.existsSync(rebuild)) {
    return rebuild;
  }
  return path.join(helperRoot, 'target/release', exe);
}

class PolicyHelperClient {
  constructor({
    pipeName = 'vmg-sentinel-helper',
    helperPath,
    storeDir,
  } = {}) {
    this.pipeName = pipeName;
    this.helperPath = helperPath;
    this.storeDir = storeDir || path.join(os.tmpdir(), 'vmg-sentinel-policy-helper');
    this.nextId = 1;
    this.child = null;
  }

  start() {
    if (!this.helperPath || !fs.existsSync(this.helperPath)) {
      return false;
    }
    this.child = spawn(
      this.helperPath,
      ['--store-dir', this.storeDir, '--pipe-name', this.pipeName],
      { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true },
    );
    this.child.stderr?.on('data', (buf) => {
      console.log('[policy-helper]', buf.toString().trim());
    });
    this.child.on('exit', (code) => {
      console.log('[policy-helper] exit', code);
      this.child = null;
    });
    return true;
  }

  /** Only kills a helper this process spawned. Never stops the LocalSystem service. */
  stop() {
    if (!this.child) {
      return;
    }
    this.child.kill();
    this.child = null;
  }

  isCurrentBuild(status) {
    const result = status?.result ?? status ?? {};
    return result.helper_build === EXPECTED_HELPER_BUILD;
  }

  call(method, params = {}, timeoutMs = 5000) {
    const id = this.nextId++;
    const request = JSON.stringify({ id, method, params });
    return new Promise((resolve, reject) => {
      const socket = net.connect(connectPath(this));
      let buf = Buffer.alloc(0);
      let settled = false;
      const finish = (error, value) => {
        if (settled) {
          return;
        }
        settled = true;
        socket.destroy();
        if (error) {
          reject(error);
        } else {
          resolve(value);
        }
      };
      socket.setTimeout(timeoutMs);
      socket.on('timeout', () => finish(new Error('policy-helper timeout')));
      socket.on('error', (error) => finish(error));
      socket.on('data', (chunk) => {
        buf = Buffer.concat([buf, chunk]);
        if (buf.length < 4) {
          return;
        }
        const len = buf.readUInt32LE(0);
        if (len > MAX_FRAME || buf.length < 4 + len) {
          if (len > MAX_FRAME) {
            finish(new Error('frame too large'));
          }
          return;
        }
        try {
          finish(null, JSON.parse(buf.subarray(4, 4 + len).toString('utf8')));
        } catch (error) {
          finish(error);
        }
      });
      socket.on('connect', () => {
        socket.write(encodeFrame(request));
      });
    });
  }

  async getStatusWithRetry(attempts = 20, delayMs = 100) {
    let lastError;
    for (let i = 0; i < attempts; i += 1) {
      try {
        return await this.getStatus();
      } catch (error) {
        lastError = error;
        await new Promise((resolve) => setTimeout(resolve, delayMs));
      }
    }
    throw lastError;
  }

  getStatus() {
    return this.call('GetStatus');
  }

  applyPolicy(document) {
    return this.call('ApplyPolicy', { document }, 30_000);
  }

  setSession(active, reason) {
    return this.call(
      'SetSession',
      { active: !!active, reason: reason || 'unspecified' },
      30_000,
    );
  }

  getRecentBlocks(since) {
    return this.call('GetRecentBlocks', since ? { since } : {});
  }

  reportTamper(kind, detail) {
    return this.call('ReportTamper', { kind, detail });
  }
}

module.exports = {
  PolicyHelperClient,
  encodeFrame,
  decodeResponse,
  defaultHelperPath,
  connectPath,
  EXPECTED_HELPER_BUILD,
  HELPER_SERVICE_NAME,
};
