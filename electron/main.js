const {
  app,
  BrowserWindow,
  ipcMain,
  screen,
  desktopCapturer,
  shell,
  Tray,
  Menu,
  Notification,
  dialog,
  session,
  powerMonitor,
} = require('electron');

const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const sharp = require('sharp');
const { Worker } = require('node:worker_threads');
const { IdleDetectorService } = require('./services/idle-detector-service');
const { MeetingDetectorService } = require('./services/meeting-detector-service');
const {
  PolicyHelperClient,
  defaultHelperPath,
  EXPECTED_HELPER_BUILD,
  HELPER_SERVICE_NAME,
} = require('./services/policy-helper-client');
const {
  createDefaultWorkPolicy,
  shouldApplyLocalDevPolicy,
  shouldSpawnHelper,
} = require('./services/dev-block-policy');
const { fetchCitadelPolicy } = require('./services/policy-fetch');
const { isWorkSessionActive, workSessionReason } = require('./services/work-session');

const trustedDevHostnames = [
  'admin-api-local.vmg-portal.com',
  'citadel-api-local.vmg-portal.com',
  'citadel-api-dev.vmg-portal.com',
  'admin-local.vmg-portal.com',
];

if (!app.isPackaged) {
  // Required for WebSocket (wss://) — certificate-error alone does not cover it.
  app.commandLine.appendSwitch('ignore-certificate-errors');

  app.on('certificate-error', (event, _webContents, url, _error, _certificate, callback) => {
    const isTrusted = trustedDevHostnames.some((hostname) => url.includes(hostname));
    if (isTrusted) {
      event.preventDefault();
      callback(true);
      return;
    }
    callback(false);
  });
}

let autoCaptureInterval = null;
let autoCaptureTimeout = null;

let writeStream = null;
let tempFilePath = null;
let recordingWidgetWindow = null;

function toggleDevTools(browserWindow) {
  if (!browserWindow?.webContents) {
    return;
  }

  if (browserWindow.webContents.isDevToolsOpened()) {
    browserWindow.webContents.closeDevTools();
  } else {
    browserWindow.webContents.openDevTools({ mode: 'detach' });
  }
}

function processImageInWorker(imgBuffer) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(path.join(__dirname, 'image-worker.js'));

    worker.on('message', (msg) => {
      worker.terminate();
      if (msg.success) {
        resolve(msg.buffer);
      } else {
        reject(new Error(msg.error));
      }
    });

    worker.on('error', reject);
    worker.postMessage({ buffer: imgBuffer });
  });
}

async function captureAllDisplaysAsSingleImage() {
  const BLUR_AMOUNT = 15;
  const JPEG_QUALITY = 80;

  const displays = screen.getAllDisplays();

  if (displays.length === 0) {
    throw new Error('No displays detected');
  }

  const maxWidth = Math.max(...displays.map((d) => d.size.width));
  const maxHeight = Math.max(...displays.map((d) => d.size.height));

  const screens = await desktopCapturer.getSources({
    types: ['screen'],
    thumbnailSize: {
      width: maxWidth,
      height: maxHeight,
    },
    fetchWindowIcons: false,
  });

  const minX = Math.min(...displays.map((d) => d.bounds.x));
  const minY = Math.min(...displays.map((d) => d.bounds.y));
  const maxX = Math.max(...displays.map((d) => d.bounds.x + d.bounds.width));
  const maxY = Math.max(...displays.map((d) => d.bounds.y + d.bounds.height));
  const totalWidth = maxX - minX;
  const totalHeight = maxY - minY;

  const compositeInputs = [];

  for (const display of displays) {
    const source =
      screens.find((s) => s.display_id === display.id.toString()) ??
      screens[displays.indexOf(display)];

    if (!source) {
      console.warn(`No capture source found for display ${display.id}`);
      continue;
    }

    let imgBuffer = source.thumbnail.toPNG();

    imgBuffer = await sharp(imgBuffer)
      .resize(display.bounds.width, display.bounds.height, { fit: 'fill' })
      .png()
      .toBuffer();

    compositeInputs.push({
      input: imgBuffer,
      left: display.bounds.x - minX,
      top: display.bounds.y - minY,
    });
  }

  if (compositeInputs.length === 0) {
    throw new Error('Failed to capture any display');
  }

  const compositedBuffer = await sharp({
    create: {
      width: totalWidth,
      height: totalHeight,
      channels: 3,
      background: { r: 0, g: 0, b: 0 },
    },
  })
    .composite(compositeInputs)
    .png()
    .toBuffer();
  const mergedBuffer = await sharp(compositedBuffer)
    .blur(BLUR_AMOUNT)
    .jpeg({ quality: JPEG_QUALITY })
    .toBuffer();

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const fileName = `screenshot-all-${timestamp}.jpg`;
  const filePath = path.join(os.homedir(), fileName);

  await fs.promises.writeFile(filePath, mergedBuffer);

  return filePath;
}
async function executeSecureCapture() {
  try {
    await captureAllDisplaysAsSingleImage();
    if (Notification.isSupported()) {
      new Notification({
        title: 'Screens Captured',
        body: 'Secure screenshot of all monitors was saved as one file.',
        icon: path.join(__dirname, 'assets/camera.ico'),
      }).show();
    }
  } catch (error) {
    console.error(error);
  }
}

app.whenReady().then(() => {
  if (!app.isPackaged) {
    session.defaultSession.setCertificateVerifyProc((request, callback) => {
      if (trustedDevHostnames.includes(request.hostname)) {
        callback(0);
        return;
      }
      callback(-2);
    });
  }

  const window = new BrowserWindow({
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js'),
      devTools: true,
    },
    frame: false,
    show: false,
  });

  const idleDetector = new IdleDetectorService({
    thresholdSec: 60,
    onIdle: () => window.webContents.send('idle:state', { is_idle: true }),
    onActive: () => window.webContents.send('idle:state', { is_idle: false }),
  });
  
  const meetingDetector = new MeetingDetectorService({
    idleDetector,
    logPath: path.join(app.getPath('userData'), 'meeting-log.jsonl'),
    onState: (state) => {
      if (!window.isDestroyed()) {
        window.webContents.send('meeting:state', state);
      }
    },
  });

  const policyHelper = new PolicyHelperClient({
    helperPath: defaultHelperPath(app.isPackaged, process.resourcesPath),
    storeDir: path.join(app.getPath('userData'), 'policy-helper'),
    pipeName: 'vmg-sentinel-helper',
  });
  let localTracking = false;
  let citadelSession = null;
  let lastPolicyStatus = null;

  async function pushWorkSession() {
    const active = isWorkSessionActive({ localTracking, citadel: citadelSession });
    const reason = workSessionReason({ localTracking, citadel: citadelSession });
    try {
      await applyLocalDevPolicyIfNeeded();
      const response = await policyHelper.setSession(active, reason);
      lastPolicyStatus = response.result ?? response;
      if (!window.isDestroyed()) {
        window.webContents.send('policy:status', lastPolicyStatus);
      }
    } catch (error) {
      console.warn('[policy-helper] SetSession failed', error.message);
    }
  }

  async function applyLocalDevPolicyIfNeeded(_status) {
    if (!shouldApplyLocalDevPolicy({ isPackaged: app.isPackaged })) {
      return;
    }
    try {
      const current = (await policyHelper.getStatus()).result;
      if (current?.policy_loaded) {
        return;
      }
    } catch {
      // Helper may not be ready; ApplyPolicy will fail loudly if so.
    }
    const applied = await policyHelper.applyPolicy(createDefaultWorkPolicy());
    if (applied && applied.ok === false) {
      throw new Error(applied.error?.message || 'ApplyPolicy failed');
    }
    console.log('[policy-helper] applied local deny-list policy');
  }

  async function attachPolicyHelper() {
    const helperPath = defaultHelperPath(app.isPackaged, process.resourcesPath);
    try {
      const existing = await policyHelper.getStatusWithRetry(30, 200);
      console.log('[policy-helper] attached to existing helper', existing);
      const result = existing?.result ?? existing ?? {};
      if (result.privilege === 'user') {
        console.warn(
          '[policy-helper] attached to a user-level helper; the LocalSystem service is not on the pipe',
        );
      }
      if (!policyHelper.isCurrentBuild(existing)) {
        const last_error = app.isPackaged
          ? `Old helper is on the pipe (build ${result.helper_build || 'unknown'}). Reinstall Sentinel so ${HELPER_SERVICE_NAME} is updated to ${EXPECTED_HELPER_BUILD}.`
          : `Old helper is on the pipe (build ${result.helper_build || 'unknown'}). Stop ${HELPER_SERVICE_NAME} / end vmg-sentinel-helper.exe, then run "${helperPath}" --install`;
        console.warn(`[policy-helper] ${last_error}`);
        lastPolicyStatus = { ...result, last_error, needs_service: true };
        if (!window.isDestroyed()) {
          window.webContents.send('policy:status', lastPolicyStatus);
        }
        return;
      }
      await applyLocalDevPolicyIfNeeded(existing);
      lastPolicyStatus = (await policyHelper.getStatus()).result ?? result;
      if (!window.isDestroyed()) {
        window.webContents.send('policy:status', lastPolicyStatus);
      }
      return;
    } catch {
      // Helper is not running yet.
    }
    if (!shouldSpawnHelper({ isPackaged: app.isPackaged })) {
      const last_error = app.isPackaged
        ? `${HELPER_SERVICE_NAME} is not running. Reinstall Sentinel (per-machine) so the installer can register the policy helper.`
        : `${HELPER_SERVICE_NAME} is not on the pipe. From an elevated prompt run: "${helperPath}" --install`;
      console.warn(`[policy-helper] ${last_error}`);
      lastPolicyStatus = {
        enforcing: false,
        session_active: false,
        needs_service: true,
        privilege: 'user',
        last_error,
      };
      if (!window.isDestroyed()) {
        window.webContents.send('policy:status', lastPolicyStatus);
      }
      return;
    }
    if (!policyHelper.start()) {
      console.warn('[policy-helper] binary missing; GetStatus will fail until it is built');
      return;
    }
    try {
      const status = await policyHelper.getStatusWithRetry();
      console.log('[policy-helper] status', status);
      await applyLocalDevPolicyIfNeeded(status);
    } catch (error) {
      console.warn('[policy-helper] unavailable', error.message);
    }
  }

  async function cookieHeaderFor(url) {
    try {
      const cookies = await session.defaultSession.cookies.get({ url });
      return cookies.map((cookie) => `${cookie.name}=${cookie.value}`).join('; ');
    } catch {
      return '';
    }
  }

  async function refreshCitadelPolicy(apiUrl) {
    if (!apiUrl) {
      return { ok: false, code: 'POLICY_FETCH_FAILED', message: 'missing api url' };
    }
    const result = await fetchCitadelPolicy({
      apiUrl,
      cookieHeader: await cookieHeaderFor(apiUrl),
    });
    if (result.ok) {
      await policyHelper.applyPolicy(result.policy);
    } else {
      await applyLocalDevPolicyIfNeeded();
    }
    lastPolicyStatus = (await policyHelper.getStatus()).result ?? lastPolicyStatus;
    if (!window.isDestroyed()) {
      window.webContents.send('policy:status', lastPolicyStatus);
    }
    return result;
  }

  void attachPolicyHelper();
  let sessionClearedOnQuit = false;
  app.on('before-quit', (event) => {
    if (sessionClearedOnQuit) {
      return;
    }
    event.preventDefault();
    sessionClearedOnQuit = true;
    localTracking = false;
    policyHelper
      .setSession(false, 'app-quit')
      .catch((error) => {
        console.warn('[policy-helper] SetSession(false) on quit failed', error.message);
      })
      .finally(() => {
        policyHelper.stop();
        app.quit();
      });
  });

  window.webContents.on('before-input-event', (_event, input) => {
    if (input.type === 'keyDown' && input.key === 'F12') {
      toggleDevTools(window);
    }
  });

  const iconPath = path.join(__dirname, 'assets/camera.ico');
  const tray = new Tray(iconPath);
  tray.on('click', () => {
    if (window.isVisible()) {
      window.hide();
    } else {
      window.show();
    }
  });

  const menuTemplate = [
    {
      label: 'Toggle Developer Tools',
      click: () => toggleDevTools(window),
    },
    { type: 'separator' },
    {
      label: 'Quit',
      click: () => {
        app.quit();
      },
    },
  ];

  const contextMenu = Menu.buildFromTemplate(menuTemplate);
  tray.setContextMenu(contextMenu);

  window.loadFile(path.join(__dirname, '../dist/sentinel/browser/index.html'));

  window.webContents.once('did-finish-load', () => {
    if (!app.isPackaged) {
      window.webContents.openDevTools({ mode: 'detach' });
    }
  });

  ipcMain.on('capture-screen', async () => {
    await executeSecureCapture();
  });

  ipcMain.on('start-auto-capture', (event, intervalMinutes) => {
    if (typeof intervalMinutes !== 'number' || intervalMinutes < 1 || intervalMinutes > 1440) {
      console.warn('Security Block: Invalid interval provided for auto-capture.');
      return;
    }

    const intervalMs = intervalMinutes * 60 * 1000;

    executeSecureCapture();

    idleDetector.start();
    meetingDetector.start();
    localTracking = true;
    void pushWorkSession();

    autoCaptureInterval = setInterval(() => {
      const randomDelayMs = Math.floor(Math.random() * intervalMs);

      autoCaptureTimeout = setTimeout(() => {
        executeSecureCapture();
      }, randomDelayMs);
    }, intervalMs);
  });

  ipcMain.on('stop-auto-capture', () => {
    if (autoCaptureInterval) {
      clearInterval(autoCaptureInterval);
      autoCaptureInterval = null;
    }
    if (autoCaptureTimeout) {
      clearTimeout(autoCaptureTimeout);
      autoCaptureTimeout = null;
    }
    meetingDetector.stop({ reason: 'privacy' });
    idleDetector.stop();
    localTracking = false;
    void pushWorkSession();
  });

  ipcMain.handle('get-screen-count', () => {
    return screen.getAllDisplays().length;
  });

  ipcMain.handle('policy:get-status', async () => {
    try {
      const response = await policyHelper.getStatus();
      lastPolicyStatus = response.result ?? response;
      return lastPolicyStatus;
    } catch (error) {
      return lastPolicyStatus ?? {
        last_error: error.message,
        enforcing: false,
        session_active: false,
        needs_service: true,
      };
    }
  });

  ipcMain.handle('policy:set-citadel-session', async (_event, payload) => {
    citadelSession = payload && typeof payload === 'object' ? payload : null;
    await pushWorkSession();
    return lastPolicyStatus;
  });

  ipcMain.handle('policy:refresh-citadel', async (_event, payload) => {
    const apiUrl = payload && typeof payload.apiUrl === 'string' ? payload.apiUrl : '';
    return refreshCitadelPolicy(apiUrl);
  });

  ipcMain.handle('set-auth-cookie', async (_event, url, name, value) => {
    if (typeof url !== 'string' || typeof name !== 'string' || typeof value !== 'string') {
      throw new Error('Invalid cookie parameters');
    }

    await session.defaultSession.cookies.set({
      url,
      name,
      value,
      secure: url.startsWith('https'),
      httpOnly: true,
      sameSite: 'no_restriction',
    });
  });

  // multi screen capture

  ipcMain.on('capture-multi-screen', async () => {
    try {
      const filePath = await captureAllDisplaysAsSingleImage();
      shell.openExternal(`file://${filePath}`);
    } catch (error) {
      console.error('Failed to capture all screens:', error);
    }
  });

  // active screen
  ipcMain.on('capture-active-screen', async (event) => {
    try {
      const cursorPoint = screen.getCursorScreenPoint();
      const activeDisplay = screen.getDisplayNearestPoint(cursorPoint);

      const screens = await desktopCapturer.getSources({
        types: ['screen'],
        thumbnailSize: {
          width: activeDisplay.size.width,
          height: activeDisplay.size.height,
        },
        fetchWindowIcons: false,
      });

      let activeSource = screens.find(
        (source) => source.display_id === activeDisplay.id.toString(),
      );

      if (!activeSource) {
        activeSource = screens[0];
      }

      let imgBuffer = activeSource.thumbnail.toPNG();
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');

      imgBuffer = await processImageInWorker(imgBuffer);

      const fileName = `screenshot-active-${timestamp}.jpg`;
      const filePath = path.join(os.homedir(), fileName);

      await fs.promises.writeFile(filePath, imgBuffer);
      shell.openExternal(`file://${filePath}`);
      imgBuffer = null;
    } catch (error) {
      console.error('Failed to process/blur the active screen:', error);
    }
  });

  // screen recording

  ipcMain.handle('getSources', async () => {
    return await desktopCapturer.getSources({ types: ['window', 'screen'] });
  });

  ipcMain.handle('getOperatingSystem', () => {
    return process.platform;
  });

  ipcMain.handle('startRecording', () => {
    tempFilePath = path.join(app.getPath('temp'), `temp-record-${Date.now()}.webm`);
    writeStream = fs.createWriteStream(tempFilePath);

    return true;
  });

  const MAX_CHUNK_SIZE = 50 * 1024 * 1024;

  ipcMain.on('saveChunk', (event, arrayBuffer) => {
    if (!arrayBuffer || arrayBuffer.byteLength > MAX_CHUNK_SIZE) {
      console.warn('Security Block: Video chunk exceeds maximum allowed size or is invalid.');
      return;
    }

    if (writeStream) {
      writeStream.write(Buffer.from(arrayBuffer));
    }
  });

  ipcMain.handle('stopRecordingAndSave', async () => {
    if (writeStream) {
      writeStream.end();
      writeStream = null;
    }

    if (!tempFilePath || !fs.existsSync(tempFilePath)) {
      return false;
    }

    const { canceled, filePath } = await dialog.showSaveDialog({
      buttonLabel: 'Save video',
      defaultPath: `vid-${Date.now()}.webm`,
    });

    if (!canceled && filePath) {
      fs.copyFileSync(tempFilePath, filePath);
      fs.unlinkSync(tempFilePath);
      tempFilePath = null;
      return true;
    } else {
      fs.unlinkSync(tempFilePath);
      tempFilePath = null;
      return false;
    }
  });
});
