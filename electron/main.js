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
} = require('electron');

const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const sharp = require('sharp');
const { Worker } = require('node:worker_threads');

let autoCaptureInterval = null;
let autoCaptureTimeout = null;

let writeStream = null;
let tempFilePath = null;
let recordingWidgetWindow = null;

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

async function executeSecureCapture() {
  try {
    const displays = screen.getAllDisplays();
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

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');

    await Promise.all(
      screens.map(async (source, index) => {
        try {
          let imgBuffer = source.thumbnail.toPNG();

          imgBuffer = await processImageInWorker(imgBuffer);

          const fileName = `screenshot-screen${index + 1}-${timestamp}.jpg`;
          const filePath = path.join(os.homedir(), fileName);

          await fs.promises.writeFile(filePath, imgBuffer);
          imgBuffer = null;
        } catch (processingError) {
          console.error(processingError);
        }
      }),
    );

    if (Notification.isSupported()) {
      new Notification({
        title: 'Screens Captured',
        body: 'Secure screenshots of all monitors were recorded.',
        icon: path.join(__dirname, 'assets/camera.ico'),
      }).show();
    }
  } catch (error) {
    console.error(error);
  }
}

app.whenReady().then(() => {
  const window = new BrowserWindow({
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js'),
    },
    frame: false,
    show: false,
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
      label: 'Quit',
      click: () => {
        app.quit();
      },
    },
  ];

  const contextMenu = Menu.buildFromTemplate(menuTemplate);
  tray.setContextMenu(contextMenu);

  window.loadFile(path.join(__dirname, '../dist/sentinel/browser/index.html'));

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
  });

  ipcMain.handle('get-screen-count', () => {
    return screen.getAllDisplays().length;
  });

  // multi screen capture

  ipcMain.on('capture-multi-screen', async (event) => {
    const displays = screen.getAllDisplays();
    const maxWidth = Math.max(...displays.map((d) => d.size.width));
    const maxHeight = Math.max(...displays.map((d) => d.size.height));

    const screens = await desktopCapturer.getSources({
      types: ['screen'],
      thumbnailSize: { width: maxWidth, height: maxHeight },
      fetchWindowIcons: false,
    });

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');

    await Promise.all(
      screens.map(async (source, index) => {
        let imgBuffer = source.thumbnail.toPNG();
        try {
          imgBuffer = await processImageInWorker(imgBuffer);

          const fileName = `screenshot-screen${index + 1}-${timestamp}.jpg`;
          const filePath = path.join(os.homedir(), fileName);

          await fs.promises.writeFile(filePath, imgBuffer);
          shell.openExternal(`file://${filePath}`);
          imgBuffer = null;
        } catch (processingError) {
          console.error(`Failed to process image:`, processingError);
        }
      }),
    );
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
