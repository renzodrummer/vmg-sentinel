const { parentPort } = require('node:worker_threads');
const sharp = require('sharp');

parentPort.on('message', async (message) => {
  try {
    const { buffer } = message;

    const processedBuffer = await sharp(buffer).blur(15).jpeg({ quality: 80 }).toBuffer();

    parentPort.postMessage({ success: true, buffer: processedBuffer });
  } catch (error) {
    parentPort.postMessage({ success: false, error: error.message });
  }
});
