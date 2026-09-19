const fs = require('node:fs');
const path = require('node:path');

class MeetingLog {
  constructor(filePath) {
    this.filePath = filePath;
    this.closed = false;
  }

  writeTransition(entry) {
    if (this.closed) return;
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    fs.appendFileSync(this.filePath, `${JSON.stringify(entry)}\n`);
  }

  close() {
    this.closed = true;
  }

  open() {
    this.closed = false;
  }
}

module.exports = { MeetingLog };