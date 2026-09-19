const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  captureScreen: () => ipcRenderer.send('capture-screen'),
  startAutoCapture: (intervalMinutes) => ipcRenderer.send('start-auto-capture', intervalMinutes),
  stopAutoCapture: () => ipcRenderer.send('stop-auto-capture'),
  getScreenCount: () => ipcRenderer.invoke('get-screen-count'),
  setAuthCookie: (url, name, value) => ipcRenderer.invoke('set-auth-cookie', url, name, value),

  captureMultiScreen: () => ipcRenderer.send('capture-multi-screen'),

  captureActiveScreen: () => ipcRenderer.send('capture-active-screen'),

  getVideoSources: () => ipcRenderer.invoke('getSources'),
  getOperatingSystem: () => ipcRenderer.invoke('getOperatingSystem'),
  startRecordingStream: () => ipcRenderer.invoke('startRecording'),
  saveVideoChunk: (arrayBuffer) => ipcRenderer.send('saveChunk', arrayBuffer),
  stopAndSaveRecording: () => ipcRenderer.invoke('stopRecordingAndSave'),
  onMeetingState: (callback) => {
    const listener = (_event, state) => callback(state);
    ipcRenderer.on('meeting:state', listener);
    return () => ipcRenderer.removeListener('meeting:state', listener);
  },
  getPolicyStatus: () => ipcRenderer.invoke('policy:get-status'),
  setCitadelWorkSession: (payload) => ipcRenderer.invoke('policy:set-citadel-session', payload),
  refreshCitadelPolicy: (payload) => ipcRenderer.invoke('policy:refresh-citadel', payload),
  onPolicyStatus: (callback) => {
    const listener = (_event, status) => callback(status);
    ipcRenderer.on('policy:status', listener);
    return () => ipcRenderer.removeListener('policy:status', listener);
  },
});
