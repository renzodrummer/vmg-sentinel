import { Injectable } from '@angular/core';
import { io, Socket } from 'socket.io-client';
import { environment } from '../environments/environment';
import {
  TIMETRACKER_SOCKET_EVENTS,
  type TimetrackerSocketEvent,
  formatTimetrackerStatus,
} from './constants/timetracker-socket.constants';
import type {
  ITimetrackerSocketPayload,
  ITimetrackerStatusNotice,
} from './models/timetracker-socket.interface';

export type SocketConnectionStatus =
  | 'disconnected'
  | 'connecting'
  | 'connected'
  | 'error';

export interface CitadelSocketConnectOptions {
  isElectron: boolean;
  actoToken: string;
  setAuthCookie?: (url: string, name: string, value: string) => Promise<void>;
}

@Injectable({
  providedIn: 'root',
})
export class CitadelSocketService {
  status: SocketConnectionStatus = 'disconnected';
  statusMessage = 'Not connected';
  lastEventName: string | null = null;
  lastEventPayload: string | null = null;
  lastEventAt: string | null = null;
  timetrackerState: ITimetrackerSocketPayload | null = null;
  statusNotice: ITimetrackerStatusNotice | null = null;

  private socket: Socket | null = null;
  private onChange: (() => void) | null = null;
  private eventHandlers = new Map<TimetrackerSocketEvent, (payload: unknown) => void>();

  setChangeListener(listener: () => void): void {
    this.onChange = listener;
  }

  async connect(options: CitadelSocketConnectOptions): Promise<void> {
    const actoToken = options.actoToken.trim();
    if (!actoToken) {
      this.setStatus('error', 'acto token is required');
      return;
    }

    if (this.socket?.connected) {
      return;
    }

    this.setStatus('connecting', 'Connecting to citadel-api…');

    if (options.setAuthCookie) {
      await options.setAuthCookie(
        environment.citadelApiUrl,
        environment.actoCookieName,
        actoToken,
      );
    } else if (options.isElectron) {
      this.setStatus('error', 'Electron cookie bridge unavailable');
      return;
    }

    if (this.socket) {
      this.setStatus('connecting', 'Reconnecting…');
      this.socket.connect();
      return;
    }

    this.socket = io(environment.citadelApiUrl, {
      withCredentials: true,
      auth: {
        clientType: options.isElectron ? 'electron' : 'web',
      },
      transports: ['polling', 'websocket'],
    });

    this.socket.on('connect', () => {
      this.setStatus('connected', `Connected (id: ${this.socket?.id ?? 'unknown'})`);
    });

    this.socket.on('disconnect', (reason) => {
      this.setStatus('disconnected', `Disconnected (${reason})`);
    });

    this.socket.on('connect_error', (error: Error) => {
      this.setStatus('error', error.message || 'Connection failed');
    });

    for (const eventName of TIMETRACKER_SOCKET_EVENTS) {
      const handler = (payload: unknown) => this.handleTimetrackerEvent(eventName, payload);
      this.eventHandlers.set(eventName, handler);
      this.socket.on(eventName, handler);
    }
  }

  disconnect(): void {
    if (!this.socket) {
      this.setStatus('disconnected', 'Not connected');
      return;
    }

    for (const [eventName, handler] of this.eventHandlers) {
      this.socket.off(eventName, handler);
    }
    this.eventHandlers.clear();

    this.socket.disconnect();
    this.socket = null;
    this.setStatus('disconnected', 'Disconnected');
  }

  private handleTimetrackerEvent(eventName: TimetrackerSocketEvent, payload: unknown): void {
    const parsed = this.parseTimetrackerPayload(payload);
    if (!parsed) {
      return;
    }

    const previousStatus = this.timetrackerState?.status;
    this.timetrackerState = parsed;
    this.lastEventName = eventName;
    this.lastEventAt = new Date().toLocaleTimeString();
    this.lastEventPayload = JSON.stringify(parsed, null, 2);

    const notice = this.buildStatusNotice(eventName, parsed, previousStatus);
    if (notice) {
      this.statusNotice = notice;
    }

    this.notifyChange();
  }

  private buildStatusNotice(
    eventName: TimetrackerSocketEvent,
    payload: ITimetrackerSocketPayload,
    previousStatus: string | undefined,
  ): ITimetrackerStatusNotice | null {
    const at = new Date().toLocaleTimeString();
    const statusLabel = formatTimetrackerStatus(payload.status);

    switch (eventName) {
      case 'timetracker:status_changed':
        return {
          event: eventName,
          at,
          status: payload.status,
          isTracking: payload.is_tracking,
          message: `Status changed to ${statusLabel}`,
        };
      case 'timetracker:started':
        return {
          event: eventName,
          at,
          status: payload.status,
          isTracking: payload.is_tracking,
          message: `Shift started — ${statusLabel}`,
        };
      case 'timetracker:stopped':
        return {
          event: eventName,
          at,
          status: payload.status,
          isTracking: payload.is_tracking,
          message: 'Shift stopped',
        };
      case 'timetracker:state':
        if (previousStatus && previousStatus !== payload.status) {
          return {
            event: eventName,
            at,
            status: payload.status,
            isTracking: payload.is_tracking,
            message: `Status updated to ${statusLabel}`,
          };
        }
        return null;
      default:
        return null;
    }
  }

  private parseTimetrackerPayload(payload: unknown): ITimetrackerSocketPayload | null {
    if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) {
      return null;
    }

    const record = payload as Partial<ITimetrackerSocketPayload>;
    if (typeof record.staff_id !== 'string' || typeof record.status !== 'string') {
      return null;
    }

    return record as ITimetrackerSocketPayload;
  }

  private setStatus(status: SocketConnectionStatus, message: string): void {
    this.status = status;
    this.statusMessage = message;
    this.notifyChange();
  }

  private notifyChange(): void {
    this.onChange?.();
  }
}
