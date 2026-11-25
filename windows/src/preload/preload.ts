// Preload bridge. The page gets exactly these functions on window.v18, and nothing else:
// no Node, no ipcRenderer, no file access. Each call goes to one fixed channel.

import { contextBridge, ipcRenderer } from 'electron';

const INVOKE = [
  'v18:get-view',
  'v18:first-run',
  'v18:go',
  'v18:start-link',
  'v18:cancel-link',
  'v18:start-connector',
  'v18:cancel-connect',
  'v18:connect-reopen',
  'v18:load-catalog',
  'v18:test-card',
  'v18:delete-card',
  'v18:settings',
  'v18:dismiss-notice',
  'v18:refresh-server',
  'v18:aadhaar-pick',
  'v18:aadhaar-build',
  'v18:aadhaar-cancel',
  'v18:aadhaar-reset',
  'v18:delete-proof-files',
  'v18:ask-approve',
  'v18:ask-phone',
  'v18:ask-back',
  'v18:ask-retry',
  'v18:ask-close',
  'v18:ask-get-card',
  'v18:open-main',
  'v18:open-hello-settings',
] as const;
type Channel = (typeof INVOKE)[number];

const api = {
  invoke(channel: Channel, arg?: string | boolean | Record<string, string | number | boolean>): Promise<unknown> {
    if (!(INVOKE as readonly string[]).includes(channel)) return Promise.reject(new Error('channel not allowed'));
    return ipcRenderer.invoke(channel, arg);
  },
  onView(cb: (view: unknown) => void): void {
    ipcRenderer.removeAllListeners('v18:view');
    ipcRenderer.on('v18:view', (_e, view) => cb(view));
  },
};

contextBridge.exposeInMainWorld('v18', api);
export type V18Bridge = typeof api;
