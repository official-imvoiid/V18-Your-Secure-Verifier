// Renders the V18 shield logo to PNGs and packs them into an .ico.
// Run with: npx electron scripts/make-icons.cjs
const { app, BrowserWindow } = require('electron');
const fs = require('node:fs');
const path = require('node:path');

const SIZES = [16, 20, 24, 32, 40, 48, 64, 128, 256];
const svg = (px) => `<svg xmlns="http://www.w3.org/2000/svg" width="${px}" height="${px}" viewBox="0 0 24 24">
<path fill="#2F5BD3" d="M12 1.4l8.8 3.5v6.7c0 5.4-3.7 9.6-8.8 11.3-5.1-1.7-8.8-5.9-8.8-11.3V4.9z"/>
<path fill="none" stroke="#FFFFFF" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" d="M8.1 12.2l2.8 2.8 5.1-5.6"/></svg>`;

async function renderBig() {
  const px = 256;
  const win = new BrowserWindow({ width: px, height: px, show: false, transparent: true, frame: false, useContentSize: true, webPreferences: { offscreen: true } });
  const page = `<html><body style="margin:0;background:transparent;overflow:hidden">${svg(px)}</body></html>`;
  await win.loadURL('data:text/html;base64,' + Buffer.from(page).toString('base64'));
  await new Promise((r) => setTimeout(r, 500));
  const img = await win.webContents.capturePage({ x: 0, y: 0, width: px, height: px });
  win.destroy();
  return img;
}

function ico(pngs) {
  const head = Buffer.alloc(6 + 16 * pngs.length);
  head.writeUInt16LE(0, 0); head.writeUInt16LE(1, 2); head.writeUInt16LE(pngs.length, 4);
  let offset = head.length;
  pngs.forEach(({ px, png }, i) => {
    const e = 6 + 16 * i;
    head.writeUInt8(px >= 256 ? 0 : px, e); head.writeUInt8(px >= 256 ? 0 : px, e + 1);
    head.writeUInt8(0, e + 2); head.writeUInt8(0, e + 3); head.writeUInt16LE(1, e + 4); head.writeUInt16LE(32, e + 6);
    head.writeUInt32LE(png.length, e + 8); head.writeUInt32LE(offset, e + 12);
    offset += png.length;
  });
  return Buffer.concat([head, ...pngs.map((p) => p.png)]);
}

app.disableHardwareAcceleration();
app.whenReady().then(async () => {
  const root = path.resolve(__dirname, '..');
  const pngs = [];
  const big = await renderBig();
  for (const px of SIZES) pngs.push({ px, png: px === 256 ? big.toPNG() : big.resize({ width: px, height: px, quality: 'best' }).toPNG() });
  fs.mkdirSync(path.join(root, 'assets'), { recursive: true });
  fs.mkdirSync(path.join(root, 'build'), { recursive: true });
  const icoBuf = ico(pngs);
  fs.writeFileSync(path.join(root, 'assets', 'icon.ico'), icoBuf);
  fs.writeFileSync(path.join(root, 'build', 'icon.ico'), icoBuf);
  fs.writeFileSync(path.join(root, 'assets', 'icon.png'), pngs.find((p) => p.px === 256).png);
  console.log('icons written:', pngs.map((p) => `${p.px}px=${p.png.length}B`).join(' '));
  app.quit();
});
