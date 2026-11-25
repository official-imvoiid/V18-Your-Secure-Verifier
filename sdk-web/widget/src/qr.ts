import qrcode from 'qrcode-generator';

/**
 * Generates an SVG string representation of a QR code.
 */
export function generateQrSvg(data: string, cellSize: number = 5, margin: number = 2): string {
  try {
    // Type 0 = auto-detect minimum version (1-40) needed for payload
    const qr = qrcode(0, 'M');
    qr.addData(data);
    qr.make();
    return qr.createSvgTag({
      cellSize,
      margin,
      scalable: true,
    });
  } catch (err: any) {
    console.error('[V18 Widget] QR generation failed:', err);
    return `<div style="padding:20px;text-align:center;color:#ef4444">Could not generate QR code: ${err.message}</div>`;
  }
}

