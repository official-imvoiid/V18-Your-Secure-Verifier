import 'package:flutter/services.dart';

class PdfRenderException implements Exception {
  const PdfRenderException(this.code);

  /// pdf_password, pdf_password_unsupported, pdf_error
  final String code;
  @override
  String toString() => 'PdfRenderException($code)';
}

/// Renders the first pages of a PDF to PNG files in the app's private cache
/// with Android's built-in PdfRenderer (see PlatformChannel.kt).
/// Call [deleteRenderedPages] as soon as the QR has been read.
class PdfPages {
  PdfPages({MethodChannel? channel})
      : _ch = channel ?? const MethodChannel('com.v18.app/platform');
  final MethodChannel _ch;

  Future<List<String>> render(String path, {String? password}) async {
    try {
      final r = await _ch.invokeMethod<List<Object?>>(
          'renderPdf', {'path': path, 'password': password});
      return (r ?? const []).whereType<String>().toList();
    } on PlatformException catch (e) {
      throw PdfRenderException(e.code);
    }
  }

  Future<void> deleteRenderedPages() async {
    try {
      await _ch.invokeMethod<void>('deleteRenderedPages');
    } on Object {
      // Best effort.
    }
  }
}
