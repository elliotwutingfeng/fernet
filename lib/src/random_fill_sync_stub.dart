import 'dart:typed_data';

/// Fallback stub for unsupported platforms.
void randomFillSync(final Uint8List bytes) {
  throw UnsupportedError(
    'Cryptographic random number generator not supported on this platform.',
  );
}
