import 'dart:typed_data';

/// Fills [bytes] with cryptographically secure random values.
void randomFillSync(final Uint8List bytes) {
  throw UnsupportedError(
    'Cryptographic random number generator not supported on this platform.',
  ); // Fallback stub for unsupported platforms.
}
