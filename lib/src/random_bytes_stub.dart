import 'dart:typed_data';

/// Generate [size] cryptographically secure random bytes.
Uint8List randomBytes(final int size) {
  throw UnsupportedError(
    'Cryptographic random number generator not supported on this platform.',
  ); // Fallback stub for unsupported platforms.
}
