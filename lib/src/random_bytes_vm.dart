import 'dart:math';
import 'dart:typed_data';

/// Generate [size] cryptographically secure random bytes.
Uint8List randomBytes(final int size) {
  final Random random = Random.secure();
  final Uint8List bytes = Uint8List(size);
  for (int i = 0; i < bytes.length; i++) {
    bytes[i] = random.nextInt(256);
  }
  return bytes;
}
