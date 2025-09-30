import 'dart:math';
import 'dart:typed_data';

/// Fills [bytes] with cryptographically secure random values.
void randomFillSync(final Uint8List bytes) {
  final Random random = Random.secure();
  for (int i = 0; i < bytes.length; i++) {
    bytes[i] = random.nextInt(256);
  }
}
