import 'dart:js_interop';
import 'dart:typed_data';

import 'package:fernet/src/random_fill_sync_vm.dart' as vm;

@JS()
external NodeCrypto require(final String id);

extension type NodeCrypto._(JSObject _) implements JSObject {
  external JSObject randomFillSync(final JSArrayBuffer buffer);
}

/// Fills [bytes] with cryptographically secure random values.
void randomFillSync(final Uint8List bytes) {
  try {
    // Web browser (more commonly used Dart platform than Node.js)
    vm.randomFillSync(bytes);
  } catch (_) {
    // Node.js
    require('crypto').randomFillSync(bytes.buffer.toJS);
  }
}
