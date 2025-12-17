import 'dart:js_interop';
import 'dart:typed_data';

import 'package:fernet/src/random_bytes_vm.dart' as vm;

@JS()
external NodeCrypto require(final String id);

extension type NodeCrypto._(JSObject _) implements JSObject {
  external JSUint8Array randomBytes(final int size);
}

/// Generate [size] cryptographically secure random bytes.
Uint8List randomBytes(final int size) {
  try {
    // Web browser (more commonly used Dart platform than Node.js)
    return vm.randomBytes(size);
  } catch (_) {
    // Node.js
    return require('crypto').randomBytes(size).toDart;
  }
}
