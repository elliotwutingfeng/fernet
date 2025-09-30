import 'dart:js_interop';
import 'dart:typed_data';

@JS()
external NodeCrypto require(final String id);

extension type NodeCrypto._(JSObject _) implements JSObject {
  external JSObject randomFillSync(final JSArrayBuffer buffer);
}

@JS('crypto.getRandomValues')
external JSObject getRandomValues(final JSUint8Array bytes);

/// Fills [bytes] with cryptographically secure random values.
void randomFillSync(final Uint8List bytes) {
  try {
    // Web browser (more commonly used Dart platform than Node.js)
    getRandomValues(bytes.toJS);
  } catch (_) {
    // Node.js
    require('crypto').randomFillSync(bytes.buffer.toJS);
  }
}
