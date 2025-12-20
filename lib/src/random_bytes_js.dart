import 'dart:js_interop';
import 'dart:typed_data';

import 'package:fernet/src/random_bytes_vm.dart' as vm;

const bool isWASM = bool.fromEnvironment('dart.tool.dart2wasm');

@JS()
@staticInterop
class Process {}

@JS()
@staticInterop
class Versions {}

@JS('process')
external Process? get _process;

extension on Process {
  external Versions? get versions;
}

extension on Versions {
  external JSAny get node;
}

bool get isNodeDart2JS => _process?.versions?.node != null && !isWASM;

@JS()
external NodeCrypto require(final String id);

extension type NodeCrypto._(JSObject _) implements JSObject {
  external JSUint8Array randomBytes(final int size);
}

/// Generate [size] cryptographically secure random bytes.
Uint8List randomBytes(final int size) => isNodeDart2JS
    ? require('crypto').randomBytes(size).toDart
    : vm.randomBytes(size);
