/// A Dart library for encrypting and decrypting messages
/// using the [Fernet] scheme.
///
/// [Fernet] guarantees that a message encrypted using it cannot be manipulated
/// or read without the key. [Fernet] is an implementation of
/// symmetric (also known as "secret key") authenticated cryptography.
/// [Fernet] also has support for implementing key rotation via [MultiFernet].
library fernet;

import 'package:fernet/fernet.dart';

export 'src/fernet_base.dart';
