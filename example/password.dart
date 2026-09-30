import 'dart:convert';
import 'dart:typed_data';

import 'package:cipherlib/hashlib.dart';
import 'package:cipherlib/random.dart';
import 'package:fernet/fernet.dart';

void main() {
  const String pwd = 'password';

  // Argon2Parameters should be adjusted to be as high as your server
  // can tolerate. OWASP provides recommended parameter values at
  // https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
  final Uint8List key = argon2id(
    utf8.encode(pwd),
    randomBytes(16),
    security: Argon2Security.owasp2,
  ).bytes;

  final Fernet f = Fernet(key);
  final Uint8List token = f.encrypt(
    utf8.encode('A really secret message. Not for prying eyes.'),
  );

  print(utf8.decode(f.decrypt(token)));
  // OUTPUT: 'A really secret message. Not for prying eyes.'
}
