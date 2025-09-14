import 'dart:convert';
import 'dart:typed_data';

import 'package:fernet/fernet.dart';
import 'package:pointycastle/key_derivators/api.dart';
import 'package:pointycastle/key_derivators/argon2.dart';

void main() {
  const String pwd = 'password';

  // Argon2Parameters should be adjusted to be as high as your server
  // can tolerate. OWASP provides recommended parameter values at
  // https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
  final Uint8List key = utf8.encode(
    base64Url.encode(
      (Argon2BytesGenerator()..init(
            Argon2Parameters(
              Argon2Parameters.ARGON2_id,
              CryptoUtils.secureRandomBytes(16),
              desiredKeyLength: 32,
              iterations: 2,
              memory: 19 * 1024,
            ),
          ))
          .process(utf8.encode(pwd)),
    ),
  );
  final Fernet f = Fernet(key);
  final Uint8List token = f.encrypt(
    utf8.encode('A really secret message. Not for prying eyes.'),
  );

  print(utf8.decode(f.decrypt(token)));
  // OUTPUT: 'A really secret message. Not for prying eyes.'
}
