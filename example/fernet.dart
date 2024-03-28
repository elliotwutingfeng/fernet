import 'dart:convert';
import 'dart:typed_data';

import 'package:fernet/fernet.dart';

void main() {
  final Fernet f = Fernet(Fernet.generateKey());
  final Uint8List token =
      f.encrypt(utf8.encode('A really secret message. Not for prying eyes.'));

  print(utf8.decode(f.decrypt(token)));
  // OUTPUT: 'A really secret message. Not for prying eyes.'
}
