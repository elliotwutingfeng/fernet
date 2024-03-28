import 'dart:convert';
import 'dart:typed_data';

import 'package:fernet/fernet.dart';

void main() {
  final Fernet f1 = Fernet(Fernet.generateKey());
  final Fernet f2 = Fernet(Fernet.generateKey());
  final MultiFernet mf1 = MultiFernet([f1, f2]);
  final Uint8List token =
      mf1.encrypt(utf8.encode('A really secret message. Not for prying eyes.'));

  print(utf8.decode(mf1.decrypt(token)));
  // OUTPUT: 'A really secret message. Not for prying eyes.'

  final Fernet f3 = Fernet(Fernet.generateKey());
  final MultiFernet mf2 = MultiFernet([f3, f1, f2]);
  final Uint8List rotated = mf2.rotate(token);

  print(utf8.decode(mf2.decrypt(rotated)));
  // OUTPUT: 'A really secret message. Not for prying eyes.'

  try {
    mf1.decrypt(rotated);
  } on InvalidToken {
    print('As expected, mf1 cannot decrypt [rotated] token.');
    // OUTPUT: 'As expected, mf1 cannot decrypt [rotated] token.'
  }
}
