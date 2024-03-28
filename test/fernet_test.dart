import 'dart:convert';
import 'dart:typed_data';

import 'package:fernet/fernet.dart';
import 'package:test/test.dart';

final Matcher throwsInvalidToken = throwsA(isA<InvalidToken>());

int timeStampToInt(String timeStamp) =>
    DateTime.parse(timeStamp).millisecondsSinceEpoch ~/ 1000;

void main() {
  group('Fernet', () {
    test('Fernet()', () {
      expect(
          () => Fernet('YQ=='), throwsArgumentError); // keyDecoded.length != 32
      expect(() => Fernet('a'),
          throwsArgumentError); // Not url-safe base64-encoded bytes
      expect(() => Fernet(0), throwsArgumentError); // Not Uint8List or String
    });

    test('CryptoUtils.aesCbc', () {
      expect(
          () => CryptoUtils.aesCbc(
              Uint8List(0), Uint8List(0), Uint8List(0), true),
          throwsArgumentError);
      expect(
          () => CryptoUtils.aesCbc(
              Uint8List(16), Uint8List(0), Uint8List(0), true),
          throwsArgumentError);
      expect(
          () => CryptoUtils.aesCbc(
              Uint8List(16), Uint8List(16), Uint8List(17), true),
          throwsArgumentError);
    });

    test(
        'Fernet.generateKey',
        () => expect(base64Url.decode(Fernet.generateKey()).length,
            32)); // 32 random bytes

    test('Fernet.decryptAtTime', () {
      final List<Map<String, String>> testVectors = [
        {
          'token': 'gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_'
              '5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA==',
          'now': '1985-10-26T01:20:01-07:00',
          'ttlSec': '60',
          'src': 'hello',
          'secret': 'cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4='
        }
      ];

      for (final Map<String, String> testVector in testVectors) {
        final Uint8List src =
            Uint8List.fromList(utf8.encode(testVector['src']!));
        final String secret = testVector['secret']!;
        final Uint8List token =
            Uint8List.fromList(utf8.encode(testVector['token']!));
        final int ttlSec = int.parse(testVector['ttlSec']!);
        final int now = timeStampToInt(testVector['now']!);

        final Fernet fernet = Fernet(secret);
        final Uint8List decrypted = fernet.decryptAtTime(token, ttlSec, now);
        expect(decrypted, src);
      }
    });

    test('Fernet.encrypt and Fernet.decrypt', () {
      final List<Map<String, String>> testVectors = [
        {
          'src': ('the quick brown fox jumps over the lazy dog\n' * 10)
              .trimRight(),
          'secret': 'DxWrhEe-a0rv0nEsMXXZK8lkQpMAQcv1GLm1CvjPVwQ='
        }
      ];

      for (final Map<String, String> testVector in testVectors) {
        final Uint8List src =
            Uint8List.fromList(utf8.encode(testVector['src']!));
        final String secret = testVector['secret']!;
        final Fernet fernet = Fernet(secret);
        final Uint8List token = fernet.encrypt(src);
        final Uint8List decrypted = fernet.decrypt(token, ttl: 100);
        expect(decrypted, src);
      }

      final Fernet fernet = Fernet(testVectors[0]['secret']);
      expect(() => fernet.decrypt(0), throwsArgumentError);
    });

    test('Fernet.extractTimeStamp', () {
      final Fernet fernet = Fernet(base64Url.encode(Uint8List(32)));
      const int currentTime = 1526138327;
      final Uint8List token = fernet.encryptAtTime(
          Uint8List.fromList(utf8.encode('encrypt me')), currentTime);
      expect(fernet.extractTimeStamp(token), currentTime);
      expect(fernet.extractTimeStamp(utf8.decode(token)), currentTime);

      const String validTokenB64 =
          'Z0FBQUFBQmE5d1hYMDNLbDZHSmZDemhMZXowdVU0UEpwcERoOV'
          'ZjR0lTU3pRQVVNbEZ3RFNmOGM0cGkxYnN6Q0VvNEZERk5VVVJk'
          'ZHVOSnhCUW1qYlZydWItNWZSdDE4WlE9PQ=='; // currentTime = 1526138327
      final Uint8List validToken = base64Url.decode(validTokenB64);
      expect(fernet.extractTimeStamp(validToken), currentTime);
      // randomly corrupt one byte such that
      // tamperedToken is still valid url-safe base64.
      final Uint8List tamperedToken = Uint8List.fromList([
        ...validToken.sublist(0, 7),
        0x59,
        ...validToken.sublist(8),
      ]);
      expect(() => fernet.extractTimeStamp(tamperedToken), throwsInvalidToken);

      expect(
          () => fernet.extractTimeStamp(
              Uint8List.fromList(utf8.encode('nonsensetoken'))),
          throwsInvalidToken);
      expect(() => fernet.extractTimeStamp(0), throwsArgumentError);
    });

    test('Fernet.decryptAtTime', () {
      final Fernet fernet = Fernet(base64Url.encode(Uint8List(32)));
      final Uint8List pt = Uint8List.fromList(utf8.encode('encrypt me'));
      final Uint8List token = fernet.encryptAtTime(pt, 100);
      expect(fernet.decryptAtTime(token, 1, 100), pt);
      expect(() => fernet.decryptAtTime(token, 1, 102), throwsInvalidToken);
      expect(
          () => fernet.decryptAtTime(Uint8List(0), 1, 100), throwsInvalidToken);
      expect(
          () => fernet.decryptAtTime(
              base64Url.encode([0, 1, 2, 3, 4, 5, 6, 7, 8]), 1, 100),
          throwsInvalidToken);
      expect(() => fernet.decryptAtTime(token.sublist(0, 8), 1, 100),
          throwsInvalidToken);
      expect(() => fernet.decryptAtTime(0, 1, 100), throwsArgumentError);
    });
  });

  group('MultiFernet', () {
    test('MultiFernet()', () {
      expect(() => MultiFernet([]), throwsArgumentError);
    });

    test('MultiFernet.encrypt and MultiFernet.decrypt', () {
      final Fernet f1 = Fernet(base64Url.encode(Uint8List(32)));
      final Fernet f2 = Fernet(base64Url.encode(Uint8List(32)));
      final MultiFernet f = MultiFernet([f1, f2]);

      expect(
        f1.decrypt(f.encrypt(Uint8List.fromList(utf8.encode('abc')))),
        [97, 98, 99],
      );

      // token as Uint8List
      expect(
        f.decrypt(f1.encrypt(Uint8List.fromList(utf8.encode('abc')))),
        [97, 98, 99],
      );
      expect(
        f.decrypt(f2.encrypt(Uint8List.fromList(utf8.encode('abc')))),
        [97, 98, 99],
      );

      // token as String
      expect(
        f.decrypt(
            utf8.decode(f1.encrypt(Uint8List.fromList(utf8.encode('abc'))))),
        [97, 98, 99],
      );
      expect(
        f.decrypt(
            utf8.decode(f2.encrypt(Uint8List.fromList(utf8.encode('abc'))))),
        [97, 98, 99],
      );

      expect(() => f.decrypt(Uint8List(16)), throwsInvalidToken);

      expect(() => f.decrypt(0), throwsArgumentError);
    });

    test('MultiFernet.decryptAtTime', () {
      final Fernet f1 = Fernet(base64Url.encode(Uint8List(32)));
      final MultiFernet f = MultiFernet([f1]);
      final Uint8List pt = Uint8List.fromList(utf8.encode('encrypt me'));
      final Uint8List token = f.encryptAtTime(pt, 100);
      expect(f.decryptAtTime(token, 1, 100), pt);
      expect(() => f.decryptAtTime(token, 1, 102), throwsInvalidToken);
      expect(() => f.decryptAtTime(0, 1, 100), throwsArgumentError);
    });

    test('MultiFernet.rotate', () {
      final Fernet f1 = Fernet(base64Url.encode(Uint8List(32)));
      final Fernet f2 =
          Fernet(base64Url.encode(Uint8List(32)..fillRange(0, 32, 1)));
      MultiFernet mf1 = MultiFernet([f1]);
      MultiFernet mf2 = MultiFernet([f2, f1]);
      final Uint8List plaintext = Uint8List.fromList(utf8.encode('abc'));

      // Uint8List
      Uint8List mf1Ciphertext = mf1.encrypt(plaintext);
      expect(mf2.decrypt(mf1Ciphertext), plaintext);
      final Uint8List rotated = mf2.rotate(mf1Ciphertext);
      expect(rotated, isNot(equals(mf1Ciphertext)));
      expect(mf2.decrypt(rotated), plaintext);
      expect(() => mf1.decrypt(rotated), throwsInvalidToken);

      // String
      final String mf1CiphertextStr = utf8.decode(mf1.encrypt(plaintext));
      expect(mf2.decrypt(mf1CiphertextStr), plaintext);
      final String rotatedStr = utf8.decode(mf2.rotate(mf1CiphertextStr));
      expect(rotatedStr, isNot(equals(mf1CiphertextStr)));
      expect(mf2.decrypt(rotatedStr), plaintext);
      expect(() => mf1.decrypt(rotatedStr), throwsInvalidToken);

      // Preserves timeStamp
      final int originalTime =
          DateTime.now().millisecondsSinceEpoch ~/ 1000 - 5 * 60;
      mf1Ciphertext = mf1.encryptAtTime(plaintext, originalTime);
      final int rotatedTime = f1.extractTimeStamp(mf1Ciphertext);

      expect(DateTime.now().millisecondsSinceEpoch ~/ 1000,
          isNot(equals(rotatedTime)));
      expect(originalTime, rotatedTime);

      // decrypt no shared keys
      mf1 = MultiFernet([f1]);
      mf2 = MultiFernet([f2]);
      expect(() => mf2.rotate(mf1.encrypt(plaintext)), throwsInvalidToken);

      expect(() => mf2.rotate(0), throwsArgumentError);
    });
  });
}
