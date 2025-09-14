import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/block/aes.dart';
import 'package:pointycastle/block/modes/cbc.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/macs/hmac.dart';
import 'package:pointycastle/paddings/pkcs7.dart';
import 'package:pointycastle/pointycastle.dart';

/// See [Fernet.decrypt] for more information.
class InvalidToken implements Exception {}

/// Maximum allowed grace period in seconds for
/// system clock time being out of sync with Fernet token.
const int _maxClockSkew = 60;

/// Utility methods for converting between integer and big endian bytes.
mixin ByteUtils {
  /// Return a Uint8List of big endian bytes representing an integer.
  static Uint8List intToBigEndianBytes(
    final int value, {
    final int length = 8,
  }) {
    final Uint8List result = Uint8List(length);
    for (int i = 0; i < length; i++) {
      result[length - 1 - i] = (value >> (8 * i)) & 0xff;
    }
    return result;
  }

  /// Return an integer representing a Uint8List of big endian bytes.
  static int intFromBigEndianBytes(final List<int> bytes) {
    int result = 0;
    for (int i = 0; i < bytes.length; i++) {
      result = (result << 8) + bytes[i];
    }
    return result;
  }
}

/// Utility methods for cryptographic algorithms AES-CBC and HMAC-SHA256.
mixin CryptoUtils {
  /// PKCS7 padding before AES-CBC encryption.
  static Uint8List pad(final Uint8List bytes, final int blockSizeBytes) {
    final int padLength = blockSizeBytes - (bytes.length % blockSizeBytes);
    final Uint8List padded = Uint8List(bytes.length + padLength)
      ..setAll(0, bytes);
    PKCS7Padding().addPadding(padded, bytes.length);
    return padded;
  }

  /// PKCS7 unpadding after AES-CBC decryption.
  static Uint8List unpad(final Uint8List bytes) {
    final int padLength = (PKCS7Padding()..init()).padCount(bytes);
    final int len = bytes.length - padLength;
    return Uint8List(len)..setRange(0, len, bytes);
  }

  /// Encrypts/Decrypts [sourceText] with symmetric [key] and initialization
  /// vector [iv].
  ///
  /// To encrypt, set [encrypt] to true. To decrypt, set [encrypt] to false.
  static Uint8List aesCbc(
    final Uint8List key,
    final Uint8List iv,
    final Uint8List sourceText,
    final bool encrypt,
  ) {
    if (![16, 24, 32].contains(key.length)) {
      throw ArgumentError('key.length must be 16, 24, or 32.');
    }
    if (iv.length != 16) {
      throw ArgumentError('iv.length must be 16.');
    }
    if (sourceText.length % 16 != 0) {
      throw ArgumentError('sourceText.length must be a multiple of 16.');
    }
    final CBCBlockCipher cbc = CBCBlockCipher(AESEngine())
      ..init(encrypt, ParametersWithIV(KeyParameter(key), iv));

    final Uint8List targetText = Uint8List(sourceText.length);

    int offset = 0;
    while (offset < sourceText.length) {
      offset += cbc.processBlock(sourceText, offset, targetText, offset);
    }
    if (sourceText.length != offset) {
      throw ArgumentError('sourceText.length must be equal to offset.');
    }
    return targetText;
  }

  /// Compare 2 lists of integers element-by-element in constant-time.
  static bool listEquals(final List<int> list1, final List<int> list2) {
    if (list1.length != list2.length) return false;
    int mismatch = 0;
    for (int i = 0; i < list1.length; i++) {
      mismatch |= (list1[i]) ^ (list2[i]);
    }
    return mismatch == 0;
  }

  /// Generate a Uint8List of random bytes of size [length] suitable
  /// for cryptographic use.
  static Uint8List secureRandomBytes(final int length) {
    final Random random = Random.secure();
    final Uint8List bytes = Uint8List(length);
    for (int i = 0; i < length; i++) {
      bytes[i] = random.nextInt(256);
    }
    return bytes;
  }

  /// Return HMAC-SHA256 digest of [data] for given secret [key].
  static Uint8List hmacSHA256Digest(
    final Uint8List key,
    final Uint8List data,
  ) => (HMac(SHA256Digest(), 64)..init(KeyParameter(key))).process(data);
}

/// This class provides both encryption and decryption facilities.
class Fernet {
  late Uint8List _signingKey;
  late Uint8List _encryptionKey;

  /// [key] is URL-safe base64-encoded and it has to
  /// be 32-bytes long before base64-encoding.
  /// This **must** be kept secret.
  /// Anyone with this [key] is able to create and read messages.
  Fernet(final dynamic key) {
    if (key is! Uint8List && key is! String) {
      throw ArgumentError('key must be Uint8List or String');
    }
    try {
      final String keyStr = key is String ? key : utf8.decode(key as Uint8List);
      final Uint8List keyDecoded = base64Url.decode(keyStr);
      if (keyDecoded.length != 32) {
        throw FormatException();
      }
      _signingKey = keyDecoded.sublist(0, 16);
      _encryptionKey = keyDecoded.sublist(16, 32);
    } on FormatException {
      throw ArgumentError(
        'Fernet key must be 32 url-safe base64-encoded bytes.',
      );
    }
  }

  /// Generates a fresh fernet key. Keep this some place safe!
  /// If you lose it you'll no longer be able to decrypt messages;
  /// if anyone else gains access to it, they'll be able to decrypt
  /// all of your messages, and they'll also be able forge arbitrary
  /// messages that will be authenticated and decrypted.
  static String generateKey() =>
      base64Url.encode(CryptoUtils.secureRandomBytes(32));

  /// Encrypts [data] passed. The result of this encryption is known as a
  /// "Fernet token" and has strong privacy and authenticity guarantees.
  Uint8List encrypt(final Uint8List data) =>
      encryptAtTime(data, DateTime.now().millisecondsSinceEpoch ~/ 1000);

  /// Encrypts [data] passed using explicitly passed [currentTime].
  /// See [Fernet.encrypt] for the documentation of the [data] parameter.
  ///
  /// The motivation behind this method is for the client code to be able
  /// to test token expiration. Since this method can be used in an
  /// insecure manner one should make sure the correct time
  /// is passed as [currentTime] outside testing.
  Uint8List encryptAtTime(final Uint8List data, final int currentTime) =>
      _encryptFromParts(data, currentTime, CryptoUtils.secureRandomBytes(16));

  Uint8List _encryptFromParts(
    final Uint8List data,
    final int currentTime,
    final Uint8List iv,
  ) {
    final Uint8List paddedData = CryptoUtils.pad(data, 128 ~/ 8);
    final Uint8List cipherText = CryptoUtils.aesCbc(
      _encryptionKey,
      iv,
      paddedData,
      true,
    );
    final Uint8List currentTimeBytes = ByteUtils.intToBigEndianBytes(
      currentTime,
    );

    final Uint8List basicParts = Uint8List.fromList([
      0x80,
      ...currentTimeBytes,
      ...iv,
      ...cipherText,
    ]);

    final Uint8List hmac = CryptoUtils.hmacSHA256Digest(
      _signingKey,
      basicParts,
    );

    return utf8.encode(base64Url.encode([...basicParts, ...hmac]));
  }

  /// Decrypts a fernet [token]. If successful you will receive the
  /// original plaintext as the result, otherwise an exception will be thrown.
  /// It is safe to use this data immediately as [Fernet] verifies that the data
  /// has not been tampered with prior to returning it.
  ///
  /// [ttl] (optional) is the number of seconds old a message may be for it to
  /// be valid. If the message is older than [ttl] seconds
  /// (from the time it was originally created) an exception will be thrown.
  /// If [ttl] is not provided (or is null),
  /// the age of the message is not considered.
  Uint8List decrypt(final dynamic token, {final int? ttl}) {
    if (token is! Uint8List && token is! String) {
      throw ArgumentError('token must be Uint8List or String');
    }
    final (int timestamp, Uint8List data) = Fernet._getUnverifiedTokenData(
      token,
    );
    List<int>? timeInfo;
    if (ttl != null) {
      timeInfo = [ttl, DateTime.now().millisecondsSinceEpoch ~/ 1000];
    }
    return _decryptData(data, timestamp, timeInfo);
  }

  /// Decrypts a token using explicitly passed [currentTime].
  /// See [Fernet.decrypt] for the documentation
  /// of the [token] and [ttl] parameters.
  ///
  /// The motivation behind this method is for the client code to be able to
  /// test [token] expiration. Since this method can be used in an insecure
  /// manner one should make sure the correct time is passed
  /// as [currentTime] outside testing.
  Uint8List decryptAtTime(
    final dynamic token,
    final int ttl,
    final int currentTime,
  ) {
    if (token is! Uint8List && token is! String) {
      throw ArgumentError('token must be Uint8List or String');
    }
    final (int timestamp, Uint8List data) = Fernet._getUnverifiedTokenData(
      token,
    );
    return _decryptData(data, timestamp, [ttl, currentTime]);
  }

  /// Returns the Unix timestamp for the [token].
  /// The caller can then decide if the [token] is about to expire and,
  /// for example, issue a new [token].
  int extractTimeStamp(final dynamic token) {
    final (int timestamp, Uint8List data) = Fernet._getUnverifiedTokenData(
      token,
    );
    // Verify the token was not tampered with.
    _verifySignature(data);
    return timestamp;
  }

  static (int, Uint8List) _getUnverifiedTokenData(final dynamic token) {
    if (token is! Uint8List && token is! String) {
      throw ArgumentError('token must be Uint8List or String');
    }
    late Uint8List data;
    try {
      data = base64Url.decode(
        token is String ? token : utf8.decode(token as Uint8List),
      );
    } on FormatException {
      throw InvalidToken();
    }
    if (data.isEmpty) {
      throw InvalidToken();
    }
    if (data[0] != 0x80) {
      throw InvalidToken();
    }
    if (data.length < 9) {
      throw InvalidToken();
    }
    final int timestamp = ByteUtils.intFromBigEndianBytes(data.sublist(1, 9));
    return (timestamp, data);
  }

  void _verifySignature(final Uint8List data) {
    final Uint8List hmac = CryptoUtils.hmacSHA256Digest(
      _signingKey,
      data.sublist(0, data.length - 32),
    );
    final Uint8List expectedMac = data.sublist(data.length - 32);
    if (!CryptoUtils.listEquals(hmac, expectedMac)) {
      throw InvalidToken();
    }
  }

  Uint8List _decryptData(
    final Uint8List data,
    final int timestamp,
    final List<int>? timeInfo,
  ) {
    if (timeInfo is List<int>) {
      final int ttl = timeInfo[0];
      final int currentTime = timeInfo[1];
      if (timestamp + ttl < currentTime ||
          currentTime + _maxClockSkew < timestamp) {
        throw InvalidToken();
      }
    }

    _verifySignature(data);

    final Uint8List iv = data.sublist(9, 25);
    final Uint8List cipherText = data.sublist(25, data.length - 32);

    final Uint8List paddedPlainText = CryptoUtils.aesCbc(
      _encryptionKey,
      iv,
      cipherText,
      false,
    );

    late Uint8List plaintext;
    try {
      plaintext = CryptoUtils.unpad(paddedPlainText);
    } on Exception {
      throw InvalidToken();
    }
    return plaintext;
  }
}

/// This class implements key rotation for [Fernet].
/// It takes a List of [Fernet] instances and implements the same API
/// with the exception of one additional method: [MultiFernet.rotate]
///
/// [MultiFernet] performs all encryption options using the first key
/// in the list provided. [MultiFernet] attempts to decrypt tokens with each key
/// in turn. A [InvalidToken] exception is thrown if the correct key is not
/// found in the list provided.
///
/// Key rotation makes it easy to replace old keys. You can add your new key at
/// the front of the list to start encrypting new messages, and remove old keys
/// as they are no longer needed.
///
/// Token rotation as offered by [MultiFernet.rotate] is a best practice and
/// manner of cryptographic hygiene designed to limit damage in the event of an
/// undetected event and to increase the difficulty of attacks. For example, if
/// an employee who had access to your company's fernet keys leaves, you'll
/// want to generate new fernet key, rotate all of the tokens currently deployed
/// using that new key, and then retire the old fernet key(s)
/// to which the employee had access.
class MultiFernet {
  late List<Fernet> _fernets;

  MultiFernet(final List<Fernet> fernets) {
    if (fernets.isEmpty) {
      throw ArgumentError('MultiFernet requires at least one Fernet instance');
    }
    _fernets = fernets;
  }

  /// See [Fernet.encrypt].
  Uint8List encrypt(final Uint8List data) =>
      encryptAtTime(data, DateTime.now().millisecondsSinceEpoch ~/ 1000);

  /// See [Fernet.encryptAtTime].
  Uint8List encryptAtTime(final Uint8List data, final int currentTime) =>
      _fernets[0].encryptAtTime(data, currentTime);

  /// Rotates a [token] by re-encrypting it under the [MultiFernet] instance's
  /// primary key. This preserves the timestamp that was originally saved with
  /// the [token]. If a [token] has successfully been rotated then the rotated
  /// [token] will be returned. If rotation fails this will throw an exception.
  Uint8List rotate(final dynamic token) {
    if (token is! Uint8List && token is! String) {
      throw ArgumentError('token must be Uint8List or String');
    }
    final (int timestamp, Uint8List data) = Fernet._getUnverifiedTokenData(
      token,
    );
    Uint8List? p;
    for (final Fernet f in _fernets) {
      try {
        p = f._decryptData(data, timestamp, null);
        break;
      } on InvalidToken {
        continue;
      }
    }
    if (p == null) {
      throw InvalidToken();
    }
    final Uint8List iv = CryptoUtils.secureRandomBytes(16);
    return _fernets[0]._encryptFromParts(p, timestamp, iv);
  }

  /// See [Fernet.decrypt].
  Uint8List decrypt(final dynamic token, {final int? ttl}) {
    if (token is! Uint8List && token is! String) {
      throw ArgumentError('token must be Uint8List or String');
    }
    for (final Fernet f in _fernets) {
      try {
        return f.decrypt(token, ttl: ttl);
      } on InvalidToken {
        continue;
      }
    }
    throw InvalidToken();
  }

  /// See [Fernet.decryptAtTime].
  Uint8List decryptAtTime(
    final dynamic token,
    final int ttl,
    final int currentTime,
  ) {
    if (token is! Uint8List && token is! String) {
      throw ArgumentError('token must be Uint8List or String');
    }
    for (final Fernet f in _fernets) {
      try {
        return f.decryptAtTime(token, ttl, currentTime);
      } on InvalidToken {
        continue;
      }
    }
    throw InvalidToken();
  }

  /// See [Fernet.extractTimeStamp].
  int extractTimeStamp(final dynamic token) {
    if (token is! Uint8List && token is! String) {
      throw ArgumentError('token must be Uint8List or String');
    }
    for (final Fernet f in _fernets) {
      try {
        return f.extractTimeStamp(token);
      } on InvalidToken {
        continue;
      }
    }
    throw InvalidToken();
  }
}
