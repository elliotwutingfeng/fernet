import 'dart:convert';
import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:cipherlib/codecs.dart';
import 'package:cipherlib/hashlib.dart';
import 'package:cipherlib/random.dart';

class InvalidToken(final String? message) implements Exception {
  @override
  String toString() => message != null
      ? 'InvalidToken: $message'
      : 'InvalidToken: Token is invalid.';
}

const int maxInt = 0x1FFFFFFFFFFFFF; // JavaScript limit: 2^53 - 1

/// [currentTime] must be a non-negative integer
/// not exceeding JavaScript limit of 2^53 - 1.
void validateCurrentTime(int currentTime) {
  if (currentTime < 0 || currentTime > maxInt) {
    throw RangeError.value(
      currentTime,
      'currentTime',
      'Must be between 0 and $maxInt',
    );
  }
}

/// Maximum allowed grace period in seconds for
/// system clock time being out of sync with Fernet token.
const int _maxClockSkew = 60;

/// This class provides both encryption and decryption facilities.
class Fernet {
  late final Uint8List _signingKey;
  late final Uint8List _encryptionKey;

  /// [key] is URL-safe base64-encoded and it has to
  /// be 32-bytes long before base64-encoding.
  /// This **must** be kept secret.
  /// Anyone with this [key] is able to create and read messages.
  factory(Object key) => switch (key) {
    final Uint8List k => Fernet.fromUint8List(k),
    final String k => Fernet.fromString(k),
    _ => throw ArgumentError('key must be Uint8List or String.'),
  };

  new fromUint8List(Uint8List key) : this.fromString(utf8.decode(key));

  new fromString(String key) {
    try {
      final Uint8List keyDecoded = base64Url.decode(key);
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
  static String generateKey() => base64Url.encode(randomBytes(32));

  /// Encrypts [data] passed. The result of this encryption is known as a
  /// "Fernet token" and has strong privacy and authenticity guarantees.
  Uint8List encrypt(Uint8List data) =>
      encryptAtTime(data, DateTime.now().millisecondsSinceEpoch ~/ 1000);

  /// Encrypts [data] passed using explicitly passed [currentTime].
  /// See [Fernet.encrypt] for the documentation of the [data] parameter.
  ///
  /// The motivation behind this method is for the client code to be able
  /// to test token expiration. Since this method can be used in an
  /// insecure manner one should make sure the correct time
  /// is passed as [currentTime] outside testing.
  Uint8List encryptAtTime(Uint8List data, int currentTime) {
    validateCurrentTime(currentTime);
    return _encryptFromParts(data, currentTime, randomBytes(16));
  }

  Uint8List _encryptFromParts(Uint8List data, int currentTime, Uint8List iv) {
    final Uint8List cipherText = AES
        .pkcs7(_encryptionKey)
        .cbc(iv)
        .encrypt(data);
    final Uint8List currentTimeBytes = fromBigInt(
      BigInt.from(currentTime),
      msbFirst: true,
    );

    final Uint8List basicParts = Uint8List.fromList([
      0x80,
      ...(Uint8List(8)..setRange(
        8 - currentTimeBytes.length,
        8,
        currentTimeBytes,
      )), // Pad to 8 bytes
      ...iv,
      ...cipherText,
    ]);

    final Uint8List hmac = sha256.hmac
        .by(_signingKey)
        .convert(basicParts)
        .bytes;

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
  Uint8List decrypt(Object token, {int? ttl}) {
    if (token is! Uint8List && token is! String) {
      throw ArgumentError('token must be Uint8List or String.');
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
  Uint8List decryptAtTime(Object token, int ttl, int currentTime) {
    validateCurrentTime(currentTime);
    if (token is! Uint8List && token is! String) {
      throw ArgumentError('token must be Uint8List or String.');
    }
    final (int timestamp, Uint8List data) = Fernet._getUnverifiedTokenData(
      token,
    );
    return _decryptData(data, timestamp, [ttl, currentTime]);
  }

  /// Returns the Unix timestamp for the [token].
  /// The caller can then decide if the [token] is about to expire and,
  /// for example, issue a new [token].
  int extractTimeStamp(Object token) {
    final (int timestamp, Uint8List data) = Fernet._getUnverifiedTokenData(
      token,
    );
    // Verify the token was not tampered with.
    _verifySignature(data);
    return timestamp;
  }

  static (int, Uint8List) _getUnverifiedTokenData(Object token) {
    if (token is! Uint8List && token is! String) {
      throw ArgumentError('token must be Uint8List or String.');
    }
    late final Uint8List data;
    try {
      data = base64Url.decode(
        token is String ? token : utf8.decode(token as Uint8List),
      );
    } on FormatException {
      throw InvalidToken('Invalid base64 encoding.');
    }
    if (data.isEmpty) {
      throw InvalidToken('Empty token.');
    }
    if (data[0] != 0x80) {
      throw InvalidToken('Invalid token version.');
    }
    if (data.length < 9) {
      throw InvalidToken('Token too short.');
    }
    final int timestamp = toBigInt(data.sublist(1, 9), msbFirst: true).toInt();
    return (timestamp, data);
  }

  void _verifySignature(Uint8List data) {
    final Uint8List hmac = sha256.hmac
        .by(_signingKey)
        .convert(data.sublist(0, data.length - 32))
        .bytes;
    final Uint8List expectedMac = data.sublist(data.length - 32);
    if (!constantTimeEquals(hmac, expectedMac)) {
      throw InvalidToken('Signature verification failed.');
    }
  }

  Uint8List _decryptData(Uint8List data, int timestamp, List<int>? timeInfo) {
    if (timeInfo is List<int>) {
      final int ttl = timeInfo[0];
      final int currentTime = timeInfo[1];
      if (timestamp + ttl < currentTime ||
          currentTime + _maxClockSkew < timestamp) {
        throw InvalidToken('Token expired or timestamp out of range.');
      }
    }

    _verifySignature(data);

    final Uint8List iv = data.sublist(9, 25);
    final Uint8List cipherText = data.sublist(25, data.length - 32);

    final Uint8List plaintext = AES
        .pkcs7(_encryptionKey)
        .cbc(iv)
        .decrypt(cipherText);
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
  late final List<Fernet> _fernets;

  new(List<Fernet> fernets) {
    if (fernets.isEmpty) {
      throw ArgumentError('MultiFernet requires at least one Fernet instance.');
    }
    _fernets = fernets;
  }

  /// See [Fernet.encrypt].
  Uint8List encrypt(Uint8List data) =>
      encryptAtTime(data, DateTime.now().millisecondsSinceEpoch ~/ 1000);

  /// See [Fernet.encryptAtTime].
  Uint8List encryptAtTime(Uint8List data, int currentTime) =>
      _fernets[0].encryptAtTime(data, currentTime);

  /// Rotates a [token] by re-encrypting it under the [MultiFernet] instance's
  /// primary key. This preserves the timestamp that was originally saved with
  /// the [token]. If a [token] has successfully been rotated then the rotated
  /// [token] will be returned. If rotation fails this will throw an exception.
  Uint8List rotate(Object token) {
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
      throw InvalidToken('Token could not be decrypted with any key.');
    }
    final Uint8List iv = randomBytes(16);
    return _fernets[0]._encryptFromParts(p, timestamp, iv);
  }

  /// See [Fernet.decrypt].
  Uint8List decrypt(Object token, {int? ttl}) {
    for (final Fernet f in _fernets) {
      try {
        return f.decrypt(token, ttl: ttl);
      } on InvalidToken {
        continue;
      }
    }
    throw InvalidToken('Token could not be decrypted with any key.');
  }

  /// See [Fernet.decryptAtTime].
  Uint8List decryptAtTime(Object token, int ttl, int currentTime) {
    for (final Fernet f in _fernets) {
      try {
        return f.decryptAtTime(token, ttl, currentTime);
      } on InvalidToken {
        continue;
      }
    }
    throw InvalidToken('Token could not be decrypted with any key.');
  }

  /// See [Fernet.extractTimeStamp].
  int extractTimeStamp(Object token) {
    for (final Fernet f in _fernets) {
      try {
        return f.extractTimeStamp(token);
      } on InvalidToken {
        continue;
      }
    }
    throw InvalidToken('Token could not be decrypted with any key.');
  }
}
