///
/// Copyright (c) [2019] [riclava]
/// [ed25519] is licensed under the Mulan PSL v1.
/// You can use this software according to the terms and conditions of the Mulan PSL v1.
/// You may obtain a copy of Mulan PSL v1 at:
///     http://license.coscl.org.cn/MulanPSL
/// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
/// PURPOSE.
/// See the Mulan PSL v1 for more details.
///
library ed25519;

import 'dart:typed_data';

typedef Uint8List HashFunc(Uint8List m);

/// Ed25519
/// BigInt ref https://api.dartlang.org/stable/2.5.0/dart-core/BigInt-class.html
class Ed25519 {
  static final int b = 256;
  static final BigInt q = BigInt.parse("57896044618658097711785492504343953926634992332820282019728792003956564819949");
  static final BigInt qm2 = BigInt.parse("57896044618658097711785492504343953926634992332820282019728792003956564819947");
  static final BigInt qp3 = BigInt.parse("57896044618658097711785492504343953926634992332820282019728792003956564819952");
  static final BigInt l = BigInt.parse("7237005577332262213973186563042994240857116359379907606001950938285454250989");
  static final BigInt d = BigInt.parse("-4513249062541557337682894930092624173785641285191125241628941591882900924598840740");
  static final BigInt I = BigInt.parse("19681161376707505956807079304988542015446066515923890162744021073123829784752");
  static final BigInt by = BigInt.parse("46316835694926478169428394003475163141307993866256225615783033603165251855960");
  static final BigInt bx = BigInt.parse("15112221349535400772501151409588531511454012693041857206046113283949847762202");
  static final List<BigInt> B = [bx % q, by % q];
  static final BigInt un = BigInt.parse("57896044618658097711785492504343953926634992332820282019728792003956564819967");

  static final BigInt zero = BigInt.from(0);
  static final BigInt one = BigInt.from(1);
  static final BigInt two = BigInt.from(2);
  static final BigInt eight = BigInt.from(8);

  // f is an hash algorithm like blake2b
  static Uint8List hash(HashFunc f, Uint8List m) {
    return f(m);
  }

  static BigInt expmod(BigInt b, BigInt e, BigInt m) {
    if (e == zero) {
      return one;
    }
    BigInt t = expmod(b, e ~/ two, m).pow(2) % m;
    if (e % two != zero) {
      t = t * b % m;
    }
    return t;
  }

  static BigInt inv(BigInt x) {
    return expmod(x, qm2, q);
  }

  static BigInt xrecover(BigInt y) {
    BigInt y2 = y * y;
    BigInt xx = (y2 - one) * (inv(d * y2 + one));
    BigInt x = expmod(xx, qp3 ~/ eight, q);
    if (!((x * x - xx) % q == zero )) x = x * I % q;
    if (!( x % two == zero )) x = q - x;
    return x;
  }

  static List<BigInt> edwards(List<BigInt> P, List<BigInt> Q) {
    BigInt x1 = P[0];
    BigInt y1 = P[1];
    BigInt x2 = Q[0];
    BigInt y2 = Q[1];
    BigInt dtemp = d * x1 * x2 * y1 * y2;
    BigInt x3 = ((x1 * y2 + x2 * y1)) * inv(one + dtemp);
    BigInt y3 = ((y1 * y2 + x1 * x2)) * inv(one - dtemp);

    return [x3 % q, y3 % q];
  }

  static List<BigInt> scalarmult(List<BigInt> P, BigInt e) {
    if (e == zero) {
      return [zero, one];
    }
    List<BigInt> Q = scalarmult(P, e ~/ two);
    Q = edwards(Q, Q);
    if (e % two != zero) Q = edwards(Q, P);
    return Q;
  }

  static Uint8List encodeint(BigInt y) {    
    return _toBytes(y);
  }

  static Uint8List encodepoint(List<BigInt> P) {
    BigInt x = P[0];
    BigInt y = P[1];
    Uint8List out = encodeint(y);
    out[out.length - 1] |= (x % two != zero) ? 0x80 : 0;
    return out;
  }

  static int bit(Uint8List h, int i) {
    return h[i ~/ 8] >> (i % 8) & 1;
  }

  static Uint8List publickey(HashFunc f, Uint8List sk) {
    Uint8List h = hash(f, sk);
    BigInt a = two.pow(b - 2);
    for (int i = 3; i < (b - 2); i++) {
      BigInt apart = two.pow(i) * BigInt.from(bit(h, i));
      a = a + apart;
    }
    List<BigInt> A = scalarmult(B, a);
    return encodepoint(A);
  }

  static BigInt hint(HashFunc f, Uint8List m) {
    Uint8List h = hash(f, m);
    BigInt hsum = zero;
    for (int i = 0; i < 2 * b; i++) {
      hsum = hsum + (two.pow(i) * BigInt.from(bit(h, i)));
    }
    return hsum;
  }

  static Uint8List signature(HashFunc f, Uint8List m, Uint8List sk, Uint8List pk) {
    Uint8List h = hash(f, sk);
    BigInt a = two.pow(b - 2);
    for (int i = 3; i < (b - 2); i++) {
      a = a + (two.pow(i) * BigInt.from(bit(h, i)));
    }

    Uint8List rsub = Uint8List(b ~/ 8 + m.length);
    int j = 0;
    for (int i = b ~/ 8; i < b ~/ 8 + (b ~/ 4 - b ~/ 8); i++) {
      rsub[j] = h[i];
      j++;
    }
    for (int i = 0; i < m.length; i++) {
      rsub[j] = m[i];
      j++;
    }
    BigInt r = hint(f, rsub);
    List<BigInt> R = scalarmult(B, r);
    Uint8List stemp = Uint8List(32 + pk.length + m.length);

    Uint8List point = encodepoint(R);
    j = 0;
    for (int i = 0; i < point.length; i++) {
      stemp[j] = point[i];
      j++;
    }
    for (int i = 0; i < pk.length; i++) {
      stemp[j] = pk[i];
      j++;
    }
    for (int i = 0; i < m.length; i++) {
      stemp[j] = m[i];
      j++;
    }
    BigInt S = (r + (hint(f, stemp) * a)) % l;
    Uint8List ur = encodepoint(R);
    Uint8List us = encodeint(S);
    Uint8List out = Uint8List(ur.length + us.length);
    j = 0;
    for (int i = 0; i < ur.length; i++) {
      out[j] = ur[i];
      j++;
    }
    for (int i = 0; i < us.length; i++) {
      out[j] = us[i];
      j++;
    }
    return out;
  }

  static bool isoncurve(List<BigInt> P) {
    BigInt x = P[0];
    BigInt y = P[1];

    BigInt xx = x * x;
    BigInt yy = y * y;
    BigInt dxxyy = d * yy * xx;
    return (-xx + yy - one - dxxyy) % q == zero;
  }

  static BigInt decodeint(Uint8List s) {
    return _fromBytes(s) & un;
  }

  static List<BigInt> decodepoint(Uint8List s) {
    Uint8List ybyte = Uint8List(s.length);
    for (int i = 0; i < s.length; i++) {
      ybyte[i] = s[s.length - 1 - i];
    }
    BigInt fb = _fromBytes(s);
    BigInt y = fb & un;
    BigInt x = xrecover(y);
    if ((x % two != zero) ? 1 : 0 != bit(s, b - 1)) {
      x = q - x;
    }
    List<BigInt> P = [x, y];
    assert(isoncurve(P));
    return P;
  }

  static bool checkvalid(HashFunc f, Uint8List s, Uint8List m, Uint8List pk) {
    assert(s.length == b ~/ 4);
    assert(pk.length == b ~/ 8);

    Uint8List rbyte = _copyRange(s, 0, b ~/ 8);
    List<BigInt> R = decodepoint(rbyte);
    List<BigInt> A = decodepoint(pk);

    Uint8List sbyte = _copyRange(s, b ~/ 8, b ~/ 4);
    BigInt S = decodeint(sbyte);

    Uint8List stemp = Uint8List(32 + pk.length + m.length);
    Uint8List point = encodepoint(R);
    int j = 0;
    for (int i = 0; i < point.length; i++) {
      stemp[j] = point[i];
      j++;
    }
    for (int i = 0; i < pk.length; i++) {
      stemp[j] = pk[i];
      j++;
    }
    for (int i = 0; i < m.length; i++) {
      stemp[j] = m[i];
      j++;
    }
    BigInt h = hint(f, stemp);
    List<BigInt> ra = scalarmult(B, S);
    List<BigInt> rb = edwards(R, scalarmult(A, h));
    if (!(ra[0] == rb[0]) || !(ra[1] == rb[1])) {
      return false;
    }
    return true;
  }

  static BigInt _fromBytes(Uint8List bytes) {
    BigInt read(int start, int end) {
      if (end - start <= 4) {
        int result = 0;
        for (int i = end - 1; i >= start; i--) {
          result = result * 256 + bytes[i];
        }
        return new BigInt.from(result);
      }
      int mid = start + ((end - start) >> 1);
      var result = read(start, mid) + read(mid, end) * (BigInt.one << ((mid - start) * 8));
      return result;
    }
    return read(0, bytes.length);
  }

  static Uint8List _toBytes(BigInt number) {
    // Not handling negative numbers. Decide how you want to do that.
    int bytes = (number.bitLength + 7) >> 3;
    var b256 = new BigInt.from(256);
    var result = new Uint8List(bytes);
    for (int i = 0; i < bytes; i++) {
      result[i] = number.remainder(b256).toInt();
      number = number >> 8;
    }
    return result;
  }

  static Uint8List _copyRange(Uint8List src, int from, int to) {
    Uint8List dst = Uint8List(to - from);
    int j = 0;
    for (int i = from; i < to; i++) {
      dst[j] = src[i];
      j++;
    }
    return dst;
  }

}
