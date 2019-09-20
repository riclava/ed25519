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
import 'dart:typed_data';

import 'package:blake2b/blake2b.dart';
import 'package:blake2b/utils.dart' as butils;
import 'package:flutter_test/flutter_test.dart';

import 'package:ed25519/ed25519.dart';
import 'package:hex/hex.dart';

Uint8List blake2bHashFunc(Uint8List m) {
  Uint8List bytes = Uint8List(64);
  var b = Blake2b(512);
  b.update(m, 0, m.length);
  b.digest(bytes, 0);
  return bytes;
}

void main() {
  
  test('adds one to input values', () {
    String expectPk = "c9f52a9ae9683a8d304c65dd87d88f1a7628eb55bd7aaba6d5d4067dde804f9c";
    String expectSign = "0029e755645c11dce87d6c16a1af9ba6559fca97c98fe282b0683708d8a6067fc5e3b007826b2d6e95c5a0c31b82e340e165679ff6cefb7de5aa744bc670df0c";

    String hsk = "11E2A3D65792FFA9E8ED15857EF13C562CF7C9BFBBFFD66FFA9B08EC709C8F0A";
    List<int> isk = HEX.decode(hsk);
    var sk = butils.Utils.int8list2uint8list(Int8List.fromList(isk));

    var pk = Ed25519.publickey(blake2bHashFunc, sk);
    var hexpk = HEX.encode(pk);
    assert(hexpk == expectPk);
    print(hexpk);

    Uint8List msg = Uint8List.fromList("This is a message".codeUnits);
    Uint8List sign = Ed25519.signature(blake2bHashFunc, msg, sk, pk);
    String hexSign = HEX.encode(sign);
    assert(hexSign == expectSign);
    print(hexSign);
    
    var valid = Ed25519.checkvalid(blake2bHashFunc, sign, msg, pk);
    assert(valid == true);
    print(valid);

  });
}
