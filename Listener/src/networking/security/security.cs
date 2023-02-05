using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;

namespace Listener {
    class Security {
        public struct EncryptionStruct {
            public int iKey1;
            public int iKey2;
            /*public int iKey3;
            public int iKey4;
            public int iKey5;
            public int iKey6;
            public int iKey7;
            public int iKey8;
            public int iKey9;
            public int iKey10;*/
            public int iHash;

            // enc only
            public long Time;
        }

        public static byte[] BinaryFirstKeys = new byte[] {
            0xe4, 0xec, 0xa3, 0x38, 0x6c, 0xc5, 0x70, 0xdd,
            0x9f, 0xb0, 0x6b, 0xce, 0x97, 0x4, 0x54, 0x63,
            0xae, 0x8e, 0x37, 0xa, 0xdb, 0xc2, 0x15, 0xda,
            0x36, 0xb3, 0x38, 0x34, 0xac, 0x61, 0xe0, 0x11,
            0xce, 0x84, 0xc8, 0x3b, 0x4a, 0x39, 0x98, 0xe9,
            0x6a, 0x84, 0x39, 0x81, 0x88, 0x8d, 0xe4, 0xb6,
            0x9c, 0x9b
        };

        public static int[] BinarySecondKeys = new int[] {
            0x18760, 0x1872a, 0x18770, 0x18762, 0x1870c, 0x186e6,
            0x1874d, 0x1874c, 0x1878a, 0x1871b, 0x30d5e, 0x30dfc,
            0x30da5, 0x30dc4, 0x30d76, 0x30e03, 0x30d6f, 0x30d44,
            0x30dc0, 0x30d9d, 0x493f2, 0x493ea, 0x493ea, 0x49413,
            0x49407, 0x4949d, 0x49461, 0x49471, 0x493f9, 0x4948e,
            0x61b4d, 0x61ada, 0x61ab9, 0x61a9e, 0x61b1c, 0x61b25,
            0x61b64, 0x61aca, 0x61b52, 0x61b4f, 0x7a166, 0x7a210,
            0x7a1ac, 0x7a14b, 0x7a214, 0x7a163, 0x7a18e, 0x7a145,
            0x7a1e6, 0x7a20f
        };

        public static void RC4(ref byte[] Data, byte[] Key, int startOffset = 0) {
            byte num;
            int num2;
            int index = 0;

            byte[] buffer = new byte[0x100];
            byte[] buffer2 = new byte[0x100];

            for (num2 = 0; num2 < 0x100; num2++) {
                buffer[num2] = (byte)num2;
                buffer2[num2] = Key[num2 % Key.GetLength(0)];
            }

            for (num2 = 0; num2 < 0x100; num2++) {
                index = ((index + buffer[num2]) + buffer2[num2]) % 0x100;
                num = buffer[num2];
                buffer[num2] = buffer[index];
                buffer[index] = num;
            }

            num2 = index = 0;

            for (int i = startOffset; i < Data.GetLength(0); i++) {
                num2 = (num2 + 1) % 0x100;
                index = (index + buffer[num2]) % 0x100;
                num = buffer[num2];
                buffer[num2] = buffer[index];
                buffer[index] = num;
                int num5 = (buffer[num2] + buffer[index]) % 0x100;
                Data[i] = (byte)(Data[i] ^ buffer[num5]);
            }
        }

        public static void EncryptKeys(ref EncryptionStruct data)
        {
            data.iKey1 ^= 0x18762;
            data.iKey1 += 1337;
            data.iKey1 -= 0x10;
            data.iKey1 ^= 0x10;
            data.iKey1 += 0x11;
            data.iKey1 ^= 0x49471;
            data.iKey1 ^= 0x7a145 << 8;
            data.iKey1 += 0x22;
            data.iKey1 ^= 0x12;
            data.iKey1++;
            data.iKey1 ^= (0x88 + 0x9c + 0x15) - 1;
            data.iKey1 += 88;
            data.iKey1 ^= 2;
            data.iKey1 -= 2;
            data.iKey1 += 3;
            data.iKey1 ^= (0x15 << 16) + 1337;
            data.iKey1 ^= (((0x35 + 0x16) - 4) + 2334) * -1;
            data.iKey1 *= -1;

            data.iKey2 ^= 12;
            data.iKey2 += 0x55 << 4;
            data.iKey2 ^= 1337;
            data.iKey2 += 12;
            data.iKey2 ^= 99;
            data.iKey2 += 0x7a20f;
            data.iKey2 -= 0x49407;
            data.iKey2 ^= 0x45;
            data.iKey2 ^= 0xFFFF;
            data.iKey2 += 0xFF;
            data.iKey2 -= 0x12;
            data.iKey2 ^= 0x123;
            data.iKey2 ^= 3;
            data.iKey2 ^= 23;
            data.iKey2 ^= 1212;
            data.iKey2 ^= 9;
            data.iKey2 += 12;
            data.iKey2 += 89;
            data.iKey2 += data.iKey1 ^ 12;
            data.iKey2 ^= data.iKey1 - 100;
            data.iKey2 += data.iKey1 ^ 13;
            data.iKey2 += data.iKey1 ^ 14;
            data.iKey2 += data.iKey1 ^ 15;
            data.iKey2 += data.iKey1 ^ 16;
            data.iKey2 += data.iKey1 ^ 17;
            data.iKey2 ^= (data.iKey1 ^ data.iKey1) + (data.iKey1 ^ data.iKey1 ^ data.iKey1 ^ data.iKey1 ^ data.iKey1 ^ data.iKey1 ^ data.iKey1 ^ 0x88) + data.iKey1 - (data.iKey1 << 8);
            data.iKey2 ^= (data.iKey1 ^ data.iKey1) + (data.iKey1 ^ data.iKey1 ^ data.iKey1 ^ data.iKey1 ^ data.iKey1 ^ data.iKey1 ^ data.iKey1 ^ 0x88) + data.iKey1 - (data.iKey1 << 16);
        }


        /*public static void EncryptKeys(ref EncryptionStruct data) {
            data.iKey1 ^= BinarySecondKeys[3];
            data.iKey1 += 1337;
            data.iKey1 -= 0x10;
            data.iKey1 ^= 0x10;
            data.iKey1 += 0x11;
            data.iKey1 ^= BinarySecondKeys[2];
            data.iKey1 ^= BinarySecondKeys[1] << 8;
            data.iKey1 += BinaryFirstKeys[12];
            data.iKey1 ^= 0x12;
            data.iKey1++;
            data.iKey1 ^= (BinaryFirstKeys[40] + BinaryFirstKeys[2] + BinaryFirstKeys[13]) - 1;
            data.iKey1 += 88;
            data.iKey1 ^= 2;
            data.iKey1 -= 2;
            data.iKey1 += 3;
            data.iKey1 ^= (BinaryFirstKeys[6] << 16) + 1337;
            data.iKey1 ^= (((BinaryFirstKeys[5] + 0x16) - 4) + 2334) * -1;
            data.iKey1 *= -1;

            data.iKey2 ^= 12;
            data.iKey2 += BinaryFirstKeys[32] << 4;
            data.iKey2 ^= 1337;
            data.iKey2 += 12;
            data.iKey2 ^= 99;
            data.iKey2 += BinarySecondKeys[31];
            data.iKey2 -= BinarySecondKeys[33];
            data.iKey2 ^= 0x45;
            data.iKey2 ^= 0xFFFF;
            data.iKey2 += 0xFF;
            data.iKey2 -= 0x12;
            data.iKey2 ^= 0x123;
            data.iKey2 ^= 3;
            data.iKey2 ^= 23;
            data.iKey2 ^= 1212;
            data.iKey2 ^= 9;
            data.iKey2 += 12;
            data.iKey2 += 91 - 2;
            data.iKey2 += data.iKey1 ^ 12;
            data.iKey2 ^= data.iKey1 - 100;
            data.iKey2 += data.iKey1 ^ 13;
            data.iKey2 += data.iKey1 ^ 14;
            data.iKey2 += data.iKey1 ^ 15;
            data.iKey2 += data.iKey1 ^ 16;
            data.iKey2 += data.iKey1 ^ 17;

            data.iKey3++;
            data.iKey3 ^= 12;
            data.iKey3 += 231;
            data.iKey3 ^= BinarySecondKeys[7];
            data.iKey3 ^= BinarySecondKeys[6];
            data.iKey3 ^= BinarySecondKeys[5];
            data.iKey3 ^= BinarySecondKeys[4];
            data.iKey3 ^= BinarySecondKeys[3];
            data.iKey3 ^= BinarySecondKeys[2];
            data.iKey3 ^= BinarySecondKeys[1];
            data.iKey3 *= -1;
            data.iKey3 += 123;
            data.iKey3 *= -1;
            data.iKey3 ^= 123123;
            data.iKey3--;
            data.iKey3++;
            data.iKey3--;
            data.iKey3 += 33;
            data.iKey3 ^= BinaryFirstKeys[2] + 1337;
            data.iKey3 ^= data.iKey2;

            data.iKey4 ^= 69;
            data.iKey4--;
            data.iKey4 += 1941;
            data.iKey4 ^= 1945;
            data.iKey4 -= 100;
            data.iKey4 ^= data.iKey3 + 1337;
            data.iKey4 ^= (data.iKey1) + 100;
            data.iKey4 ^= data.iKey3 ^ data.iKey2 ^ data.iKey1 + 69;
            data.iKey4 ^= data.iKey3 ^ data.iKey2 ^ data.iKey1 + 70;
            data.iKey4 ^= data.iKey3 ^ data.iKey2 ^ data.iKey1 + 71;
            data.iKey4 ^= data.iKey3 ^ data.iKey2 ^ data.iKey1 + 72;
            data.iKey4 ^= data.iKey3 ^ data.iKey2 ^ data.iKey1 + 73;
            data.iKey4 ^= data.iKey3 ^ data.iKey2 ^ data.iKey1 + 74;
            data.iKey4 ^= data.iKey3 ^ data.iKey2 ^ data.iKey1 + 75;
            data.iKey4 ^= data.iKey3 ^ data.iKey2 ^ data.iKey1 + 61;
            data.iKey4 ^= data.iKey3 ^ data.iKey2 ^ data.iKey1 + 22;
            data.iKey4 ^= data.iKey3 ^ data.iKey2 ^ data.iKey1 + 564;

            data.iKey5 -= 1337;
            data.iKey5 ^= BinarySecondKeys[4];
            data.iKey5 += BinarySecondKeys[39] ^ 122;
            data.iKey5 += (BinarySecondKeys[39] ^ 122) << 8;
            data.iKey5 += (BinarySecondKeys[2] ^ 56) << 8;
            data.iKey5 += 999;
            data.iKey5 ^= 1337;
            data.iKey5 ^= 0x1337;
            data.iKey5 += 69;
            data.iKey5 ^= 333;
            data.iKey5 ^= 666;
            data.iKey5 += 123;
            data.iKey5 ^= (data.iKey4 << 16) + 12;
            data.iKey5 += data.iKey1 << 2;
            data.iKey5 ^= 12345;
            data.iKey5 += BinaryFirstKeys[43];
            data.iKey5 += BinaryFirstKeys[44];
            data.iKey5 += BinaryFirstKeys[45];
            data.iKey5 += BinaryFirstKeys[46];
            data.iKey5 += BinaryFirstKeys[47];
            data.iKey5 += BinaryFirstKeys[48];
            data.iKey5 += BinaryFirstKeys[23];
            data.iKey5 += BinaryFirstKeys[25] << 8;

            data.iKey6 ^= 1234;
            data.iKey6 += 1334;
            data.iKey6 ^= 22;
            data.iKey6 ^= data.iKey5 + 1337;
            data.iKey6 ^= BinarySecondKeys[44];
            data.iKey6 ^= BinarySecondKeys[2];
            data.iKey6 += BinarySecondKeys[2];
            data.iKey6 -= BinarySecondKeys[3];
            data.iKey6 += BinarySecondKeys[4];
            data.iKey6 ^= 65;
            data.iKey6 += (data.iKey5 << 8);
            data.iKey6 -= (data.iKey3 << 8);
            data.iKey6 ^= (data.iKey2 << 8);
            data.iKey6 ^= (data.iKey1 << 8);
            data.iKey6 ^= data.iKey1;
            data.iKey6 += BinarySecondKeys[8];

            data.iKey7 ^= 43;
            data.iKey7 += BinarySecondKeys[2] + data.iKey3;
            data.iKey7 ^= 123;
            data.iKey7 += BinarySecondKeys[1] ^ data.iKey6 ^ data.iKey3 ^ data.iKey1;
            data.iKey7 ^= 6969;
            data.iKey7 ^= BinaryFirstKeys[12];
            data.iKey7 += BinaryFirstKeys[0] + BinaryFirstKeys[1] + BinaryFirstKeys[2] + BinaryFirstKeys[3] + BinaryFirstKeys[4] + BinaryFirstKeys[5] + BinaryFirstKeys[4] + (BinaryFirstKeys[41] ^ 12) + (BinaryFirstKeys[44] << 8);
            data.iKey7 ^= 100;
            data.iKey7 ^= 0x12;

            data.iKey8 ^= 1337;
            data.iKey8 += BinarySecondKeys[4];
            data.iKey8 -= BinaryFirstKeys[28] * 10;
            data.iKey8 ^= data.iKey7 - 1000;
            data.iKey8 *= -1;
            data.iKey8 += BinarySecondKeys[18];
            data.iKey8 ^= (data.iKey1 ^ 10);
            data.iKey8 ^= (data.iKey2 - 100) + 12 ^ 1337;
            data.iKey8 += 1337;
            data.iKey8 += 999;
            data.iKey8 += 666;
            data.iKey8 ^= 123;
            data.iKey8 -= 9;
            data.iKey8++;
            data.iKey8 ^= BinaryFirstKeys[12];
        }*/

        public static void DecryptKeys(ref EncryptionHeader data) {
            data.iKey8 ^= BinaryFirstKeys[12];
            data.iKey8--;
            data.iKey8 += 9;
            data.iKey8 ^= 123;
            data.iKey8 -= 666;
            data.iKey8 -= 999;
            data.iKey8 -= 1337;
            data.iKey8 ^= (data.iKey2 - 100) + 12 ^ 1337;
            data.iKey8 ^= (data.iKey1 ^ 10);
            data.iKey8 -= BinarySecondKeys[18];
            data.iKey8 *= -1;
            data.iKey8 ^= data.iKey7 - 1000;
            data.iKey8 += BinaryFirstKeys[28] * 10;
            data.iKey8 -= BinarySecondKeys[4];
            data.iKey8 ^= 1337;

            data.iKey7 ^= 0x12;
            data.iKey7 ^= 100;
            data.iKey7 -= BinaryFirstKeys[0] + BinaryFirstKeys[1] + BinaryFirstKeys[2] + BinaryFirstKeys[3] + BinaryFirstKeys[4] + BinaryFirstKeys[5] + BinaryFirstKeys[4] + (BinaryFirstKeys[41] ^ 12) + (BinaryFirstKeys[44] << 8);
            data.iKey7 ^= BinaryFirstKeys[12];
            data.iKey7 ^= 6969;
            data.iKey7 -= BinarySecondKeys[1] ^ data.iKey6 ^ data.iKey3 ^ data.iKey1;
            data.iKey7 ^= 123;
            data.iKey7 -= BinarySecondKeys[2] + data.iKey3;
            data.iKey7 ^= 43;

            data.iKey6 -= BinarySecondKeys[8];
            data.iKey6 ^= data.iKey1;
            data.iKey6 ^= (data.iKey1 << 8);
            data.iKey6 ^= (data.iKey2 << 8);
            data.iKey6 += (data.iKey3 << 8);
            data.iKey6 -= (data.iKey5 << 8);
            data.iKey6 ^= 65;
            data.iKey6 -= BinarySecondKeys[4];
            data.iKey6 += BinarySecondKeys[3];
            data.iKey6 -= BinarySecondKeys[2];
            data.iKey6 ^= BinarySecondKeys[2];
            data.iKey6 ^= BinarySecondKeys[44];
            data.iKey6 ^= data.iKey5 + 1337;
            data.iKey6 ^= 22;
            data.iKey6 -= 1334;
            data.iKey6 ^= 1234;

            data.iKey5 -= BinaryFirstKeys[25] << 8;
            data.iKey5 -= BinaryFirstKeys[23];
            data.iKey5 -= BinaryFirstKeys[48];
            data.iKey5 -= BinaryFirstKeys[47];
            data.iKey5 -= BinaryFirstKeys[46];
            data.iKey5 -= BinaryFirstKeys[45];
            data.iKey5 -= BinaryFirstKeys[44];
            data.iKey5 -= BinaryFirstKeys[43];
            data.iKey5 ^= 12345;
            data.iKey5 -= data.iKey1 << 2;
            data.iKey5 ^= (data.iKey4 << 16) + 12;
            data.iKey5 -= 123;
            data.iKey5 ^= 666;
            data.iKey5 ^= 333;
            data.iKey5 -= 69;
            data.iKey5 ^= 0x1337;
            data.iKey5 ^= 1337;
            data.iKey5 -= 999;
            data.iKey5 -= (BinarySecondKeys[2] ^ 56) << 8;
            data.iKey5 -= (BinarySecondKeys[39] ^ 122) << 8;
            data.iKey5 -= BinarySecondKeys[39] ^ 122;
            data.iKey5 ^= BinarySecondKeys[4];
            data.iKey5 += 1337;

            data.iKey4 ^= data.iKey3 ^ data.iKey2 ^ data.iKey1 + 564;
            data.iKey4 ^= data.iKey3 ^ data.iKey2 ^ data.iKey1 + 22;
            data.iKey4 ^= data.iKey3 ^ data.iKey2 ^ data.iKey1 + 61;
            data.iKey4 ^= data.iKey3 ^ data.iKey2 ^ data.iKey1 + 75;
            data.iKey4 ^= data.iKey3 ^ data.iKey2 ^ data.iKey1 + 74;
            data.iKey4 ^= data.iKey3 ^ data.iKey2 ^ data.iKey1 + 73;
            data.iKey4 ^= data.iKey3 ^ data.iKey2 ^ data.iKey1 + 72;
            data.iKey4 ^= data.iKey3 ^ data.iKey2 ^ data.iKey1 + 71;
            data.iKey4 ^= data.iKey3 ^ data.iKey2 ^ data.iKey1 + 70;
            data.iKey4 ^= data.iKey3 ^ data.iKey2 ^ data.iKey1 + 69;
            data.iKey4 ^= (data.iKey1) + 100;
            data.iKey4 ^= data.iKey3 + 1337;
            data.iKey4 += 100;
            data.iKey4 ^= 1945;
            data.iKey4 -= 1941;
            data.iKey4++;
            data.iKey4 ^= 69;

            data.iKey3 ^= data.iKey2;
            data.iKey3 ^= BinaryFirstKeys[2] + 1337;
            data.iKey3 -= 33;
            data.iKey3++;
            data.iKey3--;
            data.iKey3++;
            data.iKey3 ^= 123123;
            data.iKey3 *= -1;
            data.iKey3 -= 123;
            data.iKey3 *= -1;
            data.iKey3 ^= BinarySecondKeys[1];
            data.iKey3 ^= BinarySecondKeys[2];
            data.iKey3 ^= BinarySecondKeys[3];
            data.iKey3 ^= BinarySecondKeys[4];
            data.iKey3 ^= BinarySecondKeys[5];
            data.iKey3 ^= BinarySecondKeys[6];
            data.iKey3 ^= BinarySecondKeys[7];
            data.iKey3 -= 231;
            data.iKey3 ^= 12;
            data.iKey3--;

            data.iKey2 -= data.iKey1 ^ 17;
            data.iKey2 -= data.iKey1 ^ 16;
            data.iKey2 -= data.iKey1 ^ 15;
            data.iKey2 -= data.iKey1 ^ 14;
            data.iKey2 -= data.iKey1 ^ 13;
            data.iKey2 ^= data.iKey1 - 100;
            data.iKey2 -= data.iKey1 ^ 12;
            data.iKey2 -= 91 - 2;
            data.iKey2 -= 12;
            data.iKey2 ^= 9;
            data.iKey2 ^= 1212;
            data.iKey2 ^= 23;
            data.iKey2 ^= 3;
            data.iKey2 ^= 0x123;
            data.iKey2 += 0x12;
            data.iKey2 -= 0xFF;
            data.iKey2 ^= 0xFFFF;
            data.iKey2 ^= 0x45;
            data.iKey2 += BinarySecondKeys[33];
            data.iKey2 -= BinarySecondKeys[31];
            data.iKey2 ^= 99;
            data.iKey2 -= 12;
            data.iKey2 ^= 1337;
            data.iKey2 -= BinaryFirstKeys[32] << 4;
            data.iKey2 ^= 12;

            data.iKey1 *= -1;
            data.iKey1 ^= (((BinaryFirstKeys[5] + 0x16) - 4) + 2334) * -1;
            data.iKey1 ^= (BinaryFirstKeys[6] << 16) + 1337;
            data.iKey1 -= 3;
            data.iKey1 += 2;
            data.iKey1 ^= 2;
            data.iKey1 -= 88;
            data.iKey1 ^= (BinaryFirstKeys[40] + BinaryFirstKeys[2] + BinaryFirstKeys[13]) - 1;
            data.iKey1--;
            data.iKey1 ^= 0x12;
            data.iKey1 -= BinaryFirstKeys[12];
            data.iKey1 ^= BinarySecondKeys[1] << 8;
            data.iKey1 ^= BinarySecondKeys[2];
            data.iKey1 -= 0x11;
            data.iKey1 ^= 0x10;
            data.iKey1 += 0x10;
            data.iKey1 -= 1337;
            data.iKey1 ^= BinarySecondKeys[3];
        }

        public static void EncryptHash(ref EncryptionStruct data, Header header)
        {
            data.iHash -= 1000000000;
            data.iHash ^= 69696969;
            data.iHash += 123;
            data.iHash ^= (data.iKey1 << 2);
            data.iHash -= 1000;
            data.iHash += (data.iKey2 << 24) ^ 13;
            data.iHash -= (data.iKey2 / 2);
            data.iHash += (data.iKey1 ^ 1234);
            data.iHash ^= data.iKey2;
            data.iHash += data.iKey1;
            data.iHash ^= 111111;
            data.iHash ^= 121212;
            data.iHash ^= 131313;
            data.iHash ^= 141414;
            data.iHash ^= 151515;
            data.iHash ^= 161616;
            data.iHash ^= 171717;
            data.iHash ^= 181818;
            data.iHash ^= 191919;
            data.iHash--;
            data.iHash += 2;
            data.iHash ^= (data.iKey1 * 2);
            data.iHash ^= (data.iKey2 ^ data.iKey1) + (data.iKey1 ^ data.iKey2 ^ data.iKey2 ^ data.iKey1 ^ data.iKey2 ^ data.iKey2 ^ data.iKey1 ^ 0x88) + data.iKey1 - (data.iKey2 << 8);
            data.iHash ^= (data.iKey1 ^ data.iKey2) + (data.iKey1 ^ data.iKey2 ^ data.iKey2 ^ data.iKey1 ^ data.iKey2 ^ data.iKey2 ^ data.iKey1 ^ 0x88) + data.iKey2 - (data.iKey2 << 16);
            data.iHash ^= (data.iKey1 ^ data.iKey2) + (data.iKey1 ^ data.iKey2 ^ data.iKey2 ^ data.iKey1 ^ data.iKey2 ^ data.iKey2 ^ data.iKey1 ^ 0x88) + data.iKey1 - (data.iKey2 << 24);
            data.iHash ^= (data.iKey2 ^ data.iKey2) + (data.iKey1 ^ data.iKey2 ^ data.iKey2 ^ data.iKey1 ^ data.iKey2 ^ data.iKey2 ^ data.iKey1 ^ 0x88) + data.iKey2 - (data.iKey2 << 24);
            data.iHash ^= (data.iKey2 ^ data.iKey1) + (data.iKey1 ^ data.iKey2 ^ data.iKey2 ^ data.iKey1 ^ data.iKey2 ^ data.iKey2 ^ data.iKey1 ^ 0x88) + data.iKey1 - (data.iKey2 << 24);
            data.iHash ^= (data.iKey1 ^ data.iKey2) + (data.iKey1 ^ data.iKey2 ^ data.iKey2 ^ data.iKey1 ^ data.iKey2 ^ data.iKey2 ^ data.iKey1 ^ 0x88) + data.iKey2 - (data.iKey2 << 24);
            data.iHash ^= (data.iKey1 ^ data.iKey2) + (data.iKey1 ^ data.iKey2 ^ data.iKey2 ^ data.iKey1 ^ data.iKey2 ^ data.iKey2 ^ data.iKey1 ^ 0x88) + data.iKey1 - (data.iKey2 << 16);
            data.iHash ^= (data.iKey2 ^ data.iKey2) + (data.iKey1 ^ data.iKey2 ^ data.iKey2 ^ data.iKey1 ^ data.iKey2 ^ data.iKey2 ^ data.iKey1 ^ 0x88) + data.iKey2 - (data.iKey2 << 8);
            data.iHash ^= (data.iKey2 ^ data.iKey1) + (data.iKey1 ^ data.iKey2 ^ data.iKey2 ^ data.iKey1 ^ data.iKey2 ^ data.iKey2 ^ data.iKey1 ^ 0x88) + data.iKey1 - (data.iKey2 << 4);
            data.iHash ^= (data.iKey1 ^ data.iKey1) + (data.iKey1 ^ data.iKey2 ^ data.iKey2 ^ data.iKey1 ^ data.iKey2 ^ data.iKey2 ^ data.iKey1 ^ 0x88) + data.iKey2 - (data.iKey2 << 2);

            for (int i = 0; i < 0x10; i++)
            {
                data.iHash ^= (header.szRandomKey[i] ^ header.szRC4Key[i]);
            }
        }


        /*public static void EncryptHash(ref EncryptionStruct data) {
            data.Time = Utils.GetTimeStamp();
            data.iHash = (int)data.Time;
            data.iHash ^= 13;
            data.iHash += 1337;
            data.iHash *= -1;
            data.iHash ^= data.iKey1 + 123;
            data.iHash ^= BinarySecondKeys[data.iKey1];
            data.iHash -= (data.iKey2 ^ 123);
            data.iHash ^= (BinarySecondKeys[data.iKey1] + BinarySecondKeys[data.iKey2]);
            data.iHash ^= 69;
            data.iHash += BinaryFirstKeys[data.iKey1] * 69;
            data.iHash -= BinarySecondKeys[0];
            data.iHash ^= BinarySecondKeys[43];
            data.iHash += data.iKey4;
            data.iHash ^= data.iKey8;
            data.iHash ^= (data.iKey1 ^ 13) + (data.iKey2 ^ 23) + (data.iKey3 ^ 33) + (data.iKey4 ^ BinarySecondKeys[data.iKey1]);
            data.iHash ^= 98;
            data.iHash += (data.iKey5 << 16) ^ 2;
            data.iHash += (data.iKey9 * 2) ^ 14 + (123 ^ BinarySecondKeys[2]);
            data.iHash ^= 6969;
            data.iHash ^= (data.iKey1 ^ data.iKey2 ^ data.iKey3 ^ data.iKey4 ^ data.iKey5 ^ data.iKey6 ^ data.iKey7 ^ data.iKey8 ^ data.iKey9);
            data.iHash += 1337;
            data.iHash ^= 99;
            data.iHash ^= 99;
            data.iHash += 1331;
            data.iHash *= -1;
            data.iHash ^= data.iKey5 + 1234;
            data.iHash ^= 96;
            data.iHash += BinaryFirstKeys[data.iKey2] * 52;
            data.iHash += BinarySecondKeys[8];
            data.iHash ^= BinarySecondKeys[21];
            data.iHash += data.iKey4;
            data.iHash ^= 91;
            data.iHash ^= 92;
            data.iHash ^= 93;
            data.iHash ^= 94;
            data.iHash ^= 95;
            data.iHash ^= 96;
            data.iHash ^= 97;
            data.iHash ^= 98;
            data.iHash ^= 4545;
            data.iHash ^= (data.iKey2 ^ data.iKey2 ^ data.iKey3 ^ data.iKey4 ^ data.iKey3 ^ data.iKey6 ^ data.iKey7 ^ data.iKey5 ^ data.iKey9);
            data.iHash ^= (data.iKey2 + data.iKey2 + data.iKey3 + data.iKey4 + data.iKey3 + data.iKey6 + data.iKey7 + data.iKey5 + data.iKey9);
            data.iHash ^= (data.iKey2 * data.iKey2 * data.iKey3 * data.iKey4 * data.iKey3 * data.iKey6 * data.iKey7 * data.iKey5 * data.iKey9);
            data.iHash ^= 22;
            data.iHash ^= data.iKey2 ^ data.iKey1 + data.iKey3 ^ data.iKey4 ^ data.iKey2 ^ data.iKey8 ^ data.iKey9 ^ data.iKey2 ^ data.iKey1 ^ BinaryFirstKeys[data.iKey1] + data.iKey3 - data.iKey2 << 8;
            data.iHash ^= data.iKey1 ^ data.iKey2 + data.iKey3 ^ data.iKey4 ^ data.iKey2 ^ data.iKey8 ^ data.iKey9 ^ data.iKey2 ^ data.iKey1 ^ BinaryFirstKeys[data.iKey2] + data.iKey3 - data.iKey2 << 16;
            data.iHash ^= data.iKey1 ^ data.iKey2 + data.iKey3 ^ data.iKey4 ^ data.iKey2 ^ data.iKey8 ^ data.iKey9 ^ data.iKey2 ^ data.iKey1 ^ BinaryFirstKeys[data.iKey1] + data.iKey3 - data.iKey2 << 24;
            data.iHash ^= data.iKey2 ^ data.iKey2 + data.iKey3 ^ data.iKey4 ^ data.iKey2 ^ data.iKey8 ^ data.iKey9 ^ data.iKey2 ^ data.iKey1 ^ BinaryFirstKeys[data.iKey2] + data.iKey3 - data.iKey2 << 32;
            data.iHash ^= data.iKey2 ^ data.iKey1 + data.iKey3 ^ data.iKey4 ^ data.iKey2 ^ data.iKey8 ^ data.iKey9 ^ data.iKey2 ^ data.iKey1 ^ BinaryFirstKeys[data.iKey1] + data.iKey3 - data.iKey2 << 32;
            data.iHash ^= data.iKey1 ^ data.iKey2 + data.iKey3 ^ data.iKey4 ^ data.iKey2 ^ data.iKey8 ^ data.iKey9 ^ data.iKey2 ^ data.iKey1 ^ BinaryFirstKeys[data.iKey2] + data.iKey3 - data.iKey2 << 24;
            data.iHash ^= data.iKey1 ^ data.iKey2 + data.iKey3 ^ data.iKey4 ^ data.iKey2 ^ data.iKey8 ^ data.iKey9 ^ data.iKey2 ^ data.iKey1 ^ BinaryFirstKeys[data.iKey1] + data.iKey3 - data.iKey2 << 16;
            data.iHash ^= data.iKey2 ^ data.iKey2 + data.iKey3 ^ data.iKey4 ^ data.iKey2 ^ data.iKey8 ^ data.iKey9 ^ data.iKey2 ^ data.iKey1 ^ BinaryFirstKeys[data.iKey2] + data.iKey3 - data.iKey2 << 8;
            data.iHash ^= data.iKey2 ^ data.iKey1 + data.iKey3 ^ data.iKey4 ^ data.iKey2 ^ data.iKey8 ^ data.iKey9 ^ data.iKey2 ^ data.iKey1 ^ BinaryFirstKeys[data.iKey1] + data.iKey3 - data.iKey2 << 4;
            data.iHash ^= data.iKey1 ^ data.iKey1 + data.iKey3 ^ data.iKey4 ^ data.iKey2 ^ data.iKey8 ^ data.iKey9 ^ data.iKey2 ^ data.iKey1 ^ BinaryFirstKeys[data.iKey2] + data.iKey3 - data.iKey2 << 2;
        }*/

        public static void DecryptHash(ref EncryptionHeader data) {
            data.iHash ^= data.iKey1 ^ data.iKey1 + data.iKey3 ^ data.iKey4 ^ data.iKey2 ^ data.iKey8 ^ data.iKey9 ^ data.iKey2 ^ data.iKey1 ^ BinaryFirstKeys[data.iKey2] + data.iKey3 - data.iKey2 << 2;
            data.iHash ^= data.iKey2 ^ data.iKey1 + data.iKey3 ^ data.iKey4 ^ data.iKey2 ^ data.iKey8 ^ data.iKey9 ^ data.iKey2 ^ data.iKey1 ^ BinaryFirstKeys[data.iKey1] + data.iKey3 - data.iKey2 << 4;
            data.iHash ^= data.iKey2 ^ data.iKey2 + data.iKey3 ^ data.iKey4 ^ data.iKey2 ^ data.iKey8 ^ data.iKey9 ^ data.iKey2 ^ data.iKey1 ^ BinaryFirstKeys[data.iKey2] + data.iKey3 - data.iKey2 << 8;
            data.iHash ^= data.iKey1 ^ data.iKey2 + data.iKey3 ^ data.iKey4 ^ data.iKey2 ^ data.iKey8 ^ data.iKey9 ^ data.iKey2 ^ data.iKey1 ^ BinaryFirstKeys[data.iKey1] + data.iKey3 - data.iKey2 << 16;
            data.iHash ^= data.iKey1 ^ data.iKey2 + data.iKey3 ^ data.iKey4 ^ data.iKey2 ^ data.iKey8 ^ data.iKey9 ^ data.iKey2 ^ data.iKey1 ^ BinaryFirstKeys[data.iKey2] + data.iKey3 - data.iKey2 << 24;
            data.iHash ^= data.iKey2 ^ data.iKey1 + data.iKey3 ^ data.iKey4 ^ data.iKey2 ^ data.iKey8 ^ data.iKey9 ^ data.iKey2 ^ data.iKey1 ^ BinaryFirstKeys[data.iKey1] + data.iKey3 - data.iKey2 << 32;
            data.iHash ^= data.iKey2 ^ data.iKey2 + data.iKey3 ^ data.iKey4 ^ data.iKey2 ^ data.iKey8 ^ data.iKey9 ^ data.iKey2 ^ data.iKey1 ^ BinaryFirstKeys[data.iKey2] + data.iKey3 - data.iKey2 << 32;
            data.iHash ^= data.iKey1 ^ data.iKey2 + data.iKey3 ^ data.iKey4 ^ data.iKey2 ^ data.iKey8 ^ data.iKey9 ^ data.iKey2 ^ data.iKey1 ^ BinaryFirstKeys[data.iKey1] + data.iKey3 - data.iKey2 << 24;
            data.iHash ^= data.iKey1 ^ data.iKey2 + data.iKey3 ^ data.iKey4 ^ data.iKey2 ^ data.iKey8 ^ data.iKey9 ^ data.iKey2 ^ data.iKey1 ^ BinaryFirstKeys[data.iKey2] + data.iKey3 - data.iKey2 << 16;
            data.iHash ^= data.iKey2 ^ data.iKey1 + data.iKey3 ^ data.iKey4 ^ data.iKey2 ^ data.iKey8 ^ data.iKey9 ^ data.iKey2 ^ data.iKey1 ^ BinaryFirstKeys[data.iKey1] + data.iKey3 - data.iKey2 << 8;
            data.iHash ^= 22;
            data.iHash ^= (data.iKey2 * data.iKey2 * data.iKey3 * data.iKey4 * data.iKey3 * data.iKey6 * data.iKey7 * data.iKey5 * data.iKey9);
            data.iHash ^= (data.iKey2 + data.iKey2 + data.iKey3 + data.iKey4 + data.iKey3 + data.iKey6 + data.iKey7 + data.iKey5 + data.iKey9);
            data.iHash ^= (data.iKey2 ^ data.iKey2 ^ data.iKey3 ^ data.iKey4 ^ data.iKey3 ^ data.iKey6 ^ data.iKey7 ^ data.iKey5 ^ data.iKey9);
            data.iHash ^= 4545;
            data.iHash ^= 98;
            data.iHash ^= 97;
            data.iHash ^= 96;
            data.iHash ^= 95;
            data.iHash ^= 94;
            data.iHash ^= 93;
            data.iHash ^= 92;
            data.iHash ^= 91;
            data.iHash -= data.iKey4;
            data.iHash ^= BinarySecondKeys[21];
            data.iHash -= BinarySecondKeys[8];
            data.iHash -= BinaryFirstKeys[data.iKey2] * 52;
            data.iHash ^= 96;
            data.iHash ^= data.iKey5 + 1234;
            data.iHash *= -1;
            data.iHash -= 1331;
            data.iHash ^= 99;
            data.iHash ^= 99;
            data.iHash -= 1337;
            data.iHash ^= (data.iKey1 ^ data.iKey2 ^ data.iKey3 ^ data.iKey4 ^ data.iKey5 ^ data.iKey6 ^ data.iKey7 ^ data.iKey8 ^ data.iKey9);
            data.iHash ^= 6969;
            data.iHash -= (data.iKey9 * 2) ^ 14 + (123 ^ BinarySecondKeys[2]);
            data.iHash -= (data.iKey5 << 16) ^ 2;
            data.iHash ^= 98;
            data.iHash ^= (data.iKey1 ^ 13) + (data.iKey2 ^ 23) + (data.iKey3 ^ 33) + (data.iKey4 ^ BinarySecondKeys[data.iKey1]);
            data.iHash ^= data.iKey8;
            data.iHash -= data.iKey4;
            data.iHash ^= BinarySecondKeys[43];
            data.iHash += BinarySecondKeys[0];
            data.iHash -= BinaryFirstKeys[data.iKey1] * 69;
            data.iHash ^= 69;
            data.iHash ^= (BinarySecondKeys[data.iKey1] + BinarySecondKeys[data.iKey2]);
            data.iHash += (data.iKey2 ^ 123);
            data.iHash ^= BinarySecondKeys[data.iKey1];
            data.iHash ^= data.iKey1 + 123;
            data.iHash *= -1;
            data.iHash -= 1337;
            data.iHash ^= 13;
        }

        internal static class RandomNumbers
        {
            private static System.Random r;

            public static int NextNumber()
            {
                if (r == null)
                    Seed();

                return r.Next();
            }

            public static int NextNumber(int ceiling)
            {
                if (r == null)
                    Seed();

                return r.Next(ceiling);
            }

            public static void Seed()
            {
                r = new System.Random();
            }

            public static void Seed(int seed)
            {
                r = new System.Random(seed);
            }
        }


        public static void GenerateKeys(ref EncryptionStruct data)
        {
            //C++ TO C# CONVERTER TODO TASK: The memory management function 'memcpy' has no equivalent in C#:


            data.Time = Utils.GetTimeStamp();
            data.iHash = (int)data.Time;
            data.iKey1 = (RandomNumbers.NextNumber() % 1000) + 1;
            data.iKey2 = (RandomNumbers.NextNumber() % 1000) + 1;
        }



        /*public static void GenerateKeys(ref EncryptionStruct data) {
            data.iKey1 = new Random().Next(50);
            data.iKey2 = new Random().Next(50);
            data.iKey3 = data.iKey2 ^ 0x69 + ((new Random().Next(255)) * 100);
            data.iKey4 = data.iKey3 ^ data.iKey2 + data.iKey1;
            data.iKey5 = data.iKey4 + 0x10;
            data.iKey6 = (data.iKey5 - 0x10 ^ 12) + ((new Random().Next(255)) * 100);
            data.iKey7 = data.iKey6 ^ data.iKey4 ^ data.iKey3;
            data.iKey8 = (BinaryFirstKeys[data.iKey1] ^ data.iKey1) + ((new Random().Next(255)) * 5);
            data.iKey9 = (data.iKey4 - 0x10) ^ data.iKey5 ^ 0x79 + 0x23;
            data.iKey10 = 1337;
        }*/

        /*public static void EncryptBytes(ref byte[] arr, int size, ref EncryptionStruct data, int startOffset = 0) {
            GenerateKeys(ref data);

            byte[] staticEncryptionKey = new byte[] { 0x79, 0x6f, 0x75, 0x72, 0x20, 0x6d, 0x75, 0x6d, 0x20, 0x68, 0x61, 0x73, 0x20, 0x67, 0x61, 0x79 }; // "your mum has gay"
            byte[] firstEncryptionKey = new byte[0x10];

            BinaryWriter writer = new BinaryWriter(new MemoryStream(firstEncryptionKey));
            writer.Write(data.iKey1);
            writer.Write(data.iKey2);
            writer.Write(data.iKey3);
            writer.Write(data.iKey4);
            writer.Close();

            EncryptHash(ref data);
            EncryptKeys(ref data);

            int salt = (int)(data.Time) + 1337;
            byte[] converted = BitConverter.GetBytes(salt);

            for (int i = startOffset; i < size; i++) {
                arr[i] ^= converted[0];
                arr[i] ^= converted[1];
                arr[i] ^= converted[2];
                arr[i] ^= converted[3];
            }

            RC4(ref arr, firstEncryptionKey);
            Array.Reverse(arr);

            for (int i = startOffset; i < size; i++) {
                arr[i] ^= 0x69;
            }

            RC4(ref arr, staticEncryptionKey);
            Array.Reverse(arr);
        }*/

        public static void EncryptBytesStaticHeader(ref byte[] arr, EncryptionStruct data, Header header)
        {

            int salt = (int)(data.Time) + 1337;
            var converted = BitConverter.GetBytes(salt);

            for (int i = 44; i < arr.Length; i++)
            {
                arr[i] = (byte)(arr[i] ^ (byte)converted[0]);
                arr[i] = (byte)(arr[i] ^ (byte)converted[1]);
                arr[i] = (byte)(arr[i] ^ (byte)converted[2]);
                arr[i] = (byte)(arr[i] ^ (byte)converted[3]);

                for (int j = 0; j < 0x10; j++)
                {
                    arr[i] = (byte)(arr[i] ^ header.szRandomKey[j]);

                }
            }

                RC4(ref arr, header.szRC4Key, 44);
            
        }



        /*public static void EncryptBytesStaticHeader(ref byte[] arr, EncryptionStruct data, Header header) {
            int salt = (int)(data.Time) + 1337;
            byte[] converted = BitConverter.GetBytes(salt);

            for (int i = 44; i < arr.Length; i++) {
                arr[i] ^= converted[0];
                arr[i] ^= converted[1];
                arr[i] ^= converted[2];
                arr[i] ^= converted[3];

                for (int j = 0; j < 0x10; j++)
                {
                    arr[i] = arr[i] ^ header.szRandomKey[j];
                }

            }

            byte[] staticEncryptionKey = new byte[] { 0x79, 0x6f, 0x75, 0x72, 0x20, 0x6d, 0x75, 0x6d, 0x20, 0x68, 0x61, 0x73, 0x20, 0x67, 0x61, 0x79 };

            RC4(ref arr, header.szRC4Key, 44);
        }*/

        public static void DecryptBytes(ref byte[] arr, int size, ref EncryptionHeader data) {
            if (size > 0x80) {
                DecryptKeys(ref data);
                DecryptHash(ref data);

                int salt = data.iHash + 1337;
                byte[] converted = BitConverter.GetBytes(salt);

                for (int i = 0x80; i < size; i++) {
                    arr[i] ^= converted[3];
                    arr[i] ^= converted[2];
                    arr[i] ^= converted[1];
                    arr[i] ^= converted[0];
                }

                byte[] staticEncryptionKey = new byte[] { 0x79, 0x6f, 0x75, 0x72, 0x20, 0x6d, 0x75, 0x6d, 0x20, 0x68, 0x61, 0x73, 0x20, 0x67, 0x61, 0x79 }; // "your mum has gay"
                RC4(ref arr, staticEncryptionKey, 0x80);
            }
        }

        public static void SendPacket(EndianWriter serverWriter, Header header, byte[] dgram, EncryptionStruct enc) {
            try {
                EncryptBytesStaticHeader(ref dgram, enc, header);
                serverWriter.Write(dgram);
                serverWriter.Close();
            } catch (Exception ex) {
                Console.WriteLine("SendPacket Error: {0}", ex.Message);
            }
        }
    }
}