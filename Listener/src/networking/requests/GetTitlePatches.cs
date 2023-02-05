using System;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Collections.Generic;

namespace Listener {
    class PacketGetTitlePatches {
        private enum eGetTitlePatches {
            GET_TITLE_PATCHES_SUCCESS = 1,
            GET_TITLE_PATCHES_NO_DATA
        };
        
        public static void Handle(EndianReader reader, EndianWriter serverWriter, Header header, List<Log.PrintQueue> logId, string ip) {
            Log.Add(logId, ConsoleColor.Blue, "Command", "PacketGetTitlePatches", ip);
            Log.Add(logId, ConsoleColor.Cyan, "Console Key", Utils.BytesToString(header.szConsoleKey), ip);

            byte[] patchData = new byte[0];
            uint size = 0;
            byte[] resp = new byte[32 + 8 + Global.iEncryptionStructSize];
            EndianWriter writer = new EndianWriter(new MemoryStream(resp), EndianStyle.BigEndian);

            eGetTitlePatches status = eGetTitlePatches.GET_TITLE_PATCHES_NO_DATA;

            uint title = reader.ReadUInt32();
            uint stamp = reader.ReadUInt32();

            Log.Add(logId, ConsoleColor.Magenta, "Info", string.Format("Checking for patches for {0}-{1}", title.ToString("X4"), stamp.ToString("X4")), ip);

            if (title == 0 || !File.Exists(string.Format("Server Data/Patches/{0}-{1}.bin", title.ToString("X4"), stamp.ToString("X4")))) {
                goto end;
            }

            patchData = File.ReadAllBytes(string.Format("Server Data/Patches/{0}-{1}.bin", title.ToString("X4"), stamp.ToString("X4")));

            
            byte[] rc4Key = {
                0x73, 0x75, 0x70, 0x65, 0x72, 0x20, 0x63, 0x6F, 0x6F, 0x6C, 0x20, 0x72,
                0x63, 0x34, 0x20, 0x6B, 0x65, 0x79, 0x20, 0x64, 0x61, 0x64, 0x64, 0x79,
                0x20, 0x75, 0x77, 0x75
            };

            Security.RC4(ref patchData, rc4Key);

            status = eGetTitlePatches.GET_TITLE_PATCHES_SUCCESS;
            resp = new byte[patchData.Length + 8 + Global.iEncryptionStructSize];
            size = (uint)patchData.Length;
            writer = new EndianWriter(new MemoryStream(resp), EndianStyle.BigEndian);

            Log.Add(logId, ConsoleColor.Magenta, "Info", string.Format("Sending patches with size {0}", patchData.Length.ToString("X4")), ip);

        end:
            Security.EncryptionStruct enc = new Security.EncryptionStruct();
            Security.GenerateKeys(ref enc);
            Security.EncryptHash(ref enc, header);
            Security.EncryptKeys(ref enc);

            writer.Write(header.szRandomKey);
            writer.Write(header.szRC4Key);

            writer.Write(enc.iKey1);
            writer.Write(enc.iKey2);

            /*
            writer.Write(enc.iKey3);
            writer.Write(enc.iKey4);
            writer.Write(enc.iKey5);
            writer.Write(enc.iKey6);
            writer.Write(enc.iKey7);
            writer.Write(enc.iKey8);
            writer.Write(enc.iKey9);
            writer.Write(enc.iKey10);
            */
            writer.Write(enc.iHash);

            writer.Write((int)status);
            writer.Write(size);
            if (status == eGetTitlePatches.GET_TITLE_PATCHES_SUCCESS) writer.Write(patchData);
            writer.Close();

            Security.SendPacket(serverWriter, header, resp, enc);
            Log.Add(logId, ConsoleColor.Green, "Status", "Response sent", ip);
            Log.Print(logId);
        }
    }
}
