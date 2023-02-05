using System;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Collections.Generic;

namespace Listener {
    class PacketGetPluginPatches {
        private enum eGetPluginPatches {
            GET_PLUGIN_PATCHES_SUCCESS = 1,
            GET_PLUGIN_PATCHES_NO_DATA
        };

        public static void Handle(EndianReader reader, EndianWriter serverWriter, Header header, List<Log.PrintQueue> logId, string ip) {
            Log.Add(logId, ConsoleColor.Blue, "Command", "PacketGetPluginPatches", ip);
            Log.Add(logId, ConsoleColor.Cyan, "Console Key", Utils.BytesToString(header.szConsoleKey), ip);

            byte[] patchData = new byte[0];
            uint size = 0;
            byte[] resp = new byte[32 + 8 + Global.iEncryptionStructSize];
            EndianWriter writer = new EndianWriter(new MemoryStream(resp), EndianStyle.BigEndian);

            eGetPluginPatches status = eGetPluginPatches.GET_PLUGIN_PATCHES_NO_DATA;

            int xexID = reader.ReadInt32();

            XexInfo xeinfo = new XexInfo();
            if (!MySQL.GetXexInfo(xexID, ref xeinfo)) {
                Log.Add(logId, ConsoleColor.DarkYellow, "Reporting", string.Format("Xex identifier not found ({0})", xexID), ip);

                status = eGetPluginPatches.GET_PLUGIN_PATCHES_NO_DATA;
                goto end;
            }

            if (!File.Exists(string.Format("Server Data/Plugins/{0}.bin", xeinfo.PatchName))) {
                Log.Add(logId, ConsoleColor.DarkYellow, "Reporting", "File wasn't found on server", ip);

                status = eGetPluginPatches.GET_PLUGIN_PATCHES_NO_DATA;
                goto end;
            }

            patchData = File.ReadAllBytes(string.Format("Server Data/Plugins/{0}.bin", xeinfo.PatchName));
            
            byte[] rc4Key = {
                0x64, 0x6F, 0x6E, 0x27, 0x74, 0x20, 0x74, 0x6F, 0x75, 0x63, 0x68, 0x20,
                0x6D, 0x65, 0x20, 0x73, 0x75, 0x70, 0x61, 0x20, 0x73, 0x65, 0x63, 0x72,
                0x65, 0x74, 0x20, 0x6D, 0x61, 0x79, 0x6F
            };

            Security.RC4(ref patchData, rc4Key);

            status = eGetPluginPatches.GET_PLUGIN_PATCHES_SUCCESS;
            resp = new byte[patchData.Length + 8 + Global.iEncryptionStructSize];
            size = (uint)patchData.Length;
            writer = new EndianWriter(new MemoryStream(resp), EndianStyle.BigEndian);

            Log.Add(logId, ConsoleColor.Magenta, "Info", string.Format("Sending plugin patches {0}.bin with size {1}", xeinfo.PatchName, patchData.Length.ToString("X4")), ip);

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
            if (status == eGetPluginPatches.GET_PLUGIN_PATCHES_SUCCESS) writer.Write(patchData);
            writer.Close();

            Security.SendPacket(serverWriter, header, resp, enc);
            Log.Add(logId, ConsoleColor.Green, "Status", "Response sent", ip);
            Log.Print(logId);
        }
    }
}
