using System;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Collections.Generic;

namespace Listener {
    class PacketGetUpdate {
        private enum eGetUpdatePacketStatus {
            STATUS_SUCCESS = 1,
            STATUS_ERROR
        };

        public static void Handle(EndianReader reader, EndianWriter serverWriter, Header header, List<Log.PrintQueue> logId, string ip) {
            Log.Add(logId, ConsoleColor.Blue, "Command", "PacketGetUpdate", ip);
            Log.Add(logId, ConsoleColor.Cyan, "Console Key", Utils.BytesToString(header.szConsoleKey), ip);

            // the buffer that the resp is written into
            byte[] resp;

            // the latest xex size
            int xexSize = 0;

            EndianWriter writer;

            eGetUpdatePacketStatus status = eGetUpdatePacketStatus.STATUS_SUCCESS;

            FileInfo fi = new FileInfo("Server Data/Plugins/xbLive.xex");
            if (fi.Exists) {
                xexSize = (int)fi.Length;
            } else {
                Log.Add(logId, ConsoleColor.DarkYellow, "Reporting", "File wasn't found on server", ip);
                status = eGetUpdatePacketStatus.STATUS_ERROR;
                goto end;
            }

        end:
            // whether we only want to get the size of the file for the alloc
            bool sizeOnly = reader.ReadBoolean();

            resp = new byte[32+ 4 + (status == eGetUpdatePacketStatus.STATUS_ERROR ? 0 : (sizeOnly ? 4 : xexSize)) + Global.iEncryptionStructSize];

            writer = new EndianWriter(new MemoryStream(resp), EndianStyle.BigEndian);

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

            if (status == eGetUpdatePacketStatus.STATUS_SUCCESS) {
                if (sizeOnly) {
                    writer.Write(xexSize);
                    Log.Add(logId, ConsoleColor.Magenta, "Info", string.Format("Sent xex size to client: {0}", xexSize), ip);
                } else {
                    writer.Write(File.ReadAllBytes("Server Data/Plugins/xbLive.xex"));
                    Log.Add(logId, ConsoleColor.Magenta, "Info", string.Format("Streamed {0} bytes to client", xexSize), ip);
                }
            }

            writer.Close();

            Security.SendPacket(serverWriter, header, resp, enc);
            Log.Add(logId, ConsoleColor.Green, "Status", "Response sent", ip);
            Log.Print(logId);
        }
    }
}
