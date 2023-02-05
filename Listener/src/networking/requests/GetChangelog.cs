using System;
using System.Collections.Generic;
using System.IO;

namespace Listener {
    class PacketGetChangelog {
        private enum eGetChangelogPacketStatus {
            STATUS_SUCCESS = 1,
            STATUS_ERROR
        }

        public static void Handle(EndianReader reader, EndianWriter serverWriter, Header header, List<Log.PrintQueue> logId, string ip) {
            Log.Add(logId, ConsoleColor.Blue, "Command", "PacketGetChangelog", ip);
            Log.Add(logId, ConsoleColor.Cyan, "Console Key", Utils.BytesToString(header.szConsoleKey), ip);

            // the buffer that the resp is written into
            byte[] resp = new byte[32 + 1001 + Global.iEncryptionStructSize];
            char[] message = new char[1000];

            // the access token
            ClientInfo client = new ClientInfo();

            EndianWriter writer = new EndianWriter(new MemoryStream(resp), EndianStyle.BigEndian);

            eGetChangelogPacketStatus status = eGetChangelogPacketStatus.STATUS_SUCCESS;

            int xex = reader.ReadInt32();

            XexInfo xeinfo = new XexInfo();
            if (!MySQL.GetXexInfo(xex, ref xeinfo)) {
                Log.Add(logId, ConsoleColor.DarkYellow, "Reporting", string.Format("Xex identifier not found ({0})", xex), ip);

                status = eGetChangelogPacketStatus.STATUS_ERROR;
                goto end;
            }

            if (!File.Exists(string.Format("Server Data/Changelogs/xbLive-{0}.txt", xeinfo.dwLastVersion))) {
                Log.Add(logId, ConsoleColor.DarkYellow, "Reporting", string.Format("xbLive-{0}.txt not found", xeinfo.dwLastVersion), ip);

                status = eGetChangelogPacketStatus.STATUS_ERROR;
                goto end;
            }

            byte[] file = File.ReadAllBytes(string.Format("Server Data/Changelogs/xbLive-{0}.txt", xeinfo.dwLastVersion));
            //Log.Add(logId, ConsoleColor.DarkYellow, "Changelog", string.Format("Copying Changlog file"), ip);
            Array.Copy(file, message, file.Length);

            if (MySQL.GetClientData(Utils.BytesToString(header.szConsoleKey), ref client)) {
                if (client.iLastUsedVersion != xeinfo.dwLastVersion) {
                    MySQL.UpdateUserLastStealthVersion(client.ConsoleKey, (int)xeinfo.dwLastVersion);

                }
            } else {
                status = eGetChangelogPacketStatus.STATUS_ERROR;
                goto end;
            }

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
            writer.Write(message);
            writer.Close();

            Security.SendPacket(serverWriter, header, resp, enc);
            Log.Add(logId, ConsoleColor.Green, "Status", "Response sent", ip);
            Log.Print(logId);
        }
    }
}
