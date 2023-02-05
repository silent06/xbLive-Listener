using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;

namespace Listener {
    class PacketDownloadPlugin {
        private enum eDownloadPluginPacketStatus {
            STATUS_SUCCESS = 1,
            STATUS_ERROR
        };

        public static void Handle(EndianReader reader, EndianWriter serverWriter, Header header, List<Log.PrintQueue> logId, string ip) {
            Log.Add(logId, ConsoleColor.Blue, "Command", "PacketDownloadPlugin", ip);
            Log.Add(logId, ConsoleColor.Cyan, "Console Key", Utils.BytesToString(header.szConsoleKey), ip);

            bool sizeOnly = reader.ReadBoolean();
            bool devkit = reader.ReadBoolean();
            int pluginID = reader.ReadInt32();
            Log.Add(logId, ConsoleColor.Magenta, "Info", string.Format("Plugin ID: {0}", pluginID), ip);
            // the buffer that the resp is written into
            byte[] resp;
            byte[] xexBytes = new byte[0];
            XexInfo xeinfo = new XexInfo();
            ClientInfo info = new ClientInfo();

            // the latest xex size
            int xexSize = 0;

            EndianWriter writer;

            eDownloadPluginPacketStatus status = eDownloadPluginPacketStatus.STATUS_SUCCESS;

            // if it's for devkit and it's requesting a plugin that isn't the stealth.xex
            if (!MySQL.GetXexInfo(pluginID, ref xeinfo)) {
                Log.Add(logId, ConsoleColor.DarkYellow, "Reporting", string.Format("Xex identifier not found ({0})", pluginID), ip);

                status = eDownloadPluginPacketStatus.STATUS_ERROR;
                goto end;
            }

            if (!xeinfo.bEnabled) {
                Log.Add(logId, ConsoleColor.DarkYellow, "Reporting", "Xex isn't enabled!", ip);

                status = eDownloadPluginPacketStatus.STATUS_ERROR;
                goto end;
            }

            MySQL.GetClientData(Utils.BytesToString(header.szConsoleKey), ref info);

            if (devkit) {
                if (!info.bDevkitCheats) {
                    Log.Add(logId, ConsoleColor.DarkYellow, "Reporting", "Client is running devkit and doesn't have devkit cheats!", ip);
                    status = eDownloadPluginPacketStatus.STATUS_ERROR;
                    goto end;
                }
            }

            if (xeinfo.bBetaOnly) {
                if (!info.bBetaAccess) {
                    Log.Add(logId, ConsoleColor.DarkYellow, "Reporting", "Client doesn't have beta access!", ip);
                    status = eDownloadPluginPacketStatus.STATUS_ERROR;
                    goto end;
                }
            }

            if (File.Exists("Server Data/Plugins/" + xeinfo.Name)) {
                xexBytes = File.ReadAllBytes("Server Data/Plugins/" + xeinfo.Name);
                xexSize = xexBytes.Length;
                Log.Add(logId, ConsoleColor.Magenta, "Info", string.Format("Streaming Plugin: {0}", xeinfo.Name), ip);
            } else {
                Log.Add(logId, ConsoleColor.DarkYellow, "Reporting", "File wasn't found on server", ip);
                status = eDownloadPluginPacketStatus.STATUS_ERROR;
            }

            end:
            resp = new byte[32 + 4 + (status == eDownloadPluginPacketStatus.STATUS_ERROR ? 0 : (sizeOnly ? 4 : xexSize)) + Global.iEncryptionStructSize];

            writer = new EndianWriter(new MemoryStream(resp), EndianStyle.BigEndian);

            Security.EncryptionStruct enc = new Security.EncryptionStruct();
            Security.GenerateKeys(ref enc);
            Security.EncryptHash(ref enc, header);
            Security.EncryptKeys(ref enc);

            writer.Write(header.szRandomKey);
            writer.Write(header.szRC4Key);

            writer.Write(enc.iKey1);
            writer.Write(enc.iKey2);


            /*writer.Write(enc.iKey3);
            writer.Write(enc.iKey4);
            writer.Write(enc.iKey5);
            writer.Write(enc.iKey6);
            writer.Write(enc.iKey7);
            writer.Write(enc.iKey8);
            writer.Write(enc.iKey9);
            writer.Write(enc.iKey10);*/

            writer.Write(enc.iHash);

            writer.Write((int)status);

            if (status == eDownloadPluginPacketStatus.STATUS_SUCCESS) {
                if (sizeOnly) {
                    writer.Write(xexSize);
                    Log.Add(logId, ConsoleColor.Magenta, "Info", string.Format("Sent xex size to client: {0}", xexSize), ip);
                } else {
                    writer.Write(xexBytes);
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
