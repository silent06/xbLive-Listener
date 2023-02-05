using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.IO;
using System.Threading;
using System.Collections.Concurrent;
using System.Threading.Tasks;

namespace Listener {
    class PacketGetPlugins {
        public static void Handle(EndianReader reader, EndianWriter serverWriter, Header header, List<Log.PrintQueue> logId, string ip) {
            Log.Add(logId, ConsoleColor.Blue, "Command", "PacketGetPlugins", ip);
            Log.Add(logId, ConsoleColor.Cyan, "Console Key", Utils.BytesToString(header.szConsoleKey), ip);

            List<XexInfo> xexInfos = MySQL.GetXexInfos();

            // 17 is current size of xexinfo
            byte[] resp = new byte[0x211 + Global.iEncryptionStructSize];
            byte[] data = new byte[0x210];

            EndianWriter writer = new EndianWriter(new MemoryStream(resp), EndianStyle.BigEndian);
            EndianWriter dataWriter = new EndianWriter(new MemoryStream(data), EndianStyle.BigEndian);

            int realCount = 0;

            foreach (var xex in xexInfos) {
                if (xex.iID != 0) realCount++;
            }// if (xex. != 0)


            dataWriter.Write(realCount);

            ClientInfo info = new ClientInfo();
            MySQL.GetClientData(Utils.BytesToString(header.szConsoleKey), ref info);


            foreach (var xex in xexInfos) {
                if (xex.iID != 0) {
                    dataWriter.Write(xex.iID);
                    dataWriter.Write(xex.dwLastVersion);
                    dataWriter.Write(xex.dwTitle);
                    dataWriter.Write(xex.dwTitleTimestamp);                   
                    


                    if (xex.bBetaOnly && !info.bBetaAccess)
                        dataWriter.Write(false);
                    else dataWriter.Write(xex.bEnabled);

                    //dataWriter.Write(xex.EncryptionKey);

                    //Log.Add(logId, ConsoleColor.Magenta, "Info", string.Format("xex.iID {0}", xex.iID), ip);

                    //Log.Add(logId, ConsoleColor.Magenta, "Info", string.Format("Version {0}", xex.dwLastVersion), ip);
                    //Log.Add(logId, ConsoleColor.Magenta, "Info", string.Format("TitleId {0}", xex.dwTitle), ip);
                    //Log.Add(logId, ConsoleColor.Magenta, "Info", string.Format("timestamp {0}", xex.dwTitleTimestamp), ip);
                    //Log.Add(logId, ConsoleColor.Magenta, "Info", string.Format("Enabled? {0}", xex.bEnabled), ip);
                    //Log.Add(logId, ConsoleColor.Magenta, "Info", string.Format("EncryptionKey? {0}", xex.EncryptionKey), ip);
                }
            }

            dataWriter.Close();

            Log.Add(logId, ConsoleColor.Magenta, "Info", string.Format("Sending {0} plugin(s) to client", realCount), ip);

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
            writer.Write(realCount > 1);//send if true
            writer.Write(data);
            writer.Close();

            Security.SendPacket(serverWriter, header, resp, enc);
            Log.Add(logId, ConsoleColor.Green, "Status", "Response sent", ip);
            Log.Print(logId);
        }
    }
}
