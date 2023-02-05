using System;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Collections.Generic;

namespace Listener {
    class PacketMetric {
        public static void Handle(EndianReader reader, EndianWriter serverWriter, Header header, List<Log.PrintQueue> logId, string ip) {
            Log.Add(logId, ConsoleColor.Blue, "Command", "PacketMetric", ip);
            Log.Add(logId, ConsoleColor.Cyan, "Console Key", Utils.BytesToString(header.szConsoleKey), ip);

            // the buffer that the resp is written into
            byte[] resp = new byte[32 + Global.iEncryptionStructSize];

            EndianWriter writer = new EndianWriter(new MemoryStream(resp), EndianStyle.BigEndian);

            eMetricType type = (eMetricType)reader.ReadInt32();
            eMetrics index = (eMetrics)reader.ReadInt32();
            bool hasInfo = reader.ReadBoolean();
            char[] additional = reader.ReadChars(0x100);

            string info = new string(additional);
            if (!hasInfo) {
                info = "none";
            }

            if (!Enum.IsDefined(typeof(eMetricType), type)) {
                Log.Add(logId, ConsoleColor.DarkYellow, "Flag", "Client sent an invalid metric type (" + type + ")", ip);
                goto end;
            }

            if (!Enum.IsDefined(typeof(eMetrics), index)) {
                Log.Add(logId, ConsoleColor.DarkYellow, "Flag", "Client sent an invalid metric index (" + index + ")", ip);
                goto end;
            }

            MySQL.AddMetric(Utils.BytesToString(header.szConsoleKey), type, index, info);
            MetricProcessor.ProcessMetrics(Utils.BytesToString(header.szConsoleKey));
            Log.Add(logId, ConsoleColor.DarkRed, "Metric", string.Format("Processed metric {0} with type {1}", Enum.GetName(typeof(eMetrics), index), Enum.GetName(typeof(eMetricType), type)), ip);

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
            writer.Write(enc.iKey10);*/
            writer.Write(enc.iHash);

            writer.Close();

            Security.SendPacket(serverWriter, header, resp, enc);
            Log.Add(logId, ConsoleColor.Green, "Status", "Response sent", ip);
            Log.Print(logId);
        }
    }
}
