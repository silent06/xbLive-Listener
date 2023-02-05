using System;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Collections.Generic;

namespace Listener {
    class PacketGetKVStats {
        public static void Handle(EndianReader reader, EndianWriter serverWriter, Header header, List<Log.PrintQueue> logId, string ip) {
            Log.Add(logId, ConsoleColor.Blue, "Command", "PacketGetKVStats", ip);
            Log.Add(logId, ConsoleColor.Cyan, "Console Key", Utils.BytesToString(header.szConsoleKey), ip);

            // the buffer that the resp is written into
            byte[] resp = new byte[32+ 25 + Global.iEncryptionStructSize];

            EndianWriter writer = new EndianWriter(new MemoryStream(resp), EndianStyle.BigEndian);

            uint hash = reader.ReadUInt32();

            KVStats info = new KVStats();
            MySQL.GetKVStats(hash.ToString("X4"), ref info);

            TimeCalc calculated = new TimeCalc((int)Utils.GetTimeStamp() - info.iFirstConnection);

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

            writer.Write(calculated.iYears);
            writer.Write(calculated.iDays);
            writer.Write(calculated.iHours);
            writer.Write(calculated.iMinutes);
            writer.Write(calculated.iSeconds);
            writer.Write(info.bBanned);
            writer.Write(info.iTotalChallenges);

            writer.Close();

            Security.SendPacket(serverWriter, header, resp, enc);
            Log.Add(logId, ConsoleColor.Green, "Status", "Response sent", ip);
            Log.Print(logId);
        }
    }
}
