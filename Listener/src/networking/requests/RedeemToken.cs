using System;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Collections.Generic;

namespace Listener {
    class PacketRedeemToken {
        public static void Handle(EndianReader reader, EndianWriter serverWriter, Header header, List<Log.PrintQueue> logId, string ip) {
            Log.Add(logId, ConsoleColor.Blue, "Command", "PacketRedeemToken", ip);
            Log.Add(logId, ConsoleColor.Cyan, "Console Key", Utils.BytesToString(header.szConsoleKey), ip);

            // the buffer that the resp is written into
            byte[] resp = new byte[32 + 5 + Global.iEncryptionStructSize];

            bool validToken = false;
            bool alreadyRedeemed = false;

            int secondsAdded = 0;

            EndianWriter writer = new EndianWriter(new MemoryStream(resp), EndianStyle.BigEndian);

            char[] token = reader.ReadChars(12);

            if (token.Length < 1) {
                goto end;
            }

            validToken = MySQL.DoesRedeemTokenExist(new string(token), ref alreadyRedeemed);

            Log.Add(logId, ConsoleColor.Magenta, "Info", string.Format("Checking token {0} - valid: {1}, already used: {2}", new string(token), validToken ? "yes" : "no", alreadyRedeemed ? "yes" : "no"), ip);

            if (validToken) {
                if (!alreadyRedeemed) {
                    MySQL.GetTokenTimeAndRedeem(new string(token), Utils.BytesToString(header.szConsoleKey), ref secondsAdded);
                    Log.Add(logId, ConsoleColor.Magenta, "Info", string.Format("Added {0} seconds to users account", secondsAdded), ip);
                }
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
            writer.Write(enc.iKey10); */
            writer.Write(enc.iHash);

            writer.Write(validToken && !alreadyRedeemed);
            writer.Write(secondsAdded);
            writer.Close();

            Security.SendPacket(serverWriter, header, resp, enc);
            Log.Add(logId, ConsoleColor.Green, "Status", "Response sent", ip);
            Log.Print(logId);
        }
    }
}
