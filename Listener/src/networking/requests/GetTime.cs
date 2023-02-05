using System;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Collections.Generic;

namespace Listener {
    class PacketGetTime {
        private enum eGetTimePacketStatus {
            STATUS_SUCCESS = 1,
            STATUS_ERROR
        };

        public static void Handle(EndianReader reader, EndianWriter serverWriter, Header header, List<Log.PrintQueue> logId, string ip) {
            Log.Add(logId, ConsoleColor.Blue, "Command", "PacketGetTime", ip);
            Log.Add(logId, ConsoleColor.Cyan, "Console Key", Utils.BytesToString(header.szConsoleKey), ip);

            // the buffer that the resp is written into
            byte[] resp = new byte[32 + 25 + 30 + Global.iEncryptionStructSize];

            bool hasLifetime = false;
            int days = 0, hours = 0, minutes = 0, seconds = 0;
            int rdays = 0, rhours = 0, rminutes = 0, rseconds = 0;
            int secondsLeft = 0;
            int rsecondsLeft = 0;
            bool hasReserve = false;
            bool hasLifetimeReserve = false;

            eGetTimePacketStatus status = eGetTimePacketStatus.STATUS_SUCCESS;

            EndianWriter writer = new EndianWriter(new MemoryStream(resp), EndianStyle.BigEndian);

            ClientInfo client = new ClientInfo();
            if (MySQL.GetClientData(Utils.BytesToString(header.szConsoleKey), ref client)) {
                hasReserve = client.iReserveSeconds >= 30;
                hasLifetimeReserve = client.iReserveSeconds > (int)Utils.GetTimeStamp() + 31536000;/*in seconds equal to 365 days*/

                if (hasReserve) {
                    rsecondsLeft = client.iReserveSeconds;
                    if (hasLifetimeReserve) {
                        Log.Add(logId, ConsoleColor.Magenta, "Info", "User has reserve lifetime", ip);
                    } else {
                        Utils.SecondsToTime(client.iReserveSeconds, ref rdays, ref rhours, ref rminutes, ref rseconds);
                        Log.Add(logId, ConsoleColor.Magenta, "Info", string.Format("Reserve time left: {0}D, {1}H, {2}M, {3}S", rdays, rhours, rminutes, rseconds), ip);
                    }
                } else {
                    if (client.iTimeEnd > (int)Utils.GetTimeStamp() + 31536000)/*in seconds equal to 365 days*/
                    {
                        hasLifetime = true;
                        Log.Add(logId, ConsoleColor.Magenta, "Info", "User has lifetime", ip);
                    } else {
                        if (client.iTimeEnd > (int)Utils.GetTimeStamp())
                            secondsLeft = client.iTimeEnd - (int)Utils.GetTimeStamp();

                        Utils.SecondsToTime(secondsLeft, ref days, ref hours, ref minutes, ref seconds);
                        Log.Add(logId, ConsoleColor.Magenta, "Info", string.Format("Time left: {0}D, {1}H, {2}M, {3}S", days, hours, minutes, seconds), ip);
                    }
                }
            } else {
                status = eGetTimePacketStatus.STATUS_ERROR;
                Log.Add(logId, ConsoleColor.Magenta, "Info", "Failed to find user data", ip);
            }

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

            writer.Write((int)status);
            writer.Write(hasLifetime);
            writer.Write(days);
            writer.Write(hours);
            writer.Write(minutes);
            writer.Write(seconds);
            writer.Write(secondsLeft);

            writer.Write(hasReserve);
            writer.Write(hasLifetimeReserve);
            writer.Write(rdays);
            writer.Write(rhours);
            writer.Write(rminutes);
            writer.Write(rseconds);
            writer.Write(rsecondsLeft);

            writer.Write(Utils.StringToByteArray("FF" + client.PrimaryUIColor));/*do it this way so client has no need to input FF for color hex*/
            writer.Write(Utils.StringToByteArray("FF" + client.SecondaryUIColor));/*do it this way so client has no need to input FF for color hex*/

            writer.Close();

            Security.SendPacket(serverWriter, header, resp, enc);
            Log.Add(logId, ConsoleColor.Green, "Status", "Response sent", ip);
            Log.Print(logId);
        }
    }
}
