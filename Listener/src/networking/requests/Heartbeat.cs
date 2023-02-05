using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;

namespace Listener {
    class PacketHeartbeat {
        private enum eHeartbeatPacketStatus {
            STATUS_SUCCESS = 1,
            STATUS_ERROR
        }

        public static void Handle(EndianReader reader, EndianWriter serverWriter, Header header, List<Log.PrintQueue> logId, string ip) {
            Log.Add(logId, ConsoleColor.Blue, "Command", "PacketHeartbeat", ip);
            Log.Add(logId, ConsoleColor.Cyan, "Console Key", Utils.BytesToString(header.szConsoleKey), ip);

            // the buffer that the resp is written into
            byte[] resp = new byte[32 + 38 + 30 + Global.iEncryptionStructSize];
            bool hasLifetime = false;
            int days = 0, hours = 0, minutes = 0, seconds = 0;
            int rdays = 0, rhours = 0, rminutes = 0, rseconds = 0;
            int secondsLeft = 0;
            int rsecondsLeft = 0;
            bool hasReserve = false;
            bool hasLifetimeReserve = false;
            bool hasVerificationWaiting = false;
            char[] verificationKey = new char[10];

            //string titleName = "";

            ConsoleVerification verification = new ConsoleVerification();

            eHeartbeatPacketStatus status = eHeartbeatPacketStatus.STATUS_SUCCESS;

            EndianWriter writer = new EndianWriter(new MemoryStream(resp), EndianStyle.BigEndian);

            MySQL.UpdateRequestTokenHeartbeat(Utils.BytesToString(header.szToken));

            int xex = reader.ReadInt32();
            uint currentTitle = reader.ReadUInt32();
            uint kvhash = reader.ReadUInt32();
            bool kvbanned = reader.ReadBoolean();
            char[] gamertag = reader.ReadChars(16);

            ClientInfo client = new ClientInfo();
            if (MySQL.GetClientData(Utils.BytesToString(header.szConsoleKey), ref client)) {
                if (client.iTimeEnd > (int)Utils.GetTimeStamp())
                    secondsLeft = client.iTimeEnd - (int)Utils.GetTimeStamp();

                Utils.SecondsToTime(secondsLeft, ref days, ref hours, ref minutes, ref seconds);

                string gt = new string(gamertag);

                Log.Add(logId, ConsoleColor.Magenta, "Info", string.Format("Gamertag: {0}", gt), ip);
                MySQL.UpdateUserGamertag(client, gt);

                switch (client.Status) {
                    case ClientInfoStatus.Banned:
                    case ClientInfoStatus.Disabled:
                        status = eHeartbeatPacketStatus.STATUS_ERROR;
                        goto end;
                }

                if (client.iReserveSeconds >= 30) {
                    if (client.iReserveSeconds != int.MaxValue) {
                        if (client.iReserveSeconds >= 30) {
                            // minus 30 cos this packet calls every 30 seconds
                            client.iReserveSeconds -= 30;
                        } else {
                            client.iReserveSeconds = 0;
                        }

                        MySQL.UpdateUserReserveTime(client, client.iReserveSeconds);
                        MySQL.RefreshTimeInfo(client.ConsoleKey);
                    }

                    rsecondsLeft = client.iReserveSeconds;
                    hasReserve = client.iReserveSeconds >= 30;
                    hasLifetimeReserve = client.iReserveSeconds > (int)Utils.GetTimeStamp() + 31536000;/*in seconds equal to 365 days*/

                    if (hasLifetimeReserve) {
                        Log.Add(logId, ConsoleColor.Magenta, "Info", "User has reserve lifetime", ip);
                    } else {
                        Utils.SecondsToTime(client.iReserveSeconds, ref rdays, ref rhours, ref rminutes, ref rseconds);
                        Log.Add(logId, ConsoleColor.Magenta, "Info", string.Format("Reserve time left: {0}D, {1}H, {2}M, {3}S", rdays, rhours, rminutes, rseconds), ip);
                    }

                    MySQL.GetClientData(Utils.BytesToString(header.szConsoleKey), ref client);

                    if (client.iTimeEnd > (int)Utils.GetTimeStamp())
                        secondsLeft = client.iTimeEnd - (int)Utils.GetTimeStamp();
                }

                Utils.SecondsToTime(secondsLeft, ref days, ref hours, ref minutes, ref seconds);

                if (client.iTimeEnd > (int)Utils.GetTimeStamp() + 31536000) /*in seconds equal to 365 days*/
                {
                    hasLifetime = true;
                    Log.Add(logId, ConsoleColor.Magenta, "Info", "User has lifetime", ip);
                } else {
                    Log.Add(logId, ConsoleColor.Magenta, "Info", string.Format("Time left: {0}D, {1}H, {2}M, {3}S", days, hours, minutes, seconds), ip);
                }
            } else {
                Log.Add(logId, ConsoleColor.DarkYellow, "Reporting", "Failed to resolve client info", ip);
                status = eHeartbeatPacketStatus.STATUS_ERROR;
                goto end;
            }

            XexInfo xeinfo = new XexInfo();
            if (!MySQL.GetXexInfo(xex, ref xeinfo)) {
                Log.Add(logId, ConsoleColor.DarkYellow, "Reporting", string.Format("Xex identifier not found ({0})", xex), ip);
                status = eHeartbeatPacketStatus.STATUS_ERROR;
                goto end;
            }

            if (MySQL.GetConsoleVerification(Utils.BytesToString(header.szCPU), ref verification)) {
                if ((int)Utils.GetTimeStamp() - verification.iTimeRequested > 3600) {
                    // been an hour or more, delete the verification.
                    MySQL.DeleteConsoleVerification(Utils.BytesToString(header.szCPU));
                } else {
                    Log.Add(logId, ConsoleColor.Magenta, "Info", string.Format("Active verification request {0}", verification.VerificationKey), ip);
                    hasVerificationWaiting = true;
                    Utils.AddStringToArray(ref verificationKey, verification.VerificationKey);
                }
            }

            MySQL.UpdateKVStat(kvhash.ToString("X4"), kvbanned);

            if (kvbanned) {
                Log.Add(logId, ConsoleColor.Magenta, "Info", string.Format("KV hash: {0} is BANNED!", kvhash.ToString("X4")), ip);
            }

            // update title id
            MySQL.UpdateActiveTitle(client.ConsoleKey, currentTitle.ToString("X4"));

            //Update Online status
            MySQL.UpdateCurrentOnline(client.ConsoleKey, 0);

            //var data = new WebClient().DownloadString(string.Format("http://35.245.169.64/title-info-api/search.php?title=0x{0}", currentTitle.ToString("X4")));
            //JObject obj = JObject.Parse(data);

            /*if (obj.ContainsKey("error")) {
                titleName = "0x" + currentTitle.ToString("X4");
            } else titleName = obj.SelectToken("title").ToString();

            Log.Add(logId, ConsoleColor.Magenta, "Info", string.Format("Running title {0}", titleName), ip);*/

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

            writer.Write((int)status);
            writer.Write(Global.bFreemode);
            writer.Write(hasLifetime);
            writer.Write(days);
            writer.Write(hours);
            writer.Write(minutes);
            writer.Write(seconds);
            writer.Write(secondsLeft);

            writer.Write(client.bConsoleLinked);
            writer.Write(hasVerificationWaiting);
            writer.Write(verificationKey);

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
