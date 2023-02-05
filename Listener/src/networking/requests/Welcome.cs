using System;
using System.Collections.Generic;
using System.IO;

namespace Listener {
    class PacketWelcome {
        private enum eWelcomePacketStatus {
            STATUS_SUCCESS = 1,
            STATUS_REQUIRED_UPDATE,
            STATUS_NO_TIME,
            STATUS_DISABLED,
            STATUS_BANNED,
            STATUS_FREEMODE,
            STATUS_ERROR
        }

        public static void Handle(EndianReader reader, EndianWriter serverWriter, Header header, List<Log.PrintQueue> logId, string ip) {
            Log.Add(logId, ConsoleColor.Blue, "Command", "PacketWelcome", ip);
            Log.Add(logId, ConsoleColor.Cyan, "Console Key", Utils.BytesToString(header.szConsoleKey), ip);

            // the buffer that the resp is written into
            byte[] resp = new byte[326 + Global.iEncryptionStructSize];//309


            // the error buffer if an error occured, and the bool that shows if an error is present
            bool hasError = false;
            char[] error = new char[0x100];

            // the access token
            byte[] token = Utils.GenerateRandomData(32);
            ClientInfo client = new ClientInfo();
            KVStats stats = new KVStats();
            int daysOnKV = 1;
            int lastUsedVersion = 0;

            EndianWriter writer = new EndianWriter(new MemoryStream(resp), EndianStyle.BigEndian);

            eWelcomePacketStatus status = eWelcomePacketStatus.STATUS_NO_TIME;

            int xex = reader.ReadInt32();
            int userVersion = reader.ReadInt32();
            uint kvhash = reader.ReadUInt32();
            bool kvbanned = reader.ReadBoolean();
            bool devkit = reader.ReadBoolean();
            bool Nokvmode = reader.ReadBoolean();

            XexInfo xeinfo = new XexInfo();
            if (!MySQL.GetXexInfo(xex, ref xeinfo)) {
                Log.Add(logId, ConsoleColor.DarkYellow, "Reporting", string.Format("Xex identifier not found ({0})", xex), ip);

                status = eWelcomePacketStatus.STATUS_ERROR;
                hasError = true;
                Utils.AddStringToArray(ref error, string.Format("Xex identifier was invalid - please contact support and show them this message.\n\nInfo: {0}", xex));
                goto end;
            }

            if (userVersion != xeinfo.dwLastVersion) {
                // needs an update
                status = eWelcomePacketStatus.STATUS_REQUIRED_UPDATE;

                MySQL.AddRequestToken(Utils.BytesToString(token), Utils.BytesToString(header.szConsoleKey));
                goto end;
            }

            if (MySQL.GetClientData(Utils.BytesToString(header.szConsoleKey), ref client)) {
                switch (client.Status) {
                    case ClientInfoStatus.Banned:
                        status = eWelcomePacketStatus.STATUS_BANNED;
                        break;
                    case ClientInfoStatus.Disabled:
                        status = eWelcomePacketStatus.STATUS_DISABLED;
                        break;
                    case ClientInfoStatus.Authed:
                        status = eWelcomePacketStatus.STATUS_SUCCESS;
                        break;
                    case ClientInfoStatus.NoTime:
                        status = eWelcomePacketStatus.STATUS_NO_TIME;
                        break;
                    default:
                        status = eWelcomePacketStatus.STATUS_NO_TIME;
                        break;
                }

                lastUsedVersion = client.iLastUsedVersion;

                // update stuff
                MySQL.UpdateUserInfoWelcomePacket(Utils.BytesToString(header.szConsoleKey), kvhash.ToString("X4"), ip);
            } else {
                MySQL.AddUserWelcomePacket(Utils.BytesToString(header.szConsoleKey), Utils.BytesToString(header.szCPU), ip, kvhash.ToString("X4"));
                status = eWelcomePacketStatus.STATUS_SUCCESS;
            }

            if (devkit && !client.bAllowedOnDevkit) {
                Log.Add(logId, ConsoleColor.DarkYellow, "Reporting", string.Format("Client is running a devkit with no access", xex), ip);

                status = eWelcomePacketStatus.STATUS_ERROR;
                hasError = true;
                Utils.AddStringToArray(ref error, "You don't have access to xbLive on devkit!");
                goto end;
            }

            if (MySQL.GetKVStats(Nokvmode ? client.LastKVHash : kvhash.ToString("X4"), ref stats)) {
                // update shit
                MySQL.UpdateKVStat(Nokvmode ? client.LastKVHash : kvhash.ToString("X4"), kvbanned);
            } else {
                MySQL.AddKVStat(kvhash.ToString("X4"), (int)Utils.GetTimeStamp(), (int)Utils.GetTimeStamp(), kvbanned, kvbanned ? (int)Utils.GetTimeStamp() : 0);
            }

            // update stats
            MySQL.GetKVStats(Nokvmode ? client.LastKVHash : kvhash.ToString("X4"), ref stats);

            int daysOnKVDifference = (int)Utils.GetTimeStamp() - stats.iFirstConnection;
            if (daysOnKVDifference > 86400) {
                daysOnKV = (int)Math.Round((float)(daysOnKVDifference / 86400), 0);
            }

            Log.Add(logId, ConsoleColor.Magenta, "Info", string.Format("KV hash: {0}, banned: {1}, days: {2}, NoKvMode?: {3}", Nokvmode ? client.LastKVHash:kvhash.ToString("X4"), kvbanned ? "yes" : "no", daysOnKV, Nokvmode ? "yes":"no"), ip);


            if (status == eWelcomePacketStatus.STATUS_BANNED
                || status == eWelcomePacketStatus.STATUS_DISABLED) {
                hasError = true;

                if (client.NotifyOnSus.Length < 1) {
                    client.NotifyOnSus = "An unknown error occured! Rebooting...";
                }

                Utils.AddStringToArray(ref error, client.NotifyOnSus);
            } else {
                MySQL.AddRequestToken(Utils.BytesToString(token), Utils.BytesToString(header.szConsoleKey));

                if (Global.bFreemode) {
                    status = eWelcomePacketStatus.STATUS_FREEMODE;
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
            writer.Write(enc.iKey10);
            */
            writer.Write(enc.iHash);



            writer.Write((int)status);
            writer.Write(client.iTotalChallenges);
            writer.Write(stats.iTotalChallenges); // total challenges on THIS KV
            writer.Write(lastUsedVersion);
            writer.Write(daysOnKV); // days on KV
            writer.Write(hasError);
            writer.Write(token);

            writer.Write(error);
            writer.Close();
            Log.Add(logId, ConsoleColor.Magenta, "Info", string.Format("Sending token to client: {0}", Utils.BytesToString(token)), ip);
            Security.SendPacket(serverWriter, header, resp, enc);
            Log.Add(logId, ConsoleColor.Green, "Status", "Response sent", ip);
            Log.Print(logId);
        }
    }
}