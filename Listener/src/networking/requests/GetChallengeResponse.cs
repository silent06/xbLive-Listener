using System;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Collections.Generic;

namespace Listener {
    class PacketGetChallengeResponse {
        public static bool SendAPIRequest(ref byte[] output, byte[] hvsalt, byte[] sessionsalt, byte[] cpu, byte[] kvCpu, bool typeone, bool fcrt, bool crl, bool fake) {
            try {
                TcpClient client = new TcpClient(Global.APIChallengeIP, Global.APIChallengePort);
                NetworkStream stream = client.GetStream();

                byte[] data = new byte[0x44];

                BinaryWriter serverWriter = new BinaryWriter(new MemoryStream(data));

                serverWriter.Write(hvsalt);
                serverWriter.Write(sessionsalt);
                serverWriter.Write(cpu);
                //serverWriter.Write(kvCpu);
                serverWriter.Write(cpu);
                serverWriter.Write(typeone);
                serverWriter.Write(fcrt);
                serverWriter.Write(crl);
                serverWriter.Write(fake); // fake
                serverWriter.Close();

                stream.Write(data, 0, data.Length);

                string responseData = string.Empty;

                int bytes = stream.Read(output, 0, output.Length);
                if (bytes != 0x120) {
                    stream.Close();
                    client.Close();
                    Console.WriteLine("API ERROR - Received: {0}, instead of 0x120", bytes);
                    return false;
                }

                stream.Close();
                client.Close();

                return true;
            } catch (ArgumentNullException e) {
                Console.WriteLine("API ERROR - ArgumentNullException: {0}", e);
            } catch (SocketException e) {
                Console.WriteLine("API ERROR - SocketException: {0}", e);
            }

            return false;
        }

        public static void Handle(EndianReader reader, EndianWriter serverWriter, Header header, List<Log.PrintQueue> logId, string ip) {
            Log.Add(logId, ConsoleColor.Blue, "Command", "PacketGetChallengeResponse", ip);
            Log.Add(logId, ConsoleColor.Cyan, "Console Key", Utils.BytesToString(header.szConsoleKey), ip);

            // the buffer that the resp is written into
            byte[] resp = new byte[32 + 0x120 + Global.iEncryptionStructSize];

            EndianWriter writer = new EndianWriter(new MemoryStream(resp), EndianStyle.BigEndian);

            byte[] challengeResp = new byte[0x120];
            byte[] sessionsalt = new byte[0x10];
            bool fake = false;
            bool good = false;

            byte[] hvsalt = reader.ReadBytes(0x10);
            byte[] kvcpu = reader.ReadBytes(0x10);
            bool typeone = reader.ReadBoolean();
            bool fcrt = reader.ReadBoolean();
            bool crl = reader.ReadBoolean();

            Buffer.BlockCopy(header.szToken, 0, sessionsalt, 0, 0x10);

            ClientEndPoint endPoint = new ClientEndPoint();
            if (!MySQL.GetClientEndPoint(Utils.BytesToString(header.szToken), ref endPoint)) {
                goto end;
            }

            MySQL.IncrementRequestTokenChallengeCount(Utils.BytesToString(header.szToken));

            // if they've been connected less than 1 hour
            if (Utils.GetTimeStamp() - endPoint.WelcomeTime < 1800) {
                if (endPoint.iTotalXamChallenges > 25) {
                    // no fuckin way they sending more than 25 xam challenges within an hour
                    fake = true;
                }
            } else {
                // if it's been less than 3 hours
                if (Utils.GetTimeStamp() - endPoint.WelcomeTime < (3600 * 3)) {
                    if (endPoint.iTotalXamChallenges > 100) {
                        // no fuckin way they sending more than 50 xam challenges within an hour
                        fake = true;
                    }
                }
            }

            ClientInfo client = new ClientInfo();
            if (MySQL.GetClientData(Utils.BytesToString(header.szConsoleKey), ref client)) {
                MySQL.IncrementChallengeCount(Utils.BytesToString(header.szConsoleKey));

                if (client.iTimeEnd < (int)Utils.GetTimeStamp() && client.iReserveSeconds == 0 && !Global.bFreemode) {
                    // no time left
                    good = false;
                } else {
                    for (int i = 0; i < 5; i++) {
                        if (SendAPIRequest(ref challengeResp, hvsalt, sessionsalt, header.szCPU, kvcpu, typeone, fcrt, crl, fake)) {
                            good = true;
                            break;
                        }
                    }
                }
            }
            
            Security.RC4(ref challengeResp, sessionsalt);

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

            if (good)
                writer.Write(challengeResp);

            writer.Close();

            Security.SendPacket(serverWriter, header, resp, enc);
            Log.Add(logId, ConsoleColor.Green, "Status", "Response sent", ip);
            Log.Print(logId);
        }
    }
}
