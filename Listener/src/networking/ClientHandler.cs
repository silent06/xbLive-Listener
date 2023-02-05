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
    class ClientHandler {
        private TcpListener ListenerHandle;
        private Thread ListenerThread;
        public static Dictionary<string, SocketSpam> SocketSpamConnectionLog = new Dictionary<string, SocketSpam>();

        public ClientHandler() {
            ListenerHandle = new TcpListener(IPAddress.Any, Global.iPort);
        }

        public void Start() {
            ListenerThread = new Thread(new ThreadStart(() => {
                ListenerHandle.Start();

                while (true) {
                    Thread.Sleep(100);
                    if (ListenerHandle.Pending()) new Thread(new ParameterizedThreadStart(Handler)).Start(ListenerHandle.AcceptTcpClient());
                }
            }));
            ListenerThread.Start();
        }

        private void Handler(object client) {
            TcpClient tcpClient = (TcpClient)client;
            NetworkStream netStream = tcpClient.GetStream();
            string ip = tcpClient.Client.RemoteEndPoint.ToString().Split(new char[] { ':' })[0];

            EndianWriter serverWriter = new EndianWriter(netStream, EndianStyle.BigEndian);

            if (FirewallBanHandler.SpamDetection(ip)) {
                Console.WriteLine("Socket closed for {0} - SpamDetection was true!", ip);

                serverWriter.Write(0x13371337);
                serverWriter.Write((byte)0x1);
                serverWriter.Close();
                tcpClient.Close();
                return;
            }

            if (!netStream.CanRead) {
                Console.WriteLine("Socket closed for {0} - CanRead was false!", ip);
                tcpClient.Close();
                return;
            }

            try {
                List<Log.PrintQueue> logId = Log.GetQueue();
                Header header = new Header();

                byte[] neededHeaderData = new byte[0x8];
                if (netStream.Read(neededHeaderData, 0, 0x8) != 0x8) {
                    Log.Add(logId, ConsoleColor.DarkYellow, "Flag", "Failed to read header start", ip);
                    Log.Print(logId);

                    Utils.BanFromFirewallNonPerm(ip);

                    serverWriter.Write(0x13371337);
                    serverWriter.Write((byte)0x2);
                    serverWriter.Close();
                    tcpClient.Close();
                    return;
                }

                EndianReader baseHeaderParse = new EndianReader(new MemoryStream(neededHeaderData), EndianStyle.BigEndian);

                header.Command = (Packets)(baseHeaderParse.ReadInt32());

                if (!Enum.IsDefined(typeof(Packets), header.Command)) {
                    Log.Add(logId, ConsoleColor.DarkYellow, "Flag", "Client sent an invalid packet (" + header.Command + "). ", ip);
                    Log.Print(logId);

                    Utils.BanFromFirewallNonPerm(ip);

                    serverWriter.Write(0x13371337);
                    serverWriter.Write((byte)0x3);
                    serverWriter.Close();
                    tcpClient.Close();
                    return;
                }

                header.iSize = baseHeaderParse.ReadInt32();

                if (header.iSize > Global.iMaximumRequestSize) {
                    Log.Add(logId, ConsoleColor.DarkYellow, "Flag", "Client sent a header size bigger than the max (" + header.iSize + ").", ip);
                    Log.Print(logId);

                    Utils.BanFromFirewallNonPerm(ip);

                    serverWriter.Write(0x13371337);
                    serverWriter.Write((byte)0x4);
                    serverWriter.Close();
                    tcpClient.Close();
                    return;
                }

                byte[] data = new byte[header.iSize - 8];
                if (netStream.Read(data, 0, header.iSize - 8) != header.iSize - 8) {
                    Log.Add(logId, ConsoleColor.DarkYellow, "Flag", "Failed to read header (" + header.iSize + ").", ip);
                    Log.Print(logId);

                    Utils.BanFromFirewallNonPerm(ip);

                    serverWriter.Write(0x13371337);
                    serverWriter.Write((byte)0x5);
                    serverWriter.Close();
                    tcpClient.Close();
                    return;
                }

                byte[] untouchedData = new byte[header.iSize - 8];
                Buffer.BlockCopy(data, 0, untouchedData, 0, header.iSize - 8);

                EndianReader dataReader = new EndianReader(new MemoryStream(data), EndianStyle.BigEndian);




                header.szRandomKey = dataReader.ReadBytes(0x10);
                header.szRC4Key = dataReader.ReadBytes(0x10);


                header.bCPUEncryptionKey = dataReader.ReadByte();
                header.szCPU = dataReader.ReadBytes(0x10);
                header.bHypervisorCPUEncryptionKey = dataReader.ReadByte();
                header.szHypervisorCPU = dataReader.ReadBytes(0x10);
                header.bConsoleKeyEncryptionKey = dataReader.ReadByte();
                header.szConsoleKey = dataReader.ReadBytes(0x14);
                header.bTokenEncryptionKey = dataReader.ReadByte();
                header.szToken = dataReader.ReadBytes(0x20);


                header.Encryption.iKey1 = dataReader.ReadInt32();
                header.Encryption.iKey2 = dataReader.ReadInt32();
                header.Encryption.iKey3 = dataReader.ReadInt32();
                header.Encryption.iKey4 = dataReader.ReadInt32();
                header.Encryption.iKey5 = dataReader.ReadInt32();
                header.Encryption.iKey6 = dataReader.ReadInt32();
                header.Encryption.iKey7 = dataReader.ReadInt32();
                header.Encryption.iKey8 = dataReader.ReadInt32();
                header.Encryption.iKey9 = dataReader.ReadInt32();
                header.Encryption.iKey10 = dataReader.ReadInt32();
                header.Encryption.iHash = dataReader.ReadInt32();

                for (int i = 0; i < 0x10; i++) {
                    header.szCPU[i] ^= header.bCPUEncryptionKey;
                    header.szHypervisorCPU[i] ^= header.bHypervisorCPUEncryptionKey;
                }

                for (int i = 0; i < 0x14; i++) {
                    header.szConsoleKey[i] ^= header.bConsoleKeyEncryptionKey;
                }

                byte[] tokenDec = new byte[0x20];
                Array.Copy(header.szToken, tokenDec, 0x20);

                for (int i = 0; i < 0x20; i++) {
                    header.szToken[i] ^= header.bTokenEncryptionKey;
                }

                if (!header.szCPU.SequenceEqual(header.szHypervisorCPU)) {
                    MySQL.BanClient(Utils.BytesToString(header.szConsoleKey), "Account disabled for high chance spoofing");
                    Log.Add(logId, ConsoleColor.DarkYellow, "Flag", "Client sent a mismatching cpu set (spoofed)", ip);
                    Log.Print(logId);

                    serverWriter.Write(0x13371337);
                    serverWriter.Write((byte)0x6);
                    serverWriter.Close();
                    tcpClient.Close();
                    return;
                }

                Global.bFreemode = MySQL.IsFreemode();

                if (header.Command == Packets.PACKET_CONNECT)
                {
                    Log.Add(logId, ConsoleColor.Blue, "Command", "Incoming Connection....", ip);
                    // handle connection status
                    PacketConnect.Handle(dataReader, serverWriter, header, logId, ip);
                }
                else if (header.Command == Packets.PACKET_WELCOME)
                {
                    Log.Add(logId, ConsoleColor.Blue, "Command", "Handling Welcome Packets", ip);
                    // check status, creates access token for user.
                    PacketWelcome.Handle(dataReader, serverWriter, header, logId, ip);
                }
                else
                {
                    if (MySQL.DoesRequestTokenExist(Utils.BytesToString(header.szToken), Utils.BytesToString(header.szConsoleKey)))
                    {
                        MySQL.IncrementRequestTokenConnectionCount(Utils.BytesToString(header.szToken));

                       if(!Global.bFreemode)
                        MySQL.RefreshTimeInfo(Utils.BytesToString(header.szConsoleKey));

                        switch (header.Command) {
                                // downloads a cheat plugin
                            case Packets.PACKET_DOWNLOAD_PLUGIN:
                                PacketDownloadPlugin.Handle(dataReader, serverWriter, header, logId, ip);
                                break;
                                // gets info on plugins
                            case Packets.PACKET_GET_PLUGINS:
                                PacketGetPlugins.Handle(dataReader, serverWriter, header, logId, ip);
                                break;
                                // get the full xosc buffer
                            case Packets.PACKET_XOSC:
                                PacketXOSC.Handle(dataReader, serverWriter, header, logId, ip);
                                break;
                            case Packets.PACKET_HEARTBEAT:
                                // gets requested every 30s.
                                PacketHeartbeat.Handle(dataReader, serverWriter, header, logId, ip);
                                break;
                            case Packets.PACKET_GET_TIME:
                                // returns info on time - whether the client has lifetime, and the full time left in D, H, M & S.
                                PacketGetTime.Handle(dataReader, serverWriter, header, logId, ip);
                                break;
                            case Packets.PACKET_CHECK_TOKEN:
                                // checks a user inputted token to see if it's valid, and if it's already redeemed.
                                PacketCheckToken.Handle(dataReader, serverWriter, header, logId, ip);
                                break;
                            case Packets.PACKET_REDEEM_TOKEN:
                                // attempts to redeem a token inputted by the user.
                                PacketRedeemToken.Handle(dataReader, serverWriter, header, logId, ip);
                                break;
                            case Packets.PACKET_GET_CHALLENGE_RESPONSE:
                                //
                                PacketGetChallengeResponse.Handle(dataReader, serverWriter, header, logId, ip);
                                break;
                            case Packets.PACKET_GET_CHANGELOG:
                                PacketGetChangelog.Handle(dataReader, serverWriter, header, logId, ip);
                                break;
                            case Packets.PACKET_GET_UPDATE:
                                // used for both getting the size of the xex, and the xex bytes. Can be two different requests.
                                PacketGetUpdate.Handle(dataReader, serverWriter, header, logId, ip);
                                break;
                            case Packets.PACKET_GET_KV_STATS:
                                // used for getting the kv stat struct from a kv hash
                                PacketGetKVStats.Handle(dataReader, serverWriter, header, logId, ip);
                                break;
                            case Packets.PACKET_GET_TITLE_PATCHES:
                                // used for getting any patch data for a specific title id, i.e anti rce etc
                                PacketGetTitlePatches.Handle(dataReader, serverWriter, header, logId, ip);
                                break;
                            case Packets.PACKET_GET_PLUGIN_PATCHES:
                                // used for getting addresses that the cheats use
                                PacketGetPluginPatches.Handle(dataReader, serverWriter, header, logId, ip);
                                break;
                            case Packets.PACKET_METRIC:
                                // for when people do shit
                                PacketMetric.Handle(dataReader, serverWriter, header, logId, ip);
                                break;
                            case Packets.PACKET_BO3_CHALLENGE:
                                // B03 Challenges
                                packetB03.Handle(dataReader, serverWriter, header, logId, ip);/*Not complete*/
                                break;
                            case Packets.PACKET_GET_KV:
                                // Get KV.Bin
                                GetKV.Handle(dataReader, serverWriter, header, logId, ip);
                                break;
                        }
                    } 
                    else {
                        Log.Add(logId, ConsoleColor.DarkYellow, "Flag", string.Format("Client token doesn't exist - {0}", Utils.BytesToString(header.szToken)), ip);
                        Log.Add(logId, ConsoleColor.DarkYellow, "Flag", string.Format("Encrypted: {0}", Utils.BytesToString(tokenDec)), ip);
                        Log.Add(logId, ConsoleColor.DarkYellow, "Flag", string.Format("Key: {0}", header.bTokenEncryptionKey), ip);
                        Log.Add(logId, ConsoleColor.DarkYellow, "Flag", string.Format("Command: {0}", header.Command), ip);
                        Log.Add(logId, ConsoleColor.DarkYellow, "Flag", string.Format("CPU: {0}", Utils.BytesToString(header.szCPU)), ip);
                        Log.Add(logId, ConsoleColor.DarkYellow, "Flag", string.Format("Size: {0}", header.iSize), ip);
                        Log.Print(logId);

                        serverWriter.Write(0x13371337);
                        serverWriter.Write((byte)0x10);
                        serverWriter.Close();
                    }
                }
            } catch (Exception ex) {
                serverWriter.Close();
                Console.WriteLine("Error: {0} - {1}", ex.Message, ex.StackTrace);
            }

            tcpClient.Close();
        }
    }
}