using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Listener {
    class FirewallBanHandler {
        public static bool bUsingSpamDetection;
        public void Start() {
            new Thread(new ThreadStart(Handler)).Start();
        }

        private static void Handler() {
            while (true) {
                try
                {
                    foreach (var con in ClientHandler.SocketSpamConnectionLog.ToList()) {
                        if (con.Value.bBanned) {
                            if ((Utils.GetTimeStamp() - con.Value.BannedTimestamp) > 3600) {
                                // if it's been more than an hour since ban

                                // get the current socket spam struct from the connections dict, and update the ban details
                                SocketSpam spam = ClientHandler.SocketSpamConnectionLog[con.Key];
                                spam.bBanned = false;
                                spam.BannedTimestamp = 0;

                                // Update the connection handler with the unbanned socket, and unban the ip from the firewall.
                                ClientHandler.SocketSpamConnectionLog[con.Key] = spam;
                                Utils.UnbanFromFirewall(con.Key);
                            }
                        }
                    }

                    Thread.Sleep(10000);
                } catch (Exception e) {
                    Console.WriteLine(e);
                }
            }
        }

        public static bool SpamDetection(string ip) {
            if (ClientHandler.SocketSpamConnectionLog.ContainsKey(ip)) {
                if (ClientHandler.SocketSpamConnectionLog.TryGetValue(ip, out SocketSpam spamOut)) {
                    if (spamOut.bBanned) return true;

                    spamOut.iConnectionsMade++;
                    spamOut.ConnectionTimestamps.Add(Utils.GetTimeStamp());

                    ClientHandler.SocketSpamConnectionLog[ip] = spamOut;

                    int detection = 0;

                    if (spamOut.ConnectionTimestamps.Count >= 2) {
                        for (int i = 0; i < spamOut.ConnectionTimestamps.Count; i++) {
                            if (i == spamOut.ConnectionTimestamps.Count - 1) {
                                // last iteration
                                break;
                            } else {
                                // if the current connection timestamp minus the last is within a second
                                if ((spamOut.ConnectionTimestamps[i + 1] - spamOut.ConnectionTimestamps[i]) <= 1) {
                                    detection++;
                                }
                            }
                        }
                    }

                    if (detection >= 50) {
                        Console.WriteLine("detection: {0}", detection);

                        Utils.BanFromFirewall(ip);
                        spamOut.BannedTimestamp = Utils.GetTimeStamp();
                        spamOut.bBanned = true;
                        ClientHandler.SocketSpamConnectionLog[ip] = spamOut;

                        Console.WriteLine("Socket spam detected from {0}", ip);
                        bUsingSpamDetection = false;
                        return true;
                    }
                }
            } else {
                ClientHandler.SocketSpamConnectionLog.Add(ip, new SocketSpam(Utils.GetTimeStamp(), 0, false, 0));
            }

            bUsingSpamDetection = false;
            return false;
        }
    }
}
