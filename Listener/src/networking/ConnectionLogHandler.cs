using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;

namespace Listener {
    class ConnectionLogHandler {
        public void Start() {
            new Thread(new ThreadStart(Handler)).Start();
        }

        private static void Handler() {
            while (true) {
                try {
                    Thread.Sleep(10000);

                    List<string> indexToRemove = new List<string>();

                    foreach (var v in ClientHandler.SocketSpamConnectionLog) {
                        if ((Utils.GetTimeStamp() - v.Value.InitialTimestamp) > 120) {
                            if (!v.Value.bBanned) {
                                indexToRemove.Add(v.Key);
                            }
                        }
                    }

                    while (FirewallBanHandler.bUsingSpamDetection) Thread.Sleep(100);

                    foreach (var v in indexToRemove) {
                        ClientHandler.SocketSpamConnectionLog.Remove(v);
                    }
                } catch(Exception e) {
                    Console.WriteLine(e);
                }
            }
        }
    }
}
