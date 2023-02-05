using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading;

namespace Listener {
    class HeartbeatHandler {
        public void Start() {
            new Thread(new ThreadStart(Handler)).Start();
        }

        private static void Handler() {
            while (true) {
                try {
                    Dictionary<string, string> tokensToRemove = new Dictionary<string, string>();

                    List<ClientEndPoint> endPoints = MySQL.GetAllClientEndPoints();
                    Global.iConnectedClients = endPoints.Count;

                    foreach (var ep in endPoints) {
                        long timestamp = Utils.GetTimeStamp();

                        if (!ep.bHasReceivedPresence) {
                            if ((timestamp - ep.WelcomeTime) > 420) {
                                //Update Online status
                                MySQL.UpdateCurrentOnline(ep.ConsoleKey, 1); 
                                tokensToRemove.Add(ep.Token, "Hasn't sent initial presence in over 420 seconds");

                                continue;
                            }
                        }

                        if ((timestamp - ep.LastConnection) > 420) {
                            //Update Online status
                            MySQL.UpdateCurrentOnline(ep.ConsoleKey, 1);
                            tokensToRemove.Add(ep.Token, "Hasn't sent presence in over 420 seconds");

                            continue;
                        }
                    }

                    foreach (var token in tokensToRemove) {
                        Console.WriteLine("Deleting token: {0} - {1}", token.Key, token.Value);

                        MySQL.RemoveRequestToken(token.Key);
                    }

                    tokensToRemove.Clear();
                    endPoints.Clear();

                    Thread.Sleep(5000);
                } catch (Exception e) {
                    Console.WriteLine(e);
                }
            }
        }
    }
}
