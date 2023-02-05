using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Net;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json;
using System.Security.Cryptography;
namespace Listener {
    class Program {
        
        static void Main(string[] args) {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WindowWidth = 150;
            Console.WindowHeight = 31;
            Console.Title = "Stealth Server Client Handler";

            string filePath = "Mysqlconfig.ini";
            string filePath2 = "Settings.ini";

            if (!File.Exists(filePath))
            {
                throw new Exception("config.ini file not found");
            }

            if (!File.Exists(filePath2))
            {
                throw new Exception("Setting.ini file not found");
            }

            Utils.LoadedIni = new IniParsing("Mysqlconfig.ini");

            Global.iPort = Utils.GetPort();
            Global.APIChallengeIP = Utils.GetChallengeIP();
            Global.APIChallengePort = Utils.GetChallengePort();
            Global.host = Utils.GetSqlHostName();
            Global.Username = Utils.GetSqlUserName();
            Global.password = Utils.GetSqlPassword();
            Global.Database = Utils.GetSqlDatabase();

            try {
                // handles removing connections that aren't sus anymore
                new ConnectionLogHandler().Start();

                // handles unbanning banned ips from firewall after an hour
                new FirewallBanHandler().Start();

                // handles incoming packers
                new ClientHandler().Start();
                
                // handles presence to make sure you've received the needed presence
                new HeartbeatHandler().Start();

                new Thread(() => {
                    while (true) {
                        Global.bFreemode = MySQL.IsFreemode();
                        Console.Title = string.Format("Stealth Server Client Handler | Online Clients: {0} | Freemode: {1} | Port: {2} | SQL connected to: {3} | SQL Database: {4} | ", Global.iConnectedClients, Global.bFreemode ? "True":"False", Global.iPort, Global.host, Global.Database);

                        Thread.Sleep(10000);
                    }
                }).Start();
            } catch (Exception exception) {
                Console.WriteLine("Exception: " + exception.Message);
            }
        }
    }
}
