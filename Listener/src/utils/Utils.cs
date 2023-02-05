using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.IO;
using System.Reflection;

namespace Listener {

    class INIReader
    {
        string Path;
        string EXE = Assembly.GetExecutingAssembly().GetName().Name;
        string SettingsName = "Settings";


        [DllImport("kernel32")]
        static extern long WritePrivateProfileString(string Section, string Key, string Value, string FilePath);

        [DllImport("kernel32")]
        static extern int GetPrivateProfileString(string Section, string Key, string Default, StringBuilder RetVal, int Size, string FilePath);

        public INIReader(string IniPath = null)
        {
            //Path = new FileInfo(IniPath ?? EXE + ".ini").FullName.ToString();
            Path = new FileInfo(IniPath ?? SettingsName + ".ini").FullName.ToString();
        }

        public string Read(string Key, string Section = null)
        {
            var RetVal = new StringBuilder(255);
            GetPrivateProfileString(Section ?? EXE, Key, "", RetVal, 255, Path);
            return RetVal.ToString();
        }

        public void Write(string Key, string Value, string Section = null)
        {
            WritePrivateProfileString(Section ?? EXE, Key, Value, Path);
        }

        public void DeleteKey(string Key, string Section = null)
        {
            Write(Key, null, Section ?? EXE);
        }

        public void DeleteSection(string Section = null)
        {
            Write(null, null, Section ?? EXE);
        }

        public bool KeyExists(string Key, string Section = null)
        {
            return Read(Key, Section).Length > 0;
        }

    }

    internal class IniParsing
    {
        private string path;
        string SettingsName = "config";
        string EXE = Assembly.GetExecutingAssembly().GetName().Name;

        [DllImport("kernel32")]
        private static extern long WritePrivateProfileString(string section, string key, string val, string filePath);
        [DllImport("kernel32")]
        private static extern int GetPrivateProfileString(string section, string key, string def, StringBuilder retVal, int size, string filePath);


        public IniParsing(string INIPath)
        {
            //path = INIPath;
            path = new FileInfo(INIPath ?? SettingsName + ".ini").FullName.ToString();
        }

        public void IniWriteValue(string Section, string Key, string Value)
        {
            WritePrivateProfileString(Section, Key, Value, this.path);
        }

        public string IniReadValue(string Section, string Key)
        {
            StringBuilder temp = new StringBuilder(255);
            int i = GetPrivateProfileString(Section, Key, "", temp, 255, this.path);
            return temp.ToString();
        }

    }

    class Utils {
        
        public static IniParsing LoadedIni;

        public static INIReader INI = new INIReader("Settings.ini");

        public static int GetChallengePort()
        {
            return Convert.ToInt32(INI.Read("APIChallenegePort", "Setting"));
        }

        public static string GetChallengeIP()
        {
            return INI.Read("APIChallenege", "Setting");
        }

        public static int GetPort()
        {
            return Convert.ToInt32(INI.Read("Port", "Setting"));
        }

        public static string GetSqlHostName()
        {
            return LoadedIni.IniReadValue("mysql", "host");
        }

        public static string GetSqlUserName()
        {
            return LoadedIni.IniReadValue("mysql", "username");
        }

        public static string GetSqlPassword()
        {
            return LoadedIni.IniReadValue("mysql", "password");
        }

        public static string GetSqlDatabase()
        {
            return LoadedIni.IniReadValue("mysql", "database");
        }

        public static long GetTimeStamp() {
            return DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        }

        public static void SecondsToTime(int sec, ref int days, ref int hours, ref int minutes, ref int secnds) {
            string val = "";

            TimeSpan t = TimeSpan.FromSeconds(Convert.ToDouble(sec.ToString()));
            if (t.Days > 0)
                val = t.ToString(@"d\d\,\ hh\:mm\:ss");
            else val = t.ToString(@"hh\:mm\:ss");

            if (t.Days > 0) {
                days = int.Parse(val.Substring(0, val.IndexOf(',') - 1));
                hours = int.Parse(val.Substring(val.IndexOf(',') + 2, 2));
                minutes = int.Parse(val.Substring(val.IndexOf(':') + 1, 2));
                secnds = int.Parse(val.Substring(val.LastIndexOf(':') + 1));
            } else {
                hours = int.Parse(val.Substring(0, val.IndexOf(':')));
                minutes = int.Parse(val.Substring(val.IndexOf(':') + 1, 2));
                secnds = int.Parse(val.Substring(val.LastIndexOf(':') + 1));
            }
        }

        public static void AddStringToArray(ref char[] array, string err) {
            Array.Copy(err.ToCharArray(), 0, array, 0, err.Length);
        }
        public static byte[] StringToByteArray(string str)
        {
            return Enumerable.Range(0, str.Length).Where(x => x % 2 == 0).Select(x => Convert.ToByte(str.Substring(x, 2), 16)).ToArray();
        }
        public static byte[] GenerateRandomData(int count) {
            byte[] RandData = new byte[count];
            new Random().NextBytes(RandData);

            return RandData;
        }

        public static char[] GenerateRandomDataChars(int count) {
            byte[] RandData = new byte[count];
            new Random().NextBytes(RandData);

            return System.Text.Encoding.UTF8.GetString(RandData).ToCharArray();
        }

        public static string BytesToString(byte[] Buffer) {
            string str = "";
            for (int i = 0; i < Buffer.Length; i++) str = str + Buffer[i].ToString("X2");
            return str;
        }

        public static string BytesToStringSpaced(byte[] Buffer) {
            string str = "";
            for (int i = 0; i < Buffer.Length; i++) str = str + Buffer[i].ToString("X2") + " ";
            return str;
        }

        public static byte[] StringToBytes(string str) {
            Dictionary<string, byte> hexindex = new Dictionary<string, byte>();
            for (int i = 0; i <= 255; i++)
                hexindex.Add(i.ToString("X2"), (byte)i);

            List<byte> hexres = new List<byte>();
            for (int i = 0; i < str.Length; i += 2)
                hexres.Add(hexindex[str.Substring(i, 2)]);

            return hexres.ToArray();
        }

        public static string WindowsCmdExec(string cmd) {
            var process = new Process() {
                StartInfo = new ProcessStartInfo("cmd") {
                    UseShellExecute = false,
                    RedirectStandardInput = true,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true,
                    Arguments = string.Format("/c \"{0}\"", cmd)
                }
            };
            process.Start();
            return process.StandardOutput.ReadToEnd();
        }


        public static void BanFromFirewallNonPerm(string ip) {
            BanFromFirewall(ip);
            ClientHandler.SocketSpamConnectionLog[ip] = new SocketSpam(GetTimeStamp(), 100, true, GetTimeStamp());
        }

        public static void BanFromFirewall(string ip) {
            WindowsCmdExec(string.Format("netsh advfirewall firewall add rule name=\"" +
               "STEALTH_BAN@{0}\" " + "dir=in interface=any action=block remoteip={0}", ip));

            Console.WriteLine("{0} has been banned from the firewall", ip);
        }

        public static void UnbanFromFirewall(string ip) {
            WindowsCmdExec(string.Format("netsh advfirewall firewall delete rule name=\"" +
               "STEALTH_BAN@{0}\"", ip));

            Console.WriteLine("{0} has been unbanned from the firewall", ip);
        }
    }
}
