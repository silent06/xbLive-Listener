using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Listener {

    class Global {
        public static int iConnectedClients = 0;
        public static int iPort;
        public static int iWebhookPort = 15423;
        public static int iMaximumRequestSize = 0x1000;
        public static bool bFreemode = false;
        public static int iCurrentXexVersion = 0;
        public static int iEncryptionStructSize = 44;
        public static string host;
        public static string Username;
        public static string password;
        public static string Database;
        public static string APIChallengeIP;
        public static int APIChallengePort;
    }

    public struct TimeCalc {
        public int iYears;
        public int iDays;
        public int iHours;
        public int iMinutes;
        public int iSeconds;

        public TimeCalc(int iSeconds_) {
            iYears = Math.Abs(iSeconds_ / (60 * 60 * 24 * 365));
            iDays = iSeconds_ / 86400;
            iHours = (iSeconds_ % 86400) / 3600;
            iMinutes = ((iSeconds_ % 86400) % 3600) / 60;
            iSeconds = (((iSeconds_ % 86400) % 3600) % 60) / 1;
        }
    };

    public enum ClientInfoStatus {
        Authed,
        NoTime,
        Banned,
        Disabled
    }

    public enum eMetricType {
        METRIC_NONE,
        METRIC_WARNING,
        METRIC_DISABLE_ACCOUNT
    };

    public enum eMetrics {
        METRICS_NONE,
        METRICS_INTEGRITY_CHECK_FAILED,
        METRICS_BREAKPOINT,
        METRICS_MODULE_DIGEST_MISMATCH
    };

    public struct ClientMetric {
        public eMetricType Type;
        public eMetrics Index;

        public ClientMetric(eMetricType type, eMetrics index) {
            Type = type;
            Index = index;
        }
    }

    public struct ClientInfo {
        public int iID;
        //public string Password;
        //public string Email;
        public string ConsoleKey;
        public string CPUKey;
        public string FirstGamertag;
        public string LastGamertag;
        public bool bConsoleLinked;
        public bool bBetaAccess;
        public bool bAllowedOnDevkit;
        public bool bDevkitCheats;
        public int iTimeEnd;
        public int iTimeBeforeReserve;
        public int iReserveSeconds;
        public string FirstIP;
        public string LastIP;
        public ClientInfoStatus Status;
        public string NotifyOnSus;
        public string FirstKVHash;
        public string LastKVHash;
        public int iLastConnection;
        public int iTotalChallenges;
        public int iLastUsedVersion;
        public string strNoKVHash;
        public int iNoKVLastRefresh;

        public string Discord;
        public string Discordid;
        public string Username;
        public string email;
        public string PrimaryUIColor;
        public string SecondaryUIColor;
        public string QlaunchId;
        public string TitleID;

    }//public string Username; took out username

    public struct ConsoleVerification {
        public int iID;
        public string VerificationKey;
        public string CPUKey;
        public int iTimeRequested;
    }

    public struct KVS
    {
        public int iID;
        public string strHash;
        public int iUses;
    }

    public struct XexInfo {
        public int iID;       
        public string PatchName;
        public uint dwLastVersion;
        public uint dwTitle;
        public uint dwTitleTimestamp;
        public bool bEnabled;
        public string Name;
        public bool bBetaOnly;
        public UInt64 EncryptionKey;

    }

    public struct SocketSpam {
        public long InitialTimestamp;
        public int iConnectionsMade;
        public bool bBanned;
        public long BannedTimestamp;
        public List<long> ConnectionTimestamps;

        public SocketSpam(long init, int con, bool banned, long bannedInit) {
            InitialTimestamp = init;
            iConnectionsMade = con;
            bBanned = banned;
            BannedTimestamp = bannedInit;
            ConnectionTimestamps = new List<long>();
        }
    }

    public enum Packets {
        PACKET_WELCOME =1,
        PACKET_HEARTBEAT,
        PACKET_GET_TIME,
        PACKET_CHECK_TOKEN,
        PACKET_REDEEM_TOKEN,
        PACKET_GET_CHALLENGE_RESPONSE,
        PACKET_GET_CHANGELOG,
        PACKET_GET_UPDATE,
        PACKET_XOSC,
        PACKET_GET_PLUGINS,
        PACKET_DOWNLOAD_PLUGIN,
        PACKET_GET_KV_STATS,
        PACKET_BO3_CHALLENGE,
        PACKET_GET_TITLE_PATCHES,
        PACKET_GET_PLUGIN_PATCHES,
        PACKET_METRIC,
        PACKET_CONNECT,
        PACKET_GET_KV
    }


    public struct EncryptionHeader {

        public int iKey1;
        public int iKey2;
        public int iKey3;
        public int iKey4;
        public int iKey5;
        public int iKey6;
        public int iKey7;
        public int iKey8;
        public int iKey9;
        public int iKey10;
        public int iHash;
    }

    public struct Header {
        public Packets Command;
        public int iSize;
        public byte[] szRandomKey; // 0x10 
        public byte[] szRC4Key;// 0x10 
        public byte bCPUEncryptionKey;
        public byte[] szCPU; // 0x10
        public byte bHypervisorCPUEncryptionKey;
        public byte[] szHypervisorCPU; // 0x10
        public byte bConsoleKeyEncryptionKey;
        public byte[] szConsoleKey; // 0x14 - SPECIAL IDENTIFIER!
        public byte bTokenEncryptionKey;
        public byte[] szToken; // 0x20

        // Encryption
        public EncryptionHeader Encryption;
    }

    public struct ClientEndPoint {
        public int iID;
        public string Token;
        public string ConsoleKey;
        public long LastConnection;
        public long WelcomeTime;
        public int iConnectionIndex;
        public bool bHasReceivedPresence;
        public uint dwCurrentTitle;
        public int iTotalXamChallenges;
    }

    public struct RedeemTokens {
        public int iID;
        public string Token;
        public int iSecondsToAdd;
        public string RedeemerConsoleKey;
    }

    public struct KVStats {
        public int iID;
        public string KVHash;
        public int iFirstConnection;
        public int iLastConnection;
        public bool bBanned;
        public int iBannedTime;
        public int iTotalChallenges;
    }


}
