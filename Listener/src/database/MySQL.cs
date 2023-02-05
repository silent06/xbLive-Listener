using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using MySql.Data.MySqlClient;
using Newtonsoft.Json.Linq;

namespace Listener {
    class MySQL {
        public static MySqlConnection Setup() {
            return new MySqlConnection(String.Format("Server={0};Port=3306;Database={1};Uid={2};Password={3};", Global.host, Global.Database, Global.Username, Global.password));
        }

        public static bool Connect(MySqlConnection connection) {
            try {
                connection.Open();
                return true;
            } catch (MySqlException exception) {
                Console.WriteLine(exception.Message);
                return false;
            }
        }

        public static void Disconnect(MySqlConnection connection) {
            try {
                connection.Close();
            } catch (MySqlException exception) {
                Console.WriteLine(exception.Message);
            }
        }

        public static void UpdateClientNoKVHash(string consoleKey, string hash)
        {

            using (var db = Setup())
            {
                Connect(db);
                using (var command = db.CreateCommand())
                {
                    command.CommandText = string.Format("UPDATE `users` SET `no_kv_hash` = @nokvhash2 WHERE `console_key` = @consolekey2");
                    command.Parameters.AddWithValue("@consolekey2", consoleKey);
                    command.Parameters.AddWithValue("@nokvhash2", hash);
                    command.ExecuteNonQuery();
                }
                Disconnect(db);
            }
        }

        public static void UpdateClientNoKVLastRefresh(string consoleKey)
        {

            using (var db = Setup())
            {
                Connect(db);
                using (var command = db.CreateCommand())
                {
                    command.CommandText = string.Format("UPDATE `users` SET `no_kv_last_refresh` = @nokvlastrefresh WHERE `console_key` = @consoleKey");
                    command.Parameters.AddWithValue("@consoleKey", consoleKey);
                    command.Parameters.AddWithValue("@nokvlastrefresh", (int)Utils.GetTimeStamp());                  
                    command.ExecuteNonQuery();
                }

                Disconnect(db);
            }
        }


        public static void IncrementKVUsesCount(string hash)
        {

            using (var db = Setup())
            {
                Connect(db);
                using (var command = db.CreateCommand())
                {
                    command.CommandText = string.Format("UPDATE `kvs` SET `uses` = +1 WHERE `hash` = @hash");
                    command.Parameters.AddWithValue("@hash", hash);
                    command.ExecuteNonQuery();
                }

                Disconnect(db);
            }
        }

        public static void DecrementKVUsesCount(string hash)
        {

            using (var db = Setup())
            {
                Connect(db);
                using (var command = db.CreateCommand())
                {
                    command.CommandText = string.Format("UPDATE `kvs` SET `uses` = -1 WHERE `hash` = @hash");
                    command.Parameters.AddWithValue("@hash", hash);
                    command.ExecuteNonQuery();
                }

                Disconnect(db);
            }
        }




        public static List<KVS> GetKVs()
        {
            List<KVS> kvs = new List<KVS>();
            using (var db = Setup())
            {
                Connect(db);
                using (var command = db.CreateCommand())
                {
                    command.CommandText = string.Format("SELECT * FROM kvs");
                    using (var reader = command.ExecuteReader())
                    {
                        if (reader.HasRows)
                        {
                            while (reader.Read())
                            {
                                KVS data = new KVS
                                {
                                    iID = reader.GetInt32("id"),
                                    strHash = reader.GetString("hash"),
                                    iUses = reader.GetInt32("uses")
                                };
                                kvs.Add(data);
                            }
                        }
                    }
                }
                Disconnect(db);
            }
            return kvs;
        }

        public static void UpdateUsingKVEndpointStatus(string token, bool status)
        {

            using (var db = Setup())
            {
                Connect(db);
                using (var command = db.CreateCommand())
                {
                    command.CommandText = string.Format("UPDATE `access_tokens` SET `using_no_kv` = @status WHERE `token` = @token");
                    command.Parameters.AddWithValue("@status", status);
                    command.Parameters.AddWithValue("@token", token);
                    command.ExecuteNonQuery();
                }

                Disconnect(db);
            }
        }

        public static bool IsFreemode() {
            using (var db = Setup()) {
                Connect(db);

                using (var command = db.CreateCommand()) {
                    command.CommandText = string.Format("SELECT * FROM `vars` WHERE `id` = 1");
                    using (var reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            int freemode = reader.GetInt32("freemode");
                            if (freemode == 1)
                            {
                                return true;
                            }
                            else
                            {
                                return false;
                            }
                        }
                    }
                }
                Disconnect(db);
            }

            return false;
        }


        public static List<XexInfo> GetXexInfos() {
            List<XexInfo> xexInfos = new List<XexInfo>();

            using (var db = Setup()) {
                Connect(db);
                using (var command = db.CreateCommand()) {
                    command.CommandText = string.Format("SELECT * FROM xex_data");
                    using (var reader = command.ExecuteReader()) {
                        if (reader.HasRows) {
                            while (reader.Read()) {
                                XexInfo data = new XexInfo {
                                    iID = reader.GetInt32("id"),
                                    dwLastVersion = reader.GetUInt32("latest_version"),
                                    Name = reader.GetString("name"),
                                    dwTitle = Convert.ToUInt32(reader.GetString("title")),
                                    dwTitleTimestamp = reader.GetUInt32("title_timestamp"),
                                    bEnabled = reader.GetBoolean("enabled"),
                                    bBetaOnly = reader.GetBoolean("beta_only"),
                                    EncryptionKey = Convert.ToUInt64(reader.GetString("encryption_key"))

                                };

                                xexInfos.Add(data);
                            }
                        }
                    }
                }
                Disconnect(db);
            }

            return xexInfos;
        }

        public static bool GetXexInfo(int id, ref XexInfo data) {
            using (var db = Setup()) {
                Connect(db);
                using (var command = db.CreateCommand()) {
                    command.CommandText = string.Format("SELECT * FROM xex_data WHERE `id` = @key");
                    command.Parameters.AddWithValue("@key", id);
                    using (var reader = command.ExecuteReader()) {
                        if (reader.Read()) {
                            data.iID = reader.GetInt32("id");
                            data.dwLastVersion = reader.GetUInt32("latest_version");
                            data.Name = reader.GetString("name");
                            data.dwTitle = Convert.ToUInt32(reader.GetString("title"));
                            data.dwTitleTimestamp = reader.GetUInt32("title_timestamp");
                            data.bEnabled = reader.GetBoolean("enabled");
                            data.PatchName = reader.GetString("patch_name");
                            data.bBetaOnly = reader.GetBoolean("beta_only");

                            Disconnect(db);
                            return true;
                        }
                    }
                }
                Disconnect(db);
            }
            return false;
        }

        public static bool DoesRedeemTokenExist(string token, ref bool alreadyRedeemed) {
            using (var db = Setup()) {
                Connect(db);
                using (var command = db.CreateCommand()) {
                    command.CommandText = string.Format("SELECT * FROM redeem_tokens WHERE `token` = @token");
                    command.Parameters.AddWithValue("@token", token);
                    using (var reader = command.ExecuteReader()) {
                        if (reader.Read()) {
                            alreadyRedeemed = reader.GetString("redeemer_console_key") != "--none--";
                            Disconnect(db);
                            return true;
                        }
                    }
                }
                Disconnect(db);
            }

            return false;
        }

        public static void GetTokenTimeAndRedeem(string token, string consolekey, ref int seconds) {
            ClientInfo info = new ClientInfo();
            if (GetClientData(consolekey, ref info)) {
                if (info.Status != ClientInfoStatus.Banned && info.Status != ClientInfoStatus.Disabled) {
                    using (var db = Setup()) {
                        Connect(db);
                        using (var command = db.CreateCommand()) {
                            command.CommandText = string.Format("SELECT * FROM redeem_tokens WHERE `token` = @token");
                            command.Parameters.AddWithValue("@token", token);
                            using (var reader = command.ExecuteReader()) {
                                if (reader.Read()) {
                                    seconds = reader.GetInt32("seconds_to_add");
                                }
                            }
                        }

                        using (var command = db.CreateCommand()) {
                            command.CommandText = string.Format("UPDATE redeem_tokens SET redeemer_console_key = @console_key WHERE `token` = @token");
                            command.Parameters.AddWithValue("@token", token);
                            command.Parameters.AddWithValue("@console_key", consolekey);
                            command.ExecuteNonQuery();
                        }

                        using (var command = db.CreateCommand()) {
                            command.CommandText = string.Format("UPDATE users SET time_end = @time_end, `status` = 0 WHERE `console_key` = @console_key");
                            command.Parameters.AddWithValue("@console_key", consolekey);

                            if (info.iTimeEnd > (int)Utils.GetTimeStamp()) {
                                command.Parameters.AddWithValue("@time_end", info.iTimeEnd + seconds);
                            } else {
                                command.Parameters.AddWithValue("@time_end", (int)Utils.GetTimeStamp() + seconds);
                            }

                            command.ExecuteNonQuery();
                        }

                        Disconnect(db);
                    }
                }
            }
        }

        public static List<RedeemTokens> GetRedeemTokens() {
            List<RedeemTokens> redeemTokens = new List<RedeemTokens>();

            using (var db = Setup()) {
                Connect(db);
                using (var command = db.CreateCommand()) {
                    command.CommandText = string.Format("SELECT * FROM redeem_tokens");
                    using (var reader = command.ExecuteReader()) {
                        if (reader.HasRows) {
                            while (reader.Read()) {
                                RedeemTokens t = new RedeemTokens {
                                    iID = reader.GetInt32("id"),
                                    Token = reader.GetString("token"),
                                    iSecondsToAdd = reader.GetInt32("seconds_to_add"),
                                    RedeemerConsoleKey = reader.GetString("redeemer_console_key")
                                };
                                redeemTokens.Add(t);
                            }
                        }
                    }
                }
                Disconnect(db);
            }

            return redeemTokens;
        }

        public static List<ClientEndPoint> GetAllClientEndPoints() {
            List<ClientEndPoint> endPoints = new List<ClientEndPoint>();
            using (var db = Setup()) {
                Connect(db);
                using (var command = db.CreateCommand()) {
                    command.CommandText = string.Format("SELECT * FROM access_tokens");
                    using (var reader = command.ExecuteReader()) {
                        if (reader.HasRows) {
                            while (reader.Read()) {
                                ClientEndPoint ep = new ClientEndPoint {
                                    bHasReceivedPresence = reader.GetBoolean("has_received_presence"),
                                    Token = reader.GetString("token"),
                                    LastConnection = reader.GetInt64("last_connection"),
                                    WelcomeTime = reader.GetInt64("welcome_time"),
                                    iConnectionIndex = reader.GetInt32("connection_index"),
                                    ConsoleKey = reader.GetString("console_key"),
                                    dwCurrentTitle = uint.Parse(reader.GetString("current_title"), System.Globalization.NumberStyles.HexNumber),
                                    iTotalXamChallenges = reader.GetInt32("total_xam_challenges")
                                };
                                endPoints.Add(ep);
                            }
                        }
                    }
                }
                Disconnect(db);
            }

            return endPoints;
        }

        public static bool GetClientEndPoint(string token, ref ClientEndPoint ep) {
            using (var db = Setup()) {
                Connect(db);
                using (var command = db.CreateCommand()) {
                    command.CommandText = string.Format("SELECT * FROM access_tokens WHERE `token` = @token");
                    command.Parameters.AddWithValue("@token", token);
                    using (var reader = command.ExecuteReader()) {
                        if (reader.Read()) {
                            ep = new ClientEndPoint {
                                bHasReceivedPresence = reader.GetBoolean("has_received_presence"),
                                Token = reader.GetString("token"),
                                LastConnection = reader.GetInt64("last_connection"),
                                WelcomeTime = reader.GetInt64("welcome_time"),
                                iConnectionIndex = reader.GetInt32("connection_index"),
                                ConsoleKey = reader.GetString("console_key"),
                                dwCurrentTitle = uint.Parse(reader.GetString("current_title"), System.Globalization.NumberStyles.HexNumber),
                                iTotalXamChallenges = reader.GetInt32("total_xam_challenges")
                            };

                            Disconnect(db);
                            return true;
                        }
                    }
                }
                Disconnect(db);
            }

            return false;
        }

        public static List<ClientInfo> GetAllClientsWithTime() {
            List<ClientInfo> endPoints = new List<ClientInfo>();
            using (var db = Setup()) {
                Connect(db);
                using (var command = db.CreateCommand()) {
                    command.CommandText = string.Format("SELECT * FROM users WHERE time_end > @cur");
                    command.Parameters.AddWithValue("@cur", (int)Utils.GetTimeStamp());
                    using (var reader = command.ExecuteReader()) {
                        if (reader.HasRows) {
                            while (reader.Read()) {
                                ClientInfo d = new ClientInfo();
                                if (GetClientData(reader.GetString("console_key"), ref d)) {
                                    endPoints.Add(d);
                                }
                            }
                        }
                    }
                }
                Disconnect(db);
            }

            return endPoints;
        }

        public static void DeleteConsoleVerification(string cpu) {
            using (var db = Setup()) {
                Connect(db);
                using (var command = db.CreateCommand()) {
                    command.CommandText = string.Format("DELETE FROM console_verification WHERE `cpu_key` = @cpu_key");
                    command.Parameters.AddWithValue("@cpu_key", cpu);
                    command.ExecuteNonQuery();
                }
                Disconnect(db);
            }
        }

        public static bool GetConsoleVerification(string cpu, ref ConsoleVerification verification) {
            using (var db = Setup()) {
                Connect(db);
                using (var command = db.CreateCommand()) {
                    command.CommandText = string.Format("SELECT * FROM console_verification WHERE cpu_key = @key");
                    command.Parameters.AddWithValue("@key", cpu);
                    using (var reader = command.ExecuteReader()) {
                        if (reader.Read()) {
                            verification.iID = reader.GetInt32("id");
                            verification.VerificationKey = reader.GetString("verification_key");
                            verification.CPUKey = reader.GetString("cpu_key");
                            verification.iTimeRequested = reader.GetInt32("time_requested");

                            Disconnect(db);
                            return true;
                        }
                    }
                }
                Disconnect(db);
            }
            return false;
        }

        public static void RefreshTimeInfo(string console_key) {

            if (!Global.bFreemode)
            {
                ClientInfo info = new ClientInfo();
                if (GetClientData(console_key, ref info))
                {
                    if (info.iReserveSeconds < 30)
                    {
                        if (info.iTimeBeforeReserve != 0)
                        {
                            if (info.iTimeEnd > (int)Utils.GetTimeStamp())
                            {
                                info.iTimeEnd += info.iTimeBeforeReserve;
                                info.iTimeBeforeReserve = 0;
                            }
                            else
                            {
                                info.iTimeEnd = (int)Utils.GetTimeStamp() + info.iTimeBeforeReserve;
                                info.iTimeBeforeReserve = 0;
                            }

                            using (var db = Setup())
                            {
                                Connect(db);
                                using (var command = db.CreateCommand())
                                {
                                    command.CommandText = string.Format("UPDATE `users` SET `time_end` = @timeend, `time_before_reserve` = @timebeforereserve WHERE `console_key` = @console_key");
                                    command.Parameters.AddWithValue("@timebeforereserve", info.iTimeBeforeReserve);
                                    command.Parameters.AddWithValue("@timeend", info.iTimeEnd);
                                    command.Parameters.AddWithValue("@console_key", console_key);
                                    command.ExecuteNonQuery();
                                }

                                Disconnect(db);
                            }
                        }
                        else
                        {
                            if (info.iTimeEnd < (int)Utils.GetTimeStamp())
                            {
                                if (info.Status == ClientInfoStatus.Authed)
                                {
                                    using (var db = Setup())
                                    {
                                        Connect(db);
                                        using (var command = db.CreateCommand())
                                        {
                                            command.CommandText = string.Format("UPDATE `users` SET `status` = @status WHERE `console_key` = @console_key");
                                            command.Parameters.AddWithValue("@status", ClientInfoStatus.NoTime);
                                            command.Parameters.AddWithValue("@console_key", console_key);
                                            command.ExecuteNonQuery();
                                        }

                                        Disconnect(db);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        public static bool GetClientData(string console_key, ref ClientInfo data) {
            using (var db = Setup()) {
                Connect(db);
                using (var command = db.CreateCommand()) {
                    command.CommandText = string.Format("SELECT * FROM users WHERE console_key = @key");
                    command.Parameters.AddWithValue("@key", console_key);
                    using (var reader = command.ExecuteReader()) {
                        if (reader.Read()) {
                            data.iID = reader.GetInt32("id");
                            //data.Username = reader.GetString("username");
                            //data.Password = reader.GetString("password");
                            //data.Email = reader.GetString("email");
                            data.bConsoleLinked = reader.GetBoolean("console_linked");
                            data.bBetaAccess = reader.GetBoolean("beta_access");
                            data.ConsoleKey = reader.GetString("console_key");
                            data.CPUKey = reader.GetString("cpu");
                            data.FirstGamertag = reader.GetString("first_gamertag");
                            data.LastGamertag = reader.GetString("last_gamertag");
                            data.bDevkitCheats = reader.GetBoolean("devkit_cheats");
                            data.iTimeEnd = reader.GetInt32("time_end");
                            data.iTimeBeforeReserve = reader.GetInt32("time_before_reserve");
                            data.iReserveSeconds = reader.GetInt32("reserve_seconds");
                            data.FirstIP = reader.GetString("first_ip");
                            data.LastIP = reader.GetString("last_ip");
                            data.Status = (ClientInfoStatus)reader.GetInt32("status");
                            data.NotifyOnSus = reader.GetString("notify_on_sus");
                            data.FirstKVHash = reader.GetString("first_kv_hash");
                            data.LastKVHash = reader.GetString("last_kv_hash");
                            data.iLastConnection = reader.GetInt32("last_connection");
                            data.iTotalChallenges = reader.GetInt32("total_challenges");
                            data.iLastUsedVersion = reader.GetInt32("last_version");
                            data.bAllowedOnDevkit = reader.GetBoolean("allowed_on_devkit");
                            data.strNoKVHash = reader.GetString("no_kv_hash");
                            data.iNoKVLastRefresh = reader.GetInt32("no_kv_last_refresh");


                            data.Discord = reader.GetString("Discord");
                            data.Discordid = reader.GetString("Discordid");
                            data.Username = reader.GetString("Username");
                            data.email = reader.GetString("Email");
                            data.PrimaryUIColor = reader.GetString("primaryuicolor");
                            data.SecondaryUIColor = reader.GetString("secondaryuicolor");
                            data.QlaunchId = reader.GetString("qtitleid");
                            data.TitleID = reader.GetString("TitleID");
                            Disconnect(db);
                            return true;
                        }
                    }
                }
                Disconnect(db);
            }
            return false;
        }

        public static bool GetClientDataFromID(int ID, ref ClientInfo data) {
            using (var db = Setup()) {
                Connect(db);
                using (var command = db.CreateCommand()) {
                    command.CommandText = string.Format("SELECT * FROM users WHERE `id` = @key");
                    command.Parameters.AddWithValue("@key", ID);
                    using (var reader = command.ExecuteReader()) {
                        if (reader.Read()) {
                            data.iID = reader.GetInt32("id");
                            //data.Username = reader.GetString("username");
                            //data.Password = reader.GetString("password");
                            //data.Email = reader.GetString("email");
                            data.bConsoleLinked = reader.GetBoolean("console_linked");
                            data.bBetaAccess = reader.GetBoolean("beta_access");
                            data.ConsoleKey = reader.GetString("console_key");
                            data.CPUKey = reader.GetString("cpu");
                            data.FirstGamertag = reader.GetString("first_gamertag");
                            data.LastGamertag = reader.GetString("last_gamertag");
                            data.bDevkitCheats = reader.GetBoolean("devkit_cheats");
                            data.iTimeEnd = reader.GetInt32("time_end");
                            data.iTimeBeforeReserve = reader.GetInt32("time_before_reserve");
                            data.iReserveSeconds = reader.GetInt32("reserve_seconds");
                            data.FirstIP = reader.GetString("first_ip");
                            data.LastIP = reader.GetString("last_ip");
                            data.Status = (ClientInfoStatus)reader.GetInt32("status");
                            data.NotifyOnSus = reader.GetString("notify_on_sus");
                            data.FirstKVHash = reader.GetString("first_kv_hash");
                            data.LastKVHash = reader.GetString("last_kv_hash");
                            data.iLastConnection = reader.GetInt32("last_connection");
                            data.iTotalChallenges = reader.GetInt32("total_challenges");
                            data.iLastUsedVersion = reader.GetInt32("last_version");
                            data.bAllowedOnDevkit = reader.GetBoolean("allowed_on_devkit");

                            Disconnect(db);
                            return true;
                        }
                    }
                }
                Disconnect(db);
            }
            return false;
        }

        public static bool GetKVStats(string kvhash, ref KVStats stats) {
            using (var db = Setup()) {
                Connect(db);
                using (var command = db.CreateCommand()) {
                    command.CommandText = string.Format("SELECT * FROM kv_stats WHERE kv_hash = @kv_hash");
                    command.Parameters.AddWithValue("@kv_hash", kvhash);
                    using (var reader = command.ExecuteReader()) {
                        if (reader.Read()) {
                            stats.iID = reader.GetInt32("id");
                            stats.KVHash = reader.GetString("kv_hash");
                            stats.iFirstConnection = reader.GetInt32("first_connection");
                            stats.iLastConnection = reader.GetInt32("last_connection");
                            stats.bBanned = reader.GetBoolean("banned");
                            stats.iBannedTime = reader.GetInt32("banned_time");
                            stats.iTotalChallenges = reader.GetInt32("total_challenges");

                            Disconnect(db);
                            return true;
                        }
                    }
                }
                Disconnect(db);
            }
            return false;
        }

        public static void UpdateKVStat(string kvhash, bool banned) {
            KVStats cur = new KVStats();
            GetKVStats(kvhash, ref cur);

            using (var db = Setup()) {
                Connect(db);
                using (var command = db.CreateCommand()) {
                    command.CommandText = string.Format("UPDATE kv_stats SET last_connection = @last_connection, banned = @banned, banned_time = @banned_time WHERE `kv_hash` = @kv_hash");
                    command.Parameters.AddWithValue("@last_connection", banned ? cur.iLastConnection : Utils.GetTimeStamp());
                    command.Parameters.AddWithValue("@banned", banned);
                    command.Parameters.AddWithValue("@banned_time", banned && !cur.bBanned ? (int)Utils.GetTimeStamp() : cur.iBannedTime);
                    command.Parameters.AddWithValue("@kv_hash", kvhash);
                    command.ExecuteNonQuery();
                }
                Disconnect(db);
            }
        }

        public static void AddKVStat(string kvhash, int firstConnection, int lastConnection, bool banned, int bannedTime) {
            using (var db = Setup()) {
                Connect(db);
                using (var command = db.CreateCommand()) {
                    command.CommandText = string.Format("INSERT INTO kv_stats (kv_hash, first_connection, last_connection, banned, banned_time) VALUES (@kv_hash, @first_connection, @last_connection, @banned, @banned_time)");
                    command.Parameters.AddWithValue("@kv_hash", kvhash);
                    command.Parameters.AddWithValue("@first_connection", firstConnection);
                    command.Parameters.AddWithValue("@last_connection", lastConnection);
                    command.Parameters.AddWithValue("@banned", banned);
                    command.Parameters.AddWithValue("@banned_time", bannedTime);
                    command.ExecuteNonQuery();
                }
                Disconnect(db);
            }
        }

        public static void RemoveRequestToken(string token) {
            using (var db = Setup()) {
                Connect(db);
                using (var command = db.CreateCommand()) {
                    command.CommandText = string.Format("DELETE FROM access_tokens WHERE `token` = @token");
                    command.Parameters.AddWithValue("@token", token);
                    command.ExecuteNonQuery();
                }
                Disconnect(db);
            }
        }

        public static bool DoesRequestTokenExist(string token, string console_key) {
            using (var db = Setup()) {
                Connect(db);
                using (var command = db.CreateCommand()) {
                    command.CommandText = string.Format("SELECT * FROM access_tokens WHERE `token` = @token AND `console_key` = @console_key");
                    command.Parameters.AddWithValue("@token", token);
                    command.Parameters.AddWithValue("@console_key", console_key);
                    using (var reader = command.ExecuteReader()) {
                        if (reader.Read()) {
                            Disconnect(db);
                            return true;
                        }
                    }
                }
                Disconnect(db);
            }
            return false;
        }

        public static void AddRequestToken(string token, string console_key) {
            using (var db = Setup()) {
                Connect(db);
                using (var command = db.CreateCommand()) {
                    command.CommandText = string.Format("INSERT INTO access_tokens (connection_index, `token`, `console_key`, last_connection, welcome_time) VALUES (@connection_index, @token, @console_key, @last, @welcome)");
                    command.Parameters.AddWithValue("@connection_index", 1);
                    command.Parameters.AddWithValue("@token", token);
                    command.Parameters.AddWithValue("@console_key", console_key);
                    command.Parameters.AddWithValue("@last", Utils.GetTimeStamp());
                    command.Parameters.AddWithValue("@welcome", Utils.GetTimeStamp());
                    command.ExecuteNonQuery();
                }
                Disconnect(db);
            }
        }

        public static void UpdateRequestTokenHeartbeat(string token) {
            using (var db = Setup()) {
                Connect(db);
                using (var command = db.CreateCommand()) {
                    command.CommandText = string.Format("UPDATE access_tokens SET last_connection = @last, has_received_presence = @has WHERE `token` = @token");
                    command.Parameters.AddWithValue("@last", Utils.GetTimeStamp());
                    command.Parameters.AddWithValue("@has", 1);
                    command.Parameters.AddWithValue("@token", token);
                    command.ExecuteNonQuery();
                }
                Disconnect(db);
            }
        }

        public static void IncrementRequestTokenChallengeCount(string token) {
            using (var db = Setup()) {
                Connect(db);
                using (var command = db.CreateCommand()) {
                    command.CommandText = string.Format("UPDATE access_tokens SET total_xam_challenges=total_xam_challenges+1 WHERE `token` = @token");
                    command.Parameters.AddWithValue("@token", token);
                    command.ExecuteNonQuery();
                }
                Disconnect(db);
            }
        }

        public static void IncrementRequestTokenConnectionCount(string token) {
            using (var db = Setup()) {
                Connect(db);
                using (var command = db.CreateCommand()) {
                    command.CommandText = string.Format("UPDATE access_tokens SET connection_index=connection_index+1 WHERE `token` = @token");
                    command.Parameters.AddWithValue("@token", token);
                    command.ExecuteNonQuery();
                }
                Disconnect(db);
            }
        }

        public static void IncrementChallengeCount(string console_key) {
            string lastkvhash = "";
            using (var db = Setup()) {
                Connect(db);
                using (var command = db.CreateCommand()) {
                    command.CommandText = string.Format("SELECT * FROM users WHERE `console_key` = @console_key");
                    command.Parameters.AddWithValue("@console_key", console_key);
                    using (var reader = command.ExecuteReader()) {
                        if (reader.Read()) {
                            lastkvhash = reader.GetString("last_kv_hash");
                        }
                    }
                }
                Disconnect(db);
            }

            using (var db = Setup()) {
                Connect(db);
                using (var command = db.CreateCommand()) {
                    command.CommandText = string.Format("UPDATE users SET total_challenges=total_challenges+1 WHERE `console_key` = @console_key");
                    command.Parameters.AddWithValue("@console_key", console_key);
                    command.ExecuteNonQuery();
                }
                Disconnect(db);
            }

            if (lastkvhash.Length > 1) {
                using (var db = Setup()) {
                    Connect(db);
                    using (var command = db.CreateCommand()) {
                        command.CommandText = string.Format("UPDATE kv_stats SET total_challenges=total_challenges+1 WHERE `kv_hash` = @kv_hash");
                        command.Parameters.AddWithValue("@kv_hash", lastkvhash);
                        command.ExecuteNonQuery();
                    }
                    Disconnect(db);
                }
            }
        }

        public static int GetRequestTokenConnectionCount(string token) {
            using (var db = Setup()) {
                Connect(db);
                using (var command = db.CreateCommand()) {
                    command.CommandText = string.Format("SELECT * FROM access_tokens WHERE `token` = @token");
                    command.Parameters.AddWithValue("@token", token);
                    using (var reader = command.ExecuteReader()) {
                        if (reader.Read()) {
                            int count = reader.GetInt32("connection_index");
                            Disconnect(db);
                            return count;
                        }
                    }
                }
                Disconnect(db);
            }

            return 0;
        }

        public static void BanClient(string console_key, string reason) {
            using (var db = Setup()) {
                Connect(db);
                using (var command = db.CreateCommand()) {
                    command.CommandText = string.Format("UPDATE users SET status = @status, notify_on_sus = @reason WHERE `console_key` = @console_key");
                    command.Parameters.AddWithValue("@status", ClientInfoStatus.Disabled);
                    command.Parameters.AddWithValue("@reason", reason);
                    command.Parameters.AddWithValue("@console_key", console_key);
                    command.ExecuteNonQuery();
                }
                Disconnect(db);
            }
        }

        public static void UpdateUserInfoWelcomePacket(string consolekey, string kvhash, string ip) {
            using (var db = Setup()) {
                Connect(db);
                using (var command = db.CreateCommand()) {
                    command.CommandText = string.Format("UPDATE users SET last_kv_hash = @last_kv_hash, last_ip = @last_ip, last_connection = @last_connection WHERE `console_key` = @console_key");
                    command.Parameters.AddWithValue("@last_kv_hash", kvhash);
                    command.Parameters.AddWithValue("@last_ip", ip);
                    command.Parameters.AddWithValue("@console_key", consolekey);
                    command.Parameters.AddWithValue("@last_connection", Utils.GetTimeStamp());
                    command.ExecuteNonQuery();
                }
                Disconnect(db);
            }
        }

        public static void UpdateCurrentOnline(string consolekey, int onlinestatus)
        {
            using (var db = Setup())
            {
                Connect(db);
                using (var command = db.CreateCommand())
                {
                    command.CommandText = string.Format("UPDATE users SET online = @online WHERE `console_key` = @console_key");
                    command.Parameters.AddWithValue("@console_key", consolekey);
                    command.Parameters.AddWithValue("@online", onlinestatus);
                    command.ExecuteNonQuery();
                }
                Disconnect(db);
            }
        }

        public static void UpdateActiveTitle(string consolekey, string title)
        {
            using (var db = Setup())
            {
                Connect(db);
                using (var command = db.CreateCommand())
                {
                    command.CommandText = string.Format("UPDATE users SET TitleID = @title WHERE `console_key` = @console_key");
                    command.Parameters.AddWithValue("@console_key", consolekey);
                    command.Parameters.AddWithValue("@title", title);                  
                    command.ExecuteNonQuery();
                }
                Disconnect(db);
            }
        }

        public static void UpdateTokenActiveTitle(string token, string title) {
            using (var db = Setup()) {
                Connect(db);
                using (var command = db.CreateCommand()) {
                    command.CommandText = string.Format("UPDATE access_tokens SET current_title = @title WHERE `token` = @token");
                    command.Parameters.AddWithValue("@title", title);
                    command.Parameters.AddWithValue("@token", token);
                    command.ExecuteNonQuery();
                }
                Disconnect(db);
            }
        }

        public static void AddUserWelcomePacket(string consolekey, string cpu, string ip, string kvhash) {
            using (var db = Setup()) {
                Connect(db);
                using (var command = db.CreateCommand()) {
                    if (Global.bFreemode) {
                        command.CommandText = string.Format("INSERT INTO users (console_key, cpu, time_before_freemode, first_ip, last_ip, status, first_kv_hash, last_kv_hash) VALUES (@console_key, @cpu, @time_before_freemode, @first_ip, @last_ip, @status, @first_kv_hash, @last_kv_hash)");
                        command.Parameters.AddWithValue("@time_before_freemode", 604800);
                    } else {
                        command.CommandText = string.Format("INSERT INTO users (console_key, cpu, time_end, first_ip, last_ip, status, first_kv_hash, last_kv_hash) VALUES (@console_key, @cpu, @time_end, @first_ip, @last_ip, @status, @first_kv_hash, @last_kv_hash)");
                        command.Parameters.AddWithValue("@time_end", (int)Utils.GetTimeStamp() + 604800);
                    }

                    command.Parameters.AddWithValue("@console_key", consolekey);
                    command.Parameters.AddWithValue("@cpu", cpu);
                    command.Parameters.AddWithValue("@first_ip", ip);
                    command.Parameters.AddWithValue("@last_ip", ip);
                    command.Parameters.AddWithValue("@status", ClientInfoStatus.Authed);
                    command.Parameters.AddWithValue("@first_kv_hash", kvhash);
                    command.Parameters.AddWithValue("@last_kv_hash", kvhash);

                    command.ExecuteNonQuery();
                }
                Disconnect(db);
            }
        }

        public static void UpdateUserReserveTime(ClientInfo info,int newReserve) {

            if (!Global.bFreemode)
            {
                using (var db = Setup())
                {
                    Connect(db);
                    using (var command = db.CreateCommand())
                    {
                        command.CommandText = string.Format("UPDATE users SET reserve_seconds = @reserve_seconds WHERE `console_key` = @console_key");
                        command.Parameters.AddWithValue("@reserve_seconds", newReserve);
                        command.Parameters.AddWithValue("@console_key", info.ConsoleKey);
                        command.ExecuteNonQuery();
                    }
                    Disconnect(db);
                }
            }
        }

        public static void UpdateUserGamertag(ClientInfo info, string gamertag) {
            using (var db = Setup()) {
                Connect(db);
                using (var command = db.CreateCommand()) {
                    if (info.FirstGamertag == "--blankuser--") {
                        command.CommandText = string.Format("UPDATE users SET first_gamertag = @first, last_gamertag = @last_gamertag WHERE `console_key` = @console_key");
                        command.Parameters.AddWithValue("@first", gamertag);
                    } else {
                        command.CommandText = string.Format("UPDATE users SET last_gamertag = @last_gamertag WHERE `console_key` = @console_key");
                    }

                    command.Parameters.AddWithValue("@last_gamertag", gamertag);
                    command.Parameters.AddWithValue("@console_key", info.ConsoleKey);
                    command.ExecuteNonQuery();
                }
                Disconnect(db);
            }
        }

        public static void UpdateUserLastStealthVersion(string consolekey, int newVersion) {
            using (var db = Setup()) {
                Connect(db);
                using (var command = db.CreateCommand()) {
                    command.CommandText = string.Format("UPDATE users SET last_version = @last_version WHERE `console_key` = @console_key");
                    command.Parameters.AddWithValue("@last_version", newVersion);
                    command.Parameters.AddWithValue("@console_key", consolekey);
                    command.ExecuteNonQuery();
                }
                Disconnect(db);
            }
        }

        public static void AddMetric(string consolekey, eMetricType type, eMetrics index, string additionalInfo) {
            using (var db = Setup()) {
                Connect(db);
                using (var command = db.CreateCommand()) {
                    command.CommandText = string.Format("INSERT INTO metrics (console_key, metric_type, metric_index, additional_info, `time`) VALUES (@console_key, @metric_type, @metric_index, @additional_info, @time)");
                    command.Parameters.AddWithValue("@console_key", consolekey);
                    command.Parameters.AddWithValue("@metric_type", type);
                    command.Parameters.AddWithValue("@metric_index", index);
                    command.Parameters.AddWithValue("@additional_info", additionalInfo);
                    command.Parameters.AddWithValue("@time", Utils.GetTimeStamp());

                    command.ExecuteNonQuery();
                }
                Disconnect(db);
            }
        }

        public static List<ClientMetric> GetClientMetrics(string console_key) {
            List<ClientMetric> list = new List<ClientMetric>();
            using (var db = Setup()) {
                Connect(db);
                using (var command = db.CreateCommand()) {
                    command.CommandText = string.Format("SELECT * FROM metrics WHERE console_key = @console_key");
                    command.Parameters.AddWithValue("@console_key", console_key);
                    using (var reader = command.ExecuteReader()) {
                        if (reader.HasRows) {
                            while (reader.Read()) {
                                list.Add(new ClientMetric((eMetricType)reader.GetInt32("metric_type"), (eMetrics)reader.GetInt32("metric_index")));
                            }
                        }
                    }
                }
                Disconnect(db);
            }

            return list;
        }
    }
}