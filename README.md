# xbLive-Listener

Listener for xbLive Stealth Server. SQL db can be found in XbLive-Content https://github.com/silent06/xbLive-Content/tree/main

Dont forget to setup XbLive API challenge listener before using xbLive Listener. https://github.com/silent06/xbLive-Challenge-API


Things I added/fixed:
-B03 Anticheat bypasses works now

-NoKv Server Mode is about 95% completed

-Fixed COD Patches, AntiCheat, & Mod menu(s)

-added KvHandler to add kv info appropriately to sql backend. It will sort out kv.bin's into the kvs folder. 

-added KVChecker to be ran every 24/hr to check if kv's are banned or unbanned. Either use windows Event handler or linux cron job to setup

-added MysqlConfig.ini & Settings.ini to all apps
-added FreemodeHandler to add days while server is in freemode. For some reason freemode time was not allocated into server code. 
-added discord bot with OpenXbl support. See for more into about OpenXbl: https://xbl.io/
-added website, backend Admin panel, backend Client panel. 
-added quicklauncher.php for discordbot. People will be able to launch games & apps from discord. 
-added email support for website. You'll need to setup a local smtp server to use. 

things that need work- 
-minor NoKv issues 
-Rainbow still does some flickering
-xbLiveFuscate 
-xbLive XDK/RGloader support

may work on in the future:
-xbLiveFuscate 
-xbLive XDK/RGloader support
-Achievement Unlocker 
