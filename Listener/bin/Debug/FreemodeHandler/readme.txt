Use this while server is in freemode. It will add days to all clients. SQL stores time as unix(seconds) so even if freemode is on
client time will not stop so we have to add time to help counter balance any lost while in freemode. FYI 86400 secs= 1 day.
Also NumberOfClients checks IDs in increment order assuming you dont have things all turned around. 