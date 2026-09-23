# Decentralized-RMM
An open soruced decentralized RMM solution. Contributers wanted, we're just getting started!

I plan to write most of the code base in c# as I don't have time to learn multiple languages and this seemed a good starting point.

The overall goal of this program is to write a fully decentralized RMM solution that supports windows mac and linux however until code base is working it'll probably be limited to just windows.

Current phase, get a decentralized database working.  I'm going to use rqlite because most of the work is already done. and rhinodht looks promising for node discovery.  I'm open to better solutions as I'm very new to this level of programming, never done more than simple bash scripts.

Next phase is the windows agent. The agent will monitor it's local database for commands to execute via powershell/wmi/command prompt and insert answers into database which is then synced back to command console which will be a native app, no web apps here.


Additional tools to consider.  https://ipfs.io  stability not yet known but only one way to find out,  if it works it can probably handle the job of rqlite and rhinodht far more effectively.
