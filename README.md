# MegaSync
Syncs a mega folder with a local folder, no account required. 

In this project are the original notebook file, the compiled .py, and the distribution .exe that is created from pyinstaller with a config file.

# How To Use
To get started this using browser to the dist folder and downloaded the megasync.exe and the config.ini. Save these both in the same folder, but replace the mega url and directory with whatever you use locally. You should really make a backup of your directory before testing this out because if configured wrong it will create the mega file structure inside of whatever folder you specify and create a big mess.

Once configured, just run the .exe and you can view the logs from each download. There are currently known issues that can occur with threading, but you can mitigate this by turning threading off. This is off by default in anticipation of issues. I have found it to be faster at times, but buggier with larger files.

#Setting Up Config.ini
localSyncBaseFolder = yourfolder 

megaURL = yourmegaurl

betaThreading = False

localSyncBaseFolder = D:/Sync

megaURL = https://mega.nz/folder/gp12RQaK#SeztTrf6H3cUuJPWZEbuKQ

betaThreading = False


## For Advanced Users
For those who want to build them themselves into an .exe you can do so using pyinstaller with the following command and referenced modules installed.

pyinstaller --onefile megasync.py
