text2pcap.exe -l 105 -F pcapng `
    "hexdump_with_offsets.txt" `
    "output.pcapng"
Write-Host use: hashcat.exe --backend-ignore-cuda -m 22000 -w1 -a 0 ".\handshake.hc22000" wordlist.txt ^
Write-Host      -r rules.rule ^
Write-Host      --hwmon-temp-abort=87 --status --status-timer=30 --session=wpa2handshake

Write-Host      show password: hashcat.exe -m 22000 --show ".\handshake.hc22000"
Write-Host      resume: hashcat --session wpa2handshake --restore
Read-Host -Prompt "Press any key to continue..."