# Computer-security
Implement some common attacks
## DNS reflection attack and DNS amplification attack
(Given DNS server's IP and victim's IP)
- (Attacker)Fabricates a DNS query message with a UDP packet
- (Victim)Use wireshark to check the victim receive DNS response

Q: How to create IP Spoofing Packets?
A: Using Raw sockets


----------------------------------------------------------------------------
## Worm Attack
- pornhub:this is the attack module name(payload:may cause flooding attack)
- runetcc:this Shell Script is used to write the schedule to victim's crontab (this file shoud be placed at attack's local)
- sshlogin:remote control victim's pc.

### The worm attack method: 
   - Create two hidden directories and put attack's module in directory
   - First time ssh login to victim:we need to know the victim's username and its password
   - sshlogin(Shell Script) will send attacker's public key to victim's authorized key list,so even if victim change their password we still can login
   - When victim's find he is attacked by attacker they may change his password and delete two hidden directories.
   - However,we have already write schedule in victim's crontab and trigger automatically every 1 minute(we assume victim will not find their contab schedule),so the attack will still continue.
   
Q: How to remove worm attack?
A: useful management tool:htop / time-based job scheduler:cron
A: Remove two hidden directories and check /etc/crontab
