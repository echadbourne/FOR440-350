#!/bin/bash
echo "Welcome to Threat Hunting! NOTE: This script requires sudo to function."
while :
do
    echo "What would you like to do?"
    echo "1. Investigate Users"
    echo "2. Investigate Groups"
    echo "3. Investigate Network Connections"
    echo "4. List processes"
    echo "5. List Services"
    echo "0. Exit Program"

    read menuInput
    echo ""
    if [["$menuInput" == "0"]]; then
        echo "Exiting Program..."
        break
    elif [["$menuInput" == "1"]]; then
        echo "Listing all users:"
        grep -v '/nologin\|/false' /etc/passwd | cut -d: -f1
        echo "Checking for users with UID 0"
        awk -F: '$3 == 0 {print $1}' /etc/passwd
        echo "Checking for users with empty passwords"
        sudo awk -F: '($2 == "" || $2 == "!") {print $1}' /etc/shadow
        echo "Remove users with 'sudo userdel -r [username]'"
        echo "Enter a user to show more information. Enter '0' to exit."
        read userMenu
        while [["$userMenu" != "0"]]:
            groups "$userMenu"
            cat /etc/passwd | grep "$userMenu"
            sudo -l -U "$userMenu"
            ps aux | grep "$userMenu"
    elif [["$menuInput" == "2"]]; then
        echo "Listing all groups:"
        cut -d: -f1 /etc/group
        echo "Remove groups with 'sudo groupdel [groupname]'"
        echo "Enter a group name to display members. Enter '0' to exit"
        read groupMenu
        while [["$groupMenu" != "0"]]; 
            getent "$groupMenu"
    elif [["$menuInput" == "3"]]; then
        echo "Lising all active network connections:"
        sudo ss -tulnp
    elif [["$menuInput" == "4"]]; then
        echo "Listing all active processes:"
        ps aux
        echo ""
        echo "Listing suspicious processes:"
        ps aux | grep -E '(bash|ncat|perl)'
        echo ""
        echo "Listing processes running from suspicious locations:"
        ps aux | grep -E '(/tmp|/var/tmp|/dev/shm|/opt)'
        echo ""
        echo "Listing processes with no shell:"
        ps aux | awk '$7 == "?"'
        echo "Remove the file the processes is running from, then 'kill' the process"
    elif [["$menuInput" == "5"]]; then
        echo "Listing all services:"
        systemctl list-unit-files --type=service
    elif [["$menuInput" == "6"]]; then
        echo "Listing root's scheduled jobs:"
        sudo crontab -l
        echo ""
        echo "Listing all user crontabs:"
        for user in $(cut -f1 -d: /etc/passwd); do
            echo "=== Crontab for $user ==="
            sudo crontab -u $user -l 2>/dev/null
        done
    elif [["$menuInput" == "7"]]; then
        echo "Listing file permissions of the /tmp directory"
        ls -la /tmp
        echo ""
        echo "Listing file permissions of the /opt directory"
        ls -la /opt
    elif [["$menuInput" == "8"]]; then
        echo "Listing SUID files:"
        find / -perm -4000 -type f 2>/dev/null
        echo ""
        echo "Listing SGID files:"
        find / -perm -2000 -type f 2>/dev/null
        echo ""
        echo "Listing both SUID and SGID Files:"
        find / -perm /6000 -type f 2>/dev/null
    else
        echo "Please select a valid option
    fi
done