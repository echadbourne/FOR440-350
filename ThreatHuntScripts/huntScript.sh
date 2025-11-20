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
    echo "6. List Scheduled Jobs"
    echo "7. Investigate File Permissions"
    echo "8. Check Bash History"
    echo "9. List contents of common suspicious file locations"
    echo "0. Exit Program"

    read menuInput
    echo "You selected $menuInput"
    echo ""
    if [[ "$menuInput" == "0" ]]; then
        echo "Exiting Program..."
        break
    elif [[ "$menuInput" == "1" ]]; then
        echo "==Listing all users=="
        grep -v '/nologin\|/false' /etc/passwd | cut -d: -f1
        echo "==Users with UID 0=="
        awk -F: '$3 == 0 {print $1}' /etc/passwd
        echo "==Users with empty passwords=="
        sudo awk -F: '($2 == "" || $2 == "!") {print $1}' /etc/shadow
        echo "Enter a user to show more information. Enter '0' to exit."
        read userMenu
        while [[ "$userMenu" != "0" ]]; do
            echo "==Groups=="
            groups "$userMenu"
            echo "==More Information=="
            cat /etc/passwd | grep "$userMenu"
            echo "==Sudo Permissions=="
            sudo -l -U "$userMenu"
            echo "==Open Processes=="
            ps aux | grep "$userMenu"
            echo "Enter a user to show more information. Enter '0' to exit."
            read userMenu
            done
        echo "Remove users with 'sudo userdel -r [username]'"
    elif [[ "$menuInput" == "2" ]]; then
        echo "Listing all groups:"
        cut -d: -f1 /etc/group
        echo "Enter a group name to display members. Enter '0' to exit"
        read groupMenu
        while [[ "$groupMenu" != "0" ]]; do
            echo "==Members of group $groupMenu=="
            getent group "$groupMenu"
            echo "Enter a group name to display members. Enter '0' to exit"
            read groupMenu
            done
        echo "Remove groups with 'sudo groupdel [groupname]'"
    elif [[ "$menuInput" == "3" ]]; then
        echo "Lising all active network connections:"
        sudo ss -tulnp
    elif [[ "$menuInput" == "4" ]]; then
        echo "Listing all active processes:"
        ps aux
        echo "Please select what to investigate:"
        echo "1. Suspicious processes"
        echo "2. Processes from suspicious locations"
        echo "3. Processes with no shell"
        echo "4. Recently started processes"
        echo "5. Long Running processes"
        echo "0. Exit"
        read processMenu
        while [[ "$processMenu" != "0" ]]; do
            if [[ "$processMenu" == "1" ]]; then
                echo "Listing suspicious processes:"
                ps aux | grep -E '(bash|ncat|perl)'
                echo ""
            elif [[ "$processMenu" == "2" ]]; then
                echo "Listing processes running from suspicious locations:"
                ps aux | grep -E '(/tmp|/var/tmp|/dev/shm|/opt)'
                echo ""
            elif [[ "$processMenu" == "3" ]]; then
                echo "Listing processes with no shell:"
                ps aux | awk '$7 == "?"'
            elif [[ "$processMenu" == "4" ]]; then
                ps -eo pid,etime,cmd, --sort=start_time | head -20
            elif [[ "$processMenu" == "5" ]]; then
                ps -eo pid,etime,cmd | grep bash
            fi
            echo "Please select what to investigate:"
            echo "1. Suspicious processes"
            echo "2. Processes from suspicious locations"
            echo "3. Processes with no shell"
            echo "4. Recently started processes"
            echo "5. Long Running processes"
            echo "0. Exit"
            read processMenu
            done
        echo ""
        echo "For removal: Remove the file the processes is running from, then 'kill' the process"
    elif [[ "$menuInput" == "5" ]]; then
        echo "Listing all services:"
        systemctl list-unit-files --type=service
        echo "Enter a service to investigate, enter '0' to exit"
        read serviceMenu
        while [[ "$serviceMenu" != "0" ]]; do
            echo "==Status=="
            systemctl status $serviceMenu
            echo "==Content=="
            systemctl cat $serviceMenu
            echo "==Dependencies=="
            systemctl list-dependencies $serviceMenu
            echo "Enter a service to investigate, enter '0' to exit"
            read serviceMenu
            done
    elif [[ "$menuInput" == "6" ]]; then
        echo "Listing all user crontabs:"
        for user in $(cut -f1 -d: /etc/passwd); do
            echo "==Crontab for $user=="
            sudo crontab -u $user -l 2>/dev/null
            echo ""
        done
    elif [[ "$menuInput" == "7" ]]; then
        echo "Listing file permissions of the /tmp directory"
        ls -la /tmp
        echo ""
        echo "Listing file permissions of the /opt directory"
        ls -la /opt
        echo "Listing files with 777 permissions"
        sudo find / -type f -perm 0777 2>/dev/null
        echo ""
        echo "==Listing SUID files=="
        find / -perm -4000 -type f 2>/dev/null
        echo ""
        echo "==Listing SGID files=="
        find / -perm -2000 -type f 2>/dev/null
        echo ""
        #echo "Listing both SUID and SGID Files:"
        #find / -perm /6000 -type f 2>/dev/null
    elif [[ "$menuInput" == "8" ]]; then
        echo "==History for root=="
        sudo cat /root/.bash_history
        echo ""
        for user_home in /home/*; do
            echo "==History for $(basename $user_home)=="
            cat "$user_home/.bash_history"
            echo ""
        done
    elif [[ "$menuInput" == "9" ]]; then
        echo "==Contents of /tmp=="
        ls -la /tmp
        echo ""
        echo "==Contents of /var/tmp=="
        ls -la /var/tmp
        echo ""
        echo "==Contents of /opt=="
        ls -la /opt
        echo ""
        echo "==Contents of /dev/shm=="
        ls -la /dev/shm
        echo ""
        echo "Please enter a user you would like to view the contents of the /home directory for, or exit with '0'"
        read contentMenu
        while [[ "$contentMenu" != "0" ]]; do
            echo "==Contents of /home/$contentMenu=="
            ls -la /home/$contentMenu
            echo ""
            echo "Please enter a user you would like to view the contents of the /home directory for, or exit with '0'"
            read contentMenu
        done

    else
        echo "Please select a valid option"
    fi
done