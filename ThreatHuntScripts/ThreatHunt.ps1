Do{
Write-Host "`What do you want to check?`n1. Hostname and computer info`n2. User and Group information`
3. Network Information`n4. Processes and Scheduled Tasks`n5. Services `n6. Suspicious Files `n7. Detailed Task Information`
0. Exit"
if ($choice = Read-Host "Please enter your choice, 0-7"){

switch($choice){
    "1"{
        #Get basic computer information
        Write-Host "Hostname:"
        hostname
        Write-Host "Account Security Information:"
        net accounts
        if ($compinfo = Read-Host "Do you want to display extended computer information? (y) or (n)"){
            switch($compinfo){
            "y"{Get-ComputerInfo}
            }} else{ break}
    }
    "2"{
        # Look for suspicious Users
        Write-Host "User accounts on this machine"
        Get-Localuser | Format-Table
        Write-Host "User accounts in Administrators group"
        Get-LocalgroupMember -Group "Administrators" -Erroraction Stop | Select-Object Name | Format-Table
        # Look for suspicious groups, and users in privledged groups
        Write-Host "Groups on host machine"
        Get-Localgroup | Format-Table -wrap
        
    }
    "3"{
        # Checking Open Connections
        netstat -ano
    }
    "4"{
        Write-Host "All Running Processes:"
        Get-Process | Select-Object Id, ProcessName, Path | Format-Table -AutoSize

        Write-Host "Checking For Suspicious Processes"
        Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Select-Object ProcessId, CommandLine | Format-Table -wrap
        Write-Host "Process Check Complete"

        Write-Host "All Scheduled Tasks:"
        Get-ScheduledTask | Format-Table -AutoSize
    }
    "5"{

        Get-Service | Where-Object{$_.Status -eq "Stopped"} | Format-Table
        Get-Service | Where-Object{$_.Status -eq "Running"} | Format-Table
    }
    "6"{
        Write-Host "Displaying content of 'Users\Public' Folder"
        Get-ChildItem -Path C:\Users\Public -Recurse -File
        Write-Host "Displaying content of 'Users\All Users"
        Get-ChildItem -Path "C:\Users\All Users" -File -Hidden
#        Write-Host "Do you want to check for suspicious files with the 'Everyone:(F) Parameter?`
#        This operation can take a long time (This is currently broken)"
#        $confirmation = Read-Host "y or n"
#        switch($confirmation){
#                "y"{
#
#                    icacls "C:\*" /t /c 2>nul | findstr "Everyone:(F)"
#                }
#                "n"{
#                    break
#                }
#        }
    }
    "7"{
        if($Task = Read-Host "What is the task you want to investigate (Please include full task name)?"){
        Write-Host "Displaying Task Creation Time"
        Get-ScheduledTask -TaskName "$Task" | Select-Object Date, Author, Taskname | Format-Table
        Start-Sleep -seconds 3
        Write-Host "Displaying Task Triggers"
        (Get-ScheduledTask -TaskName "$Task" | Select-Object *).Triggers
        start-sleep -seconds 4
        Write-Host "Displaying Task Actions"
        (Get-ScheduledTask -TaskName "$Task" | Select-Object *).Actions
        start-sleep -seconds 2
        Write-Host "Displaying Task Principal"
        (Get-ScheduledTask -TaskName "$Task" | Select-Object *).Principal
        start-sleep -seconds 1
        }
        else{break}
    }
}}#end of if and switch

} until($choice -eq "0")
Write-Host "Exiting Program..."