rule ScheduledTasks {
    meta:
        description = "Checks for access to the scheduled task folder"
        author = "Elizabeth Chadbourne"
        date = "2025-11-08"
    strings:
        $crontab = "/etc/cron"
    condition:
        $crontab
}