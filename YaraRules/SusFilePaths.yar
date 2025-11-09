rule FilePath {
    meta:
        description = "Detects file accessing suspicious directories"
        author = "Elizabeth Chadbourne"
        date = "2025-11-08"
    strings:
        $Temp1 = "/tmp"
        $Temp2 = "/var/tmp"
        $Dev = "/dev/shm"
    condition:
        any of them
}