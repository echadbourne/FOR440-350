rule ReconnaissanceCheck {
    meta:
        description = "Checks for common reconnaissance methods"
        author = "Elizabeth Chadbourne"
        date = "2025-11-08"
    strings:
        $hostname = "gethostname"
        $passwdacces = "/etc/passwd"
        $shadowaccess = "/ect/shadow"
        $processdiscovery = "ps aux"
    condition:
        one of them
}