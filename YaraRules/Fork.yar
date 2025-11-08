rule Fork{
    meta:
        description = "Detects a file creating a process"
        author = "Elizabeth Chadbourne"
        date = "2025-11-08"
    strings:
        $Fork = "fork("
    condition:
        $Fork
}