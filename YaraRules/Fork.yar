rule Fork{
    meta:
        description = ""
        author = "Elizabeth Chadbourne"
        date = "2025-11-08"
    strings:
        $Fork = "fork("
    condition:
        $Fork
}