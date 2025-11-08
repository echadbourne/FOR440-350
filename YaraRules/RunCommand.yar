rule RunCommand {
    meta:
        description = ""
        author = "Elizabeth Chadbourne"
        date = "2025-11-08"
    strings:
        $System = "system("
    condition:
        $System
}