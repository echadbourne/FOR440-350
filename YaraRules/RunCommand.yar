rule RunCommand {
    meta:
        description = "Detects a file running a shell command"
        author = "Elizabeth Chadbourne"
        date = "2025-11-08"
    strings:
        $System = "system("
    condition:
        $System
}