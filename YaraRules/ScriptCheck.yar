rule ScriptCheck {
    meta:
        description = "Checks if a file is interacting with a script"
        author = "Elizabeth Chadbourne"
        date = "2025-11-08"
    strings:
        $script = ".sh"
    condition:
        $script
}