rule BindPort {
    meta:
        description = "Detects use of the 'bind' function"
        author = "Elizabeth Chadbourne"
        date = "2025-11-08"
    strings:
        $Bind = "bind("
    condition:
        $Bind
}