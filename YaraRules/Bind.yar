rule BindPort {
    meta:
        description = ""
        author = "Elizabeth Chadbourne"
        date = "2025-11-08"
    strings:
        $Bind = "bind("
    condition:
        $Bind
}