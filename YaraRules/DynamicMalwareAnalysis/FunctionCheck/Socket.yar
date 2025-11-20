rule NetworkSocket {
    meta:
        description = "Detects the creation of a network socket"
        author = "Elizabeth Chadbourne"
        date = "2025-11-08"
    strings:
        $Socket = "socket"
    condition:
        $Socket
}