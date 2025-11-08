rule ServiceAcces {
    meta:
        description = "Detects if a file is accessing a service"
        author = "Elizabeth Chadbourne"
        date = "2025-11-08"
    strings:
        $Service = ".service"
    condition:
        $Service
}