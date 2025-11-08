rule ShadowFile{
    meta:
        description = "Checks if the shadow file was accessed"
        author = "Elizabeth Chadbourne"
        date = "2025-11-08"
        version = "1.0"
    strings:
        $Shadow = 'fopen ("/etc/shadow")'
    condition:
        $Shadow
}