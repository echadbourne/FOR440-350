rule DeleteFile {
    meta:
        description = ""
        author = "Elizabeth Chadbourne"
        date = "2025-11-08"
    strings:
        $DeleteFile = "unlink("
    condition:
        $DeleteFile
}