rule DeleteFile {
    meta:
        description = "Detects the deletion function in a file"
        author = "Elizabeth Chadbourne"
        date = "2025-11-08"
    strings:
        $DeleteFile = "unlink("
    condition:
        $DeleteFile
}