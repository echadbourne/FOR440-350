rule FileOpenModify{
    meta:
        description = "Checks for file creation or modification commands such as mkdir or chmod"
        author = "Elizabeth Chadbourne"
        date = "2025-11-08"
    strings:
        $chmod = "chmod"
        $mkdir = "mkdir"
        $fopen = "fopen"
    condition:
        one of them
}