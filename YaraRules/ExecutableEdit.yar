rule ExecutableEdit {
    meta:
        description = ""
        author = "Elizabeth Chadbourne"
        date = "2025-11-08"
    strings:
        $chmod = "chmod("
        $executable = "0755"
    condition:
        all of them
}