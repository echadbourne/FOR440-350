rule ExecutableEdit {
    meta:
        description = "Detects a file editing another to make it executable"
        author = "Elizabeth Chadbourne"
        date = "2025-11-08"
    strings:
        $chmod = "chmod("
        $executable = "0755"
    condition:
        all of them
}