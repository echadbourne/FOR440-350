rule ExecuteProgram{
    meta:
        description = "Detects a file executing another program"
        author = "Elizabeth Chadbourne"
        date = "2025-11-08"
    strings:
        $Execute = "execve"
    condition:
        $Execute
}