rule ExecuteProgram{
    meta:
        description = ""
        author = "Elizabeth Chadbourne"
        date = "2025-11-08"
    strings:
        $Execute = "execve("
    condition:
        $Execute
}