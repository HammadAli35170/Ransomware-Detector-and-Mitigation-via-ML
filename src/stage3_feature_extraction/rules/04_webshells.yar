rule ASPX_Webshell : webshell malware
{
    meta:
        confidence = "high"

    strings:
        $eval = "<%@ " ascii
        $exec1 = "Process.Start" ascii
        $exec2 = "eval(" ascii nocase
        $exec3 = "Request.Item[" ascii

    condition:
        $eval and 1 of ($exec*)
}

rule PHP_Webshell : webshell malware
{
    meta:
        confidence = "high"

    strings:
        $a = "eval("
        $b = "gzinflate("
        $c = "base64_decode("
        $d = "passthru("
        $e = "shell_exec("
        $f = "system("

    condition:
        uint32(0) == 0x3f68703c and 2 of them
}
