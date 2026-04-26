rule Office_Macro_Dropper : office malware initial_access
{
    meta:
        confidence = "high"

    strings:
        $a = "AutoOpen" ascii
        $b = "Document_Open" ascii
        $c = "Workbook_Open" ascii
        $d = "Shell(" ascii
        $e = "WScript.Shell" ascii
        $f = "powershell" ascii nocase

    condition:
        uint32(0) == 0xd0cf11e0 and 2 of them
}

rule Office_DDE_Exploit : office malware initial_access
{
    meta:
        confidence = "medium"

    strings:
        $dde = "DDE" ascii
        $cmd = "cmd.exe" ascii
        $cpl = "control.exe" ascii

    condition:
        $dde and ($cmd or $cpl)
}
