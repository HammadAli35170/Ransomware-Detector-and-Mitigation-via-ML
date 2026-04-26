rule Obfuscated_PowerShell : script obfuscation ransomware
{
    meta:
        confidence = "high"

    strings:
        $ref = "System.Management.Automation"
        $s1 = "FromBase64String" ascii
        $s2 = "Invoke-Expression" ascii nocase
        $s3 = "IEX (" ascii
        $s4 = "^" wide
        $s5 = " -join" wide

    condition:
        $ref and 2 of ($s*)
}

rule Suspicious_VBS_JScript : script obfuscation
{
    meta:
        confidence = "medium"

    strings:
        $a = "CreateObject(" ascii
        $b = "WScript.Shell" ascii
        $c = "ExecuteGlobal" ascii
        $d = "eval(" ascii

    condition:
        2 of them
}
