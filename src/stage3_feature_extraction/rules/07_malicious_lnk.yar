rule Malicious_LNK : lnk malware initial_access
{
    meta:
        confidence = "high"

    strings:
        $lnk = { 4C 00 00 00 01 14 02 00 }
        $cmd = "cmd.exe" wide nocase
        $ps = "powershell.exe" wide nocase
        $remote1 = "http://" ascii
        $remote2 = "https://" ascii

    condition:
        $lnk at 0 and ($cmd or $ps) and any of ($remote*)
}
