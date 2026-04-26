rule LOLBAS_CertUtil_Decode : lolbas suspicious
{
    meta:
        confidence = "medium"

    strings:
        $cmd = "certutil.exe" wide nocase
        $arg1 = "-decode" wide
        $arg2 = "-f" wide

    condition:
        $cmd and 1 of ($arg*)
}

rule LOLBAS_Bitsadmin_Download : lolbas suspicious
{
    meta:
        confidence = "medium"

    strings:
        $a = "bitsadmin" wide nocase
        $b = "/transfer" wide
        $c = "/download" wide

    condition:
        $a and ($b or $c)
}

rule LOLBAS_Rundll32_JavaScript : lolbas suspicious
{
    meta:
        confidence = "high"

    strings:
        $a = "rundll32.exe" wide nocase
        $b = "javascript:" wide nocase

    condition:
        $a and $b
}
