rule UPX_Packed : packer obfuscation
{
    meta:
        confidence = "low"

    strings:
        $upx1 = "UPX!" ascii
        $upx2 = "This file was packed with the UPX executable packer" ascii

    condition:
        any of them
}

rule VMProtect : packer obfuscation
{
    meta:
        confidence = "medium"

    strings:
        $a = "VMProtect" fullword
        $b = "VmpExec" ascii

    condition:
        any of them
}
