rule Ransomware_Note_Keywords : ransomware ransom_note
{
    meta:
        confidence = "high"

    strings:
        $a1 = "your files are encrypted" nocase
        $a2 = "how_to_recover" nocase
        $a3 = "README.txt" nocase
        $a4 = "RECOVER" nocase

    condition:
        any of them and filesize < 50KB
}

rule Ransomware_Extensions : ransomware encryption
{
    meta:
        confidence = "high"

    strings:
        $ext1 = ".lockbit" nocase
        $ext2 = ".conti" nocase
        $ext3 = ".play" nocase
        $ext4 = ".akira" nocase
        $ext5 = ".blackcat" nocase
        $ext6 = ".hive" nocase

    condition:
        any of them
}
