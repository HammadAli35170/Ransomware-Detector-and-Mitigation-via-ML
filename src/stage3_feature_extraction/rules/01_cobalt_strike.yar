rule CobaltStrike_Beacon_4_7_to_4_9 : malware c2 cobaltstrike
{
    meta:
        author = "EliteBlueTeam 2025"
        description = "Cobalt Strike 4.7–4.9 reflective loader + config"
        confidence = "high"

    strings:
        $mz = { 4D 5A }
        $s1 = "ReflectiveLoader" ascii
        $s2 = "%s as %s\\%s" ascii
        $s3 = "www6.config" ascii
        $s4 = "post-ex" ascii
        $config1 = /http[s]?:\/\/[a-z0-9.-]{10,80}\/[a-z]{2,8}/
        $config2 = { 69 00 00 00 ?? ?? ?? ?? 6B 00 00 00 }

    condition:
        $mz at 0 and (2 of ($s*)) or $config1 or $config2
}

rule CobaltStrike_NamedPipe : malware c2 cobaltstrike
{
    meta:
        description = "Cobalt Strike named pipe communication"
        confidence = "medium"

    strings:
        $pipe1 = "\\pipe\\msagent_" ascii
        $pipe2 = "\\pipe\\status_" ascii
        $pipe3 = "\\pipe\\postex_" ascii

    condition:
        any of them
}
