/*
 * EICAR antivirus test file — a harmless, industry-standard test pattern that
 * every antivirus is expected to detect. Shipped so the local YARA path can be
 * verified fully offline (no network, no real malware).
 */

rule EICAR_Test_File
{
    meta:
        description = "EICAR antivirus test file (harmless test pattern)"
        reference   = "https://www.eicar.org/download-anti-malware-testfile/"
        severity    = "test"

    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    condition:
        $eicar
}
