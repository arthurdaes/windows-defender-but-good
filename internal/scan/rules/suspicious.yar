/*
 * Minimal illustrative starter rules — NOT comprehensive coverage. For real
 * protection, drop community rulesets into your user rules directory
 * (%APPDATA%\Windows Defender but Good\rules\); they are compiled alongside these:
 *   - YARA-Forge:        https://yarahq.github.io/
 *   - Neo23x0/signature-base: https://github.com/Neo23x0/signature-base
 */

rule Suspicious_Packer_Section_Names
{
    meta:
        description = "Common runtime-packer section names (UPX/ASPack/etc.)"
        severity    = "suspicious"

    strings:
        $upx0    = "UPX0"
        $upx1    = "UPX1"
        $aspack  = ".aspack"
        $nsp     = ".nsp0"
        $themida = ".themida"

    condition:
        uint16(0) == 0x5A4D and any of them
}
