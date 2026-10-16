rule PS_command_execution{
    meta:
    description="Detects powershell command with -EX bypass"
    author="MedicWiesel"
    date="14-10-2026"
    reference="https://bazaar.abuse.ch/sample/feddb7d55438986e3fdc46f5422865004cde6d01d23a85c616f4c1c401603dd5"
    strings:
    $s1="powershell" nocase
    $bypass=/-(ep|ex[a-z]{0,14})\s+bypass/ nocase
    condition:
    $s1 and $bypass

}

rule PS_Encoding{
    meta:
        description="Detects powershell command with base64 encoded blob"
        author="MedicWiesel"
        date="14-10-2026"
        reference="https://bazaar.abuse.ch/sample/feddb7d55438986e3fdc46f5422865004cde6d01d23a85c616f4c1c401603dd5"
    strings:
        $ps="powershell"
        $enc=/\s-e(c|n[a-z]{0,12})?\s+([a-zA-Z0-9\/+]){40,}={0,2}/
    condition:
        $ps and $enc

}
rule CMD_with_exp_env_strings{
    meta:
        description="Detects VBScript using comspec and expanded environment strings"
        author="MedicWiesel"
        date="14-10-2026"
        reference="https://bazaar.abuse.ch/sample/feddb7d55438986e3fdc46f5422865004cde6d01d23a85c616f4c1c401603dd5"
    strings:
        $s1="expandenvironmentstrings" nocase
        // comspec
        $rex=/(chrw?\s*\(\s*&?[0-9a-fx]+\s*\)\s*&?\s*){5,}/i
    condition:
        $s1 and $rex
}
rule RemCosRATstager{
    meta:
        description="Detects RemCosRat stager/dropper that uses VBScript"
        author="MedicWiesel"
        date="14-10-2026"
        reference="https://bazaar.abuse.ch/sample/feddb7d55438986e3fdc46f5422865004cde6d01d23a85c616f4c1c401603dd5"
    strings:
    // HTML application check
        $s1="script.shell" nocase
        $s2="<script language=\"VBScript\">" nocase
        $s3="content=\"IE=EmulateIE8\"" nocase
        $s4="<html>"
        $s5="<!DOCTYPE html>"
        // base64 strings for downloading file check
        $b64_url="http://172.245.195.208/24/nice.js" wide base64
        $b64_ip="172.245.195.208" wide base64
        $b64_out="-OutFile" wide base64
    condition:
        filesize<1MB and
        any of ($s3,$s4,$s5) in (0..200) and
        any of ($s1,$s2) and
        (PS_command_execution or PS_Encoding) and
        any of ($b64_url, $b64_ip, $b64_out) and
        CMD_with_exp_env_strings
}
