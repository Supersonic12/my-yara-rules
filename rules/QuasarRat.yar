rule QuasarRAT_variant{
    meta:
        description="detects QuasarRat derived .NET rats"
        author="MedicWiesel"
        date="11-10-2026"
        reference="https://bazaar.abuse.ch/sample/0fdf8b638918ac7a04c36e6ea150548dcd245caa8674601c8a9d5905e77f9bc3/"
    strings:
        $s1="Quasar" ascii wide
        $s2="BouncyCastle" nocase ascii wide
        $s3="ProtoBuf" nocase ascii wide
        $s4="MaxXor" nocase ascii wide

        $useragent1="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A" ascii wide
        $useragent2="Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:76.0) Gecko/20100101 Firefox/76.0" ascii wide

        $domain1="https://ipwho.is/" ascii wide
        $domain2="https://api.ipify.org/" ascii wide

        $mscore="mscoree.dll"

        $persistencereg1="LocalMachineRun" ascii wide nocase
        $persistencereg2="Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $persistencereg3="SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase

        $persistenceschtask1="schtasks" ascii wide
        $persistenceschtask2="/create /tn" ascii wide
        $persistenceschtask3="/sc ONLOGON /tr" ascii wide
        $persistenceschtask4="/rl HIGHEST /f" ascii wide
        $persistenceschtask5="/delete /tn" ascii wide
        $impersonation1="runas" ascii wide
        $impersonation2="/k START \"\" \"" ascii wide

        $batler1="chcp 65001" ascii wide
        $batler2="echo DONT CLOSE THIS WINDOW!" ascii wide
        $batler3="ping -n 10 localhost > nul" ascii wide
        $batler4="del /a /q /f \"" ascii wide
        $batler5="move /y \"" ascii wide
        $batler6="start \"\" \"" ascii wide

        $query1="SELECT * FROM Win32_BIOS" ascii wide nocase
        $query2="SELECT * FROM Win32_BaseBoard" ascii wide nocase
        $query3="SELECT * FROM Win32_Processor" ascii wide nocase
        $query4="Select * From Win32_ComputerSystem" ascii wide nocase
        $query5="SELECT * FROM Win32_DisplayConfiguration" ascii wide nocase
        $query6="SELECT * FROM Win32_OperatingSystem WHERE Primary='true'" ascii wide nocase
        $query7="SELECT * FROM AntivirusProduct" ascii wide nocase
        $query8="SELECT * FROM FirewallProduct" ascii wide nocase
        $query9="SELECT Caption FROM Win32_OperatingSystem" ascii wide nocase

        $rexstr1="(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})" ascii wide
        $rexstr2="^\\d{4}\\-(0[1-9]|1[012])\\-(0[1-9]|[12][0-9]|3[01])$" ascii wide

    condition:
        uint16be(0)==0x4D5A and
        filesize < 10MB and
        $mscore and
        (
            ($s1 or $s4) and 2 of ($s*) or
            (
                (
                    4 of ($batler*) and
                    5 of ($query*)
                ) and
                (
                    any of ($domain*) or
                    any of ($useragent*) or
                    any of ($rexstr*) or
                    (
                        (
                            all of ($persistencereg*) and
                            (
                                4 of ($persistenceschtask*) or
                                any of ($impersonation*)
                            )
                        )
                    )
                )
            )
        )
}
