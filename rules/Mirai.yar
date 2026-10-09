rule Mirai_Variant{
    meta:
        description="detects Mirai Botnet Malware family binary variant"
        author="MedicWiesel"
        date="09-10-2026"
    strings:

        // strings
        $s1="nfinity"
        $s2="The People's"
        $s3="solokey"
        $s4="telecomadmin"
        $s5="admintelecom"
        $s6="admin123"
        $s7="GeNeXiS@19"
        $s8="IPCam@sw"
        $s9="beardropper"
        $s10="t0talc0ntr0l4!"
        $s11="|abcdefghijklmnopqrstuvwxyz0123456789\":,{}[]"
        $s12="rasberrypie"
        $s13="juantech"
        $s14="ipcam_rt5350"
        $s15="oelinux123"

        // busybox commands used
        $busybox1="/bin/busybox hostname PBOC"
        $busybox2="/bin/busybox echo >"
        $busybox3="/bin/busybox wget http://"
        $busybox4="/bin/busybox tftp -g"
        $busybox5="/bin/busybox ftpget"
        $busybox6="/bin/busybox chmod +x .d; ./.d; ./dvrHelper selfrep"

        // request headers
        $req1="GET /dlr"
        $req2="GET /api/v1/status HTTP/1.1"
        $req3="Host: api.svc.local"
        $req4="Accept: */*"
        $req5="POST /api/sync HTTP/1.1"
        $req6="GET /b2 HTTP/1.0"

        $j1="{\"status\":\"ok\""
        $j2="{\"status\":\"ok\",\"code\":200,\"data\":{\"id\":"
        // killer script
        $hex1="\\x23\\x21\\x2F\\x62\\x69\\x6E\\x2F\\x73\\x68\\x0A\\x0A\\x66\\x6F\\x72\\x20\\x70\\x72\\x6F\\x63\\x5F\\x64\\x69\\x72\\x20\\x69\\x6E\\x20\\x2F\\x70\\x72\\x6F\\x63"
        $hex2="\\x2F\\x2A\\x3B\\x20\\x64\\x6F\\x0A\\x20\\x20\\x20\\x20\\x70\\x69\\x64\\x3D\\x24\\x7B\\x70\\x72\\x6F\\x63\\x5F\\x64\\x69\\x72\\x23\\x23\\x2A\\x2F\\x7D\\x0A\\x0A"
        $hex3="\\x20\\x20\\x20\\x20\\x72\\x65\\x73\\x75\\x6C\\x74\\x3D\\x24\\x28\\x6C\\x73\\x20\\x2D\\x6C\\x20\\x22\\x2F\\x70\\x72\\x6F\\x63\\x2F\\x24\\x70\\x69\\x64\\x2F\\x65"
        $hex4="\\x78\\x65\\x22\\x20\\x32\\x3E\\x20\\x2F\\x64\\x65\\x76\\x2F\\x6E\\x75\\x6C\\x6C\\x29\\x0A\\x0A\\x20\\x20\\x20\\x20\\x69\\x66\\x20\\x5B\\x20\\x22\\x24\\x72\\x65"
        $hex5="\\x73\\x75\\x6C\\x74\\x22\\x20\\x21\\x3D\\x20\\x22\\x24\\x7B\\x72\\x65\\x73\\x75\\x6C\\x74\\x25\\x28\\x64\\x65\\x6C\\x65\\x74\\x65\\x64\\x29\\x7D\\x22\\x20\\x5D"
        $hex6="\\x3B\\x20\\x74\\x68\\x65\\x6E\\x0A\\x20\\x20\\x20\\x20\\x20\\x20\\x20\\x20\\x6B\\x69\\x6C\\x6C\\x20\\x2D\\x39\\x20\\x22\\x24\\x70\\x69\\x64\\x22\\x0A\\x20\\x20"
        $hex7="\\x20\\x20\\x66\\x69\\x0A\\x64\\x6F\\x6E\\x65\\x0A"

    condition:
        uint32be(0)==0x7F454C46 and
        filesize <=300KB and
        4 of ($busybox*) and
        10 of ($s*) and
        7 of ($req*, $hex*, $j*)
}
