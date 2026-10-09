rule RemusStealer_Variant{
    meta:
    // this detection should have gazillions of false positives. So I wouldn't count on it'
        description="detects Remus Stealer on the basis of go build."
        author="MedicWiesel"
        date="09-10-2026"
    strings:
        $go_build_id="Go build ID:"
        // pe headers specific to go build
        $peheader1=".xdata"
        $peheader2=".pdata"
        $peheader3=".symtab"
        // cert authority
        $compName="DigiCert Inc"
        $compDomain="www.digicert.com"
        $comptrusted1="DigiCert Assured ID Root CA0"
        $comptrusted2="DigiCert Trusted Root G40"
        $url1="http://cacerts.digicert.com/DigiCertAssuredIDRootCA.cr"
        $url2="http://cacerts.digicert.com/DigiCertTrustedRootG4.cr"
        $url3="http://crl3.digicert.com/DigiCertTrustedRootG4.cr"
        $timestamping1="DigiCert Trusted G4 TimeStamping RSA4096 SHA256 2025 CA10"
        $timestamping2="DigiCert, Inc.1"
        // frostelement
        $frost="Frost Element"
        // domains
        $domain1="trenthamsrealty.com"
        $domain2="cyonex.sbs"
        $domain3="cfcher.biz"

    condition:
        uint16(0)==0x4D5A and filesize <= 10MB and
        all of ($go_build_id,$peheader*) and
        $frost
        5 of ($comp*,$url*,$timestamping*) or
        3 of ($domain*)
}
