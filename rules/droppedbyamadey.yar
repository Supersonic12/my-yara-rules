import "pe"

rule unpackedVersion{
    meta:
      description = "a RAT dropped by Amadey Infostealer malware(after unpack)"
      author="MedicWiesel"
    strings:
    // absolutes
      $webhook="https://discord.com/api/webhooks/1558004281972367461"
      $c2="ws://31.77.148.141:1338/ws"
    // might be
      $file1="%sstx_%08lx.dll"
      $file2="%sscx_%08lx.dll"
      $hex1="%08lx%08lx%04lx"
      $hex2="xm_%08lx%04lx%s"
      $file3="%sdx_%08lx.ps1"
      // Stresser calls.
      $e1="StresserInit"
      $e2="StresserStart"
      $e3="StresserStop"
      // Jsons
      $json1="{\"content\":\"%.1800s\"}"
      $json2="{\"type\":\"hello\",\"id\":\"%s\",\"user\":\"%s\",\"os\":\"%s\",\"ownerId\":%d}"
      $json3="{\"type\":\"progress\",\"op\":\"%s\",\"pct\":%d,\"note\":\"%s\"}"
      $json4="{\"type\":\"result\",\"reqId\":\"%s\",\"ok\":%d,\"data\":\"%s\"}"
      $json5="{\"type\":\"frame\",\"jpg\":\"%s\"}"
      $pong="{\"type\":\"pong\"}"

      $mutex1= "Global\\Xmd98004fa9380" wide
      $mutex_prefix= "Global\\Xmd" wide 
    condition:
      uint16(0) == 0x5A4D and filesize < 2MB and 
      (
        // Direct config search
        any of ($webhook,$c2) and 4 of ($json*, $file*, $e*,$pong,$hex*) or 
        (
          // Forged Data and mutex name search
          pe.version_info["OriginalFilename"] == "audiodg.exe" and 
          pe.version_info["CompanyName"] == "Adobe Systems" and 
          pe.version_info["LegalCopyright"] == "Copyright (C) 2022 Intel Corporation" and 
          any of ($mutex*)
        ) or
        // Family search
        8 of ($json*, $file*, $e*, $pong, $hex*)
      )
}
