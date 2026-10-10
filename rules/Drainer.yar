rule Drainer_Variant_forMemory{
    meta:
        description="Detects worm/money stealer/clipboard injector python malware"
        author="MedicWiesel"
        date="10-10-2026"
    strings:
        $s1="WScript.Shell"
        $s2="\\system32\\z \\cmd.exe"
        $s3="%comspec% /c"
        $s4="BTCWallet"
        $s5="Error find_server_ip"
        $s6="root\\cimv2"
        $s7="attrib +r +h +s"
        $s8="Task Manager has been disabled by your administrator"
        $s9="taskmgr.exe"
        $s10="[Disable] task manager"
        $s11="disable_taskmgr"


        $wbemquery1="SELECT * FROM Win32_DiskDrive WHERE InterfaceType = \"USB\""
        $wbemquery2="SELECT * from Win32_DiskDriveToDiskPartition"
        $wbemquery3="SELECT * from Win32_LogicalDiskToPartition"
        $wbemquery4="SELECT * from Win32_LogicalDisk WHERE DeviceID="

        $autorun1="[autorun]"
        $autorun2="open="
        $autorun3="icon="
        $autorun4="label=click to Open"
        $autorun5="[Content]"
        $autorun6="MusicFiles=false"
        $autorun7="PictureFiles=false"
        $autorun8="VideoFiles=false"

        $wmicall1="Set objWshShl = WScript.CreateObject(\"WScript.Shell\")"
        $wmicall2="Set objWMIService = GetObject(\"winmgmts:\" & \"{impersonationLevel=impersonate}!//./root/cimv2\")"
        $wmicall3="Set colMonitoredProcesses = objWMIService.ExecNotificationQuery(\"select * from __instancecreationevent \" & \" within 1 where TargetInstance isa 'Win32_Process'\")"
        $wmicall4="Set objLatestProcess = colMonitoredProcesses.NextEvent"
        $wmicall5="If LCase(objLatestProcess.TargetInstance.Name) = \""
        $wmicall6="objLatestProcess.TargetInstance.Terminate"


        $rexstring="#0bw0#(.+?)#0bw0#"

        $fernetkey="-zlOqEUi2itii1JoKHl-TqupkDZfhLpRjWsI0xRuGrg="

        $mutex="PA_mutex_xp4"
        /*
         * This are left in sample vlog.
         * But competent attacker can remove them.
        $vlog1="before detectSandboxie"
        $vlog2="after detectSandboxie"
        $vlog3="after detectVM and before encryptBlg"
        $vlog4="before BTCWalletInject():"
        $vlog5="win32clipboard.GetClipboardData()"
        $vlog6="win32clipboard.CloseClipboard()"
        $vlog7="win32clipboard.OpenClipboard()"
        $vlog8="win32clipboard.EmptyClipboard()"
        $vlog9="win32clipboard.SetClipboardText(MyWallet)"
        $vlog10="disconnect (BTC Wallet Inject break"
        $vlog11="after BTCWalletInject():"
        */
        $checksandbox1="SbieDll.dll"
        $checksandbox2="Select * from Win32_DiskDrive"
        $checksandbox3="vbox"
        $checksandbox4="virtual"

        $regkey1="Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $regkey2="winupdate"

        $domain1="https://www.google.com/"
        $domain2="http://wallpaperaccess.ir/access.txt"
        $domainRex1=/\.blogfa\.com/
        $domainRex2=/\.blogsky\.com/
        $domainRex3=/\.takblog\.net\/rss.xml/
        $domainRex4=/\.photoblog\.com/
        $domainRex5=/\.creerunblog\.fr/
        $domainRex6=/\.samenblog\.com/
        $domainRex7=/\.niloblog\.com/
        $domainRex8=/\.loxblog\.com/
        $domainRex9=/\.niniweblog\.com/
        $domainRex10=/\.parsiblog\.com/
        $domainRex11=/\.persianblog\.ir/
        $domainRex12=/\.weebly\.com/
        $domainRex13=/\.wordpress\.com/
        $domainRex14=/\.blogger\.com/
        $mainDomain=/http:\/\/[a-z0-9]{8}\.[a-zA-Z0-9/]{,20}\.[a-z]{,4}/
    condition:
        // first milestone is mutex name and fernet key
        ($mutex or $fernetkey) and
        // second milestone is gathering wallet with domains
        ((10 of ($domain*) or #mainDomain > 10) and ($rexstring) and
        // vm,sandbox check and persistence
        3 of ($regkey*,$check*) and
        // other strings
        (
            5 of ($s*) or
            // and wmi and webm query for taskmanager block and usb drive identification
            7 of ($wmicall*,$wbemquery*) or
            6 of ($autorun*)
        )
}
