import "pe"

rule Gacoabon_Mutex{
    strings:
        $susMutex1="chillerspetrification"
        $susMutex2="helplinesfrostiest"
    condition:
        any of ($susMutex*)
}
rule Gacoabon_WeakEvidence{
    strings:
        $domain="usefilebox.com"
        $ip="104.21.81.161"
        $file1="C:\\Program Files (x86)\\CMake\\sharniskioush.txt"
        $file2="C:\\Program Files\\Dolphin Anty\\iultoasosp"
        $file3="C:\\Program Files\\madams\\etyieciitz"
        $file4="C:\\ProgramData\\disbursements\\schmiovidyieups.dat"
    condition:
        ($domain and $ip) and
        any of ($file*)
}
rule Gacoabon_Injected_PEHeader{
    strings:
        $hex_header={4d 5a 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 00 50 45 00 00 64 86 ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 f0 00 22 0b 02 0e 00 00 ba 06 00 00 c2 01 00 00 00 00 00 b0 a8 06 00 00 10 00 00 00 00 00 80 01 00 00 00 00 10 00 00 00 02 00 00 06 00 00 00 00 00 00 00 06 00 00 00 00 00 00 00 00 e0 08 00 00 04 00 00 00 00 00 00 02 00 00 01 00 00 10 00 00 00 00 00 00 10 00 00 00 00 00 00 00 00 10 00 00 00 00 00 00 10 00 00 00 00 00 00 00 00 00 00 10 00 00 00 88 dd 07 00 44 00 00 00 cc dd 07 00 50 00 00 00 00 00 00 00 00 00 00 00 00 70 08 00 e8 00 00 00 00 00 00 00 00 00 00 00 d0 08 00 dc 07 00 00 00 00 00 00 00 00 00 00}
        condition:
        (pe.imports("kernel32.dll", "LoadLibraryA") and
        pe.imports("kernel32.dll", "GetProcAddress") and
        pe.imports("kernel32.dll", "IsDebuggerPresent") and
        pe.imports("kernel32.dll", "VirtualProtect")) or
        $hex_header
}
rule Gacoabon_PE{
    condition:
        pe.is_pe and
        pe.version_info["OriginalFilename"] == "gacoabon.exe" and
        pe.version_info["CompanyName"] == "Gacoabon Labs, LLC"
}
rule GacoabonDropper{
    meta:
        author="MedicWiesel"
        date="16-10-2026"
        description="Detects Gacoabon stager that uses process injection"
        reference="https://bazaar.abuse.ch/sample/8360a40c7eb801b653b9f2180c9b3dc49fb9c6ed139f98e2491aa031f69052a8/"
    condition:
        (Gacoabon_Mutex and
        Gacoabon_Injected_PEHeader and
        Gacoabon_WeakEvidence) or
        Gacoabon_PE
}
