/*
An Implementation of WannaCry
Rule hasn't been tested on multiple files
*/
rule WannaCry
{
  meta:
      author= "MedicWiesel"
      description= "Detects via strings that possibly exists in Wannacry binary"
      reference="https://bazaar.abuse.ch/sample/b69cdbaf327bf600f6e0ccd230367d28ab5be6977d35d51f78ad7229d75fb7f6"
      date="09-10-2026"
  strings:
      $export = "launcher.dll"
      $s1 = "PlayGame"
      $D4 = /(D.{1,6}4){1,3}/
      $domain = "http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"
      $name1 = "WANACRY!"
      $name2 = "WNcry@2ol7"
      $name3 = "WanaCrypt0r" wide
      $language = /msg\/m_[a-zA-Z\s()]{5,21}\.wnry/
      $ext = /[a-z]\.wnry/

      // array of symbols
      $symbol1="abcdefghijklmnopqrstuvwxyz"
      $symbol2="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
      $symbol3=" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
      // commands
      $cmd1="cmd.exe /c \"%s\""
      $cmd2="icacls . /grant Everyone:F /T /C /Q"
  condition:
    uint16(0)== 0x5A4D and
    filesize <= 10MB and
    $D4 and
    1 of ($symbol*) and
    8 of ($export,$s1,$domain,$name*,$language,$ext,$cmd*)

}
rule WannaCry_SMB{
    meta:
        description="This version of WannaCry also had SMB payloads inside"
        author="MedicWiesel"
        date="09-10-2026"
    strings:
        // this version also had some SMB protocol payloads
        $smb1=/SMB[a-zA-Z23]/
        $smb2="__TREEID__PLACEHOLDER__"
        $smb3="__USERID__PLACEHOLDER__"
        $path="C:\\%s\\%s"
        $share1="\\\\%s\\IPC$"
        $share2="\\\\172.16.99.5\\IPC$" wide
        $share3="\\\\192.168.56.20\\IPC$" wide
    condition:
        WannaCry and
        all of ($smb2,$smb3) and
        any of ($path,$share*,$smb1)
}
