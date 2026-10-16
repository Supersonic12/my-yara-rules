/*
An Implementation of WannaCry
Rule hasn't been tested on multiple files
*/
rule WannaCryBasic
{
  meta:
      author= "MedicWiesel"
      description= "Detects via strings that possibly exists in Wannacry binary"
      reference="https://bazaar.abuse.ch/sample/79af101b4ef565a38c39f1d11632eedc12624d6d667bf4d3c3f185d12634253e/"
      date="29/09/2026"
  strings:
      $export = "launcher.dll"
      $s1 = "PlayGame"
      $D4 = /(D.{,6}4)+/
      $domain = "http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"
      $name1 = "WANACRY!"
      $name2 = "WNcry@2o17"
      $ext = /^(.+\.wnry)/

  condition:
      all of them
}
