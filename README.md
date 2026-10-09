# Yara rule compilation

9/10/2026

Today I'm going to make a compilation for writing yara rules in order to improve writing the rule itself and doing static analysis on malware samples. By the way, samples are going to be taken from MalwareBazaar platform. Since I'm writing yara rules I will mostly do static analysis, but when it is needed I might do dynamic analysis also. I will try to write yara rules for both linux and windows binaries.
My goal is to write 15 yara rules.

## 1st rule
[Malware's Link](https://bazaar.abuse.ch/sample/7299d673b54d925035aaca820db13f3daa1e39e11cda36dbbfcc7bd26ffb6fc9/)

![file command](./images/Screenshot_20261009_112505.png)

![MZ](images/Screenshot_20261009_130750.png)
In the page itself it is being said that this malware has been dropped by Amadey malware. Which makes me highly sure that it is also a malicious file. 

![strings command on upx packed PE](./images/Screenshot_20261009_112753.png)
In this malware UPX packer has been used I will need to unpack it. This also means that when used directly on the file yara couldn't be able to detect it. Only if the yara is used on memory it can detect the unpacked version strings which I will try to write my rule on.

I easily unpacked it using upx linux version. 
![unpacking](./images/Screenshot_20261009_112943.png)

I ran file command on the unpacked binary again for checking if it is .NET binary or not. (If it would be .NET binary then my work with dynamic analysis would be easier and it would make my static analysis on binary more assured.)
![file command](./images/Screenshot_20261009_113106.png)

It was not. So I continued basic static analysis.

### Strings
This is all strings I found that can be used to write yara rule.
![Domain, Ip, Exe](./images/Screenshot_20261009_113554.png)
![Discord](./images/Screenshot_20261009_113923.png)

Also there was some .dll and .ps1 being used in the file.

![ps1](images/Screenshot_20261009_131355.png)

![dll1](images/Screenshot_20261009_131458.png)


![dll2](images/Screenshot_20261009_131552.png)

there is also Stresser related functions.

![Stresser info](images/Screenshot_20261009_131729.png)

I also checked wide strings and there are some interesting findings.

![Wide Strings](images/Screenshot_20261009_133728.png)

And I think I finished writing rules for this file. I tested it and it works. Though there will be multiple false positives is my guess.

[Final Rule](./rules/droppedbyamadey.yar "Yara Rule")
