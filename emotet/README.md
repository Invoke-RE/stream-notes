## February 28 Stream

* Samples from: [https://www.malware-traffic-analysis.net/2020/09/30/](https://www.malware-traffic-analysis.net/2020/09/30/)
* Useful for VM hardening [https://github.com/hatching/vmcloak](https://github.com/hatching/vmcloak)
* Extracted PowerShell from word document using `olevba`, `vipermonkey` and Assemblyline [https://cybercentrecanada.github.io/assemblyline4_docs/](https://cybercentrecanada.github.io/assemblyline4_docs/)
* Unpacked multi-stage dave crypter infection chain
* Had a first stage shellcode loader, that mapped a second stage that eventually executed a third stage
* Dumped/carved all stages using static and dynamic analysis
* Can write static unpacker for Emotet payloads if desired later on
* Found final stage hashing algorithm was using Emotet algorithm from Hashdb
    * https://github.com/OALabs/hashdb/blob/main/algorithms/emotet.py
* Emotet hashing algorithm uses different XOR modifying for DLL and function names that need to be set in hashdb plugin
* asherien1 mentioned cvtres LOLBAS https://isc.sans.edu/diary/27892 that might be used by Qakbot
* Davecrypter is used to deliver Qakbot, BRC4 and Emotet