# Red Team Stream (March 30 2024)

## Sliver

* [https://sliver.sh/](https://sliver.sh/)
* Compile obfuscation affects both function name strings and code itself. This was confirmed through generating one obfuscated binary and one non-obfuscated binary.
* Runtime check-in makes use of hardware identifier from the registry etc.
* http-c2.go contains the models package that contains C2 information?
* Build pipeline makes use of Golang templates to template custom configuration information
*  '--canary' in command line sets 'canaryDomain' in 'client/command/generate/generate.go' which appends the canary domains to "canaryDomains".
* In plaintext binary the C2 is embedded in github_com_bishopfox_sliver_implant_sliver_transports_C2Generator_func2
* C2 profiles are written a protobuf in `client/command/generate/` and read during build time while being embedded in raw golang code by built system
* Canaries do not appear to be in plaintext when embedded properly?
* TODO: Find where domain is used in obfuscated sample.

## Havoc

* [https://github.com/HavocFramework/Havoc](https://github.com/HavocFramework/Havoc)
* Havoc uses djb2 hashing for dynamic import resolution upon execution
* TODO: finish dynamic resolution code and markup IDB or BNDB for next stream. Then finish reversing Havoc.

# Red Team Stream (April 13 2024)

* Hashdb [https://github.com/OALabs/hashdb](https://github.com/OALabs/hashdb)
* Hashdb IDA plugin [https://github.com/OALabs/hashdb-ida](https://github.com/OALabs/hashdb-ida)
* Hashdb Binja plugin [https://github.com/cxiao/hashdb_bn](https://github.com/cxiao/hashdb_bn)
* [https://github.com/Vector35/sigkit](https://github.com/Vector35/sigkit) - Signature generation kit for generating signature libraries
* Gamozo Printer Hacking Series [https://www.youtube.com/watch?v=qti5_NOLE8M&list=PLSkhUfcCXvqGGQN8ATgWI0XYGvU-jq0uG](https://www.youtube.com/watch?v=qti5_NOLE8M&list=PLSkhUfcCXvqGGQN8ATgWI0XYGvU-jq0uG)
* Havoc's C2 IP is in plaintext. The configuration parsing code is kind of crazy, and may indicate a variable length configuration, because data is periodically walked with different function calls.
* TODO: finish reversing havoc's config structure and automating extracting configuration and look for more samples
* Found Sliver's obfuscation mechanism which is Garble [https://github.com/burrowers/garble](https://github.com/burrowers/garble)
* Found Sergei's deobfuscation techniques here: [https://web.archive.org/web/20230924191918/https://research.openanalysis.net/bandit/stealer/garble/go/obfuscation/2023/07/31/bandit-garble.html](https://web.archive.org/web/20230924191918/https://research.openanalysis.net/bandit/stealer/garble/go/obfuscation/2023/07/31/bandit-garble.html)
* TODO: Setup emulation code like Sergei and write automation to identify target functions for emulation. Ideally this leads to deobfuscation of C2 addresses

# Red Team Stream (June 10 2024)

* Havoc will have certain code (i.e SMB) based on ifdefs so the config extractor has to accomodate for that
* Wrote Havoc configuration structure parser with Binary Ninja [parse_havoc_generic.py](scripts/parse_havoc_generic.py)
* Wrote a Binary Ninja script to assist with hash resolution markups [map_enums.py](scripts/map_enums.py)
* Wrote a Yara rule to detect additional Havoc payloads on [unpac.me](unpac.me)