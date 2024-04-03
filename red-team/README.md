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
