### Babuk

* Triage run: https://tria.ge/250421-m366ya1zaz
* https://github.com/Hildaboo/BabukRansomwareSourceCode
* IDA Yara Plugin https://github.com/mahmoudimus/ida-pysigmaker
* Yara

```
rule Invoke_Babuk_Babyk {
    strings:
        // HC-128 code
        // .text:0040C5BC C1 E9 16                                shr     ecx, 16h
        // .text:0040C5BF BA 04 00 00 00                          mov     edx, 4
        // .text:0040C5C4 6B C2 0D                                imul    eax, edx, 0Dh
        $hc_128_1 = { C1 ?? 16 ?? 04 00 00 00 6B ?? 0D }
        $hc_128_2 = { C1 ?? 16 ?? 04 00 00 00 6B ?? 0E }
        $hc_128_3 = { C1 ?? 18 ?? 04 00 00 00 C1 ?? 03 }
        // CRC32 checksum bytes
        $crc32_1 = { B7 1D C1 04 6E }
    condition:
        all of them
}
```