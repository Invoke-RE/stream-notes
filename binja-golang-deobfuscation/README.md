## January 4 2025 - Binary Ninja Ungarble Stream

* Blog on using Binary Ninja WARP https://www.seandeaton.com/binary-ninja-warp-signatures/
* Binary Refinery vstack https://binref.github.io/units/formats/exe/vstack.html
* Max's blog on recovering symbols for Ghidra using BSim https://www.trellix.com/en-ca/blogs/research/no-symbols-no-problem/
* Using WARP signatures https://docs.binary.ninja/dev/annotation.html#warp-signature-libraries
* WARP open source repo https://github.com/Vector35/warp

* Garble signature:

```
rule garbled_golang {
    strings:
        // 004628aa  0fb6540448         movzx   edx, byte [rsp+rax+0x48 {var_40}]
        // 004628af  0fb6740449         movzx   esi, byte [rsp+rax+0x49 {var_40+0x1}]
        // 004628b4  89f7               mov     edi, esi
        // 004628b6  31d6               xor     esi, edx
        // 004628b8  8d3430             lea     esi, [rax+rsi]
        // 004628bb  8d76ed             lea     esi, [rsi-0x13]
        $ = { 0f b6 ?? ?? ?? 0f b6 ?? ?? ?? 89 f7 31 d6 8d ?? ?? ?? 8d ?? ?? }
    condition:
        all of them
}
```

* Ungarble code https://github.com/Invoke-RE/ungarble_bn