## DCRat June 03 2025 Stream

* Sample: [https://github.com/Invoke-RE/community-malware-research/tree/main/Research/RATs/dcrat](https://github.com/Invoke-RE/community-malware-research/tree/main/Research/RATs/dcrat)

### Basic Yara Rule

```
rule dcrat
{
    meta:
        author = "Josh Reynolds"
        description = "DCRat Example to test"
    strings:
        $s1 = "DcRatByqwqdanchun" wide
    condition:
        all of them
}
```

### Decryption Script

```python
#!/usr/bin/env python3
#
# Iterate UserStrings and display one per line.

import sys
import dnfile
import base64
import hashlib
import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def show_strings(fname):
    arr = []
    # parse .NET executable
    dn = dnfile.dnPE(fname)
    # if no CLR data found, do nothing
    if not hasattr(dn, "net"):
        return

    # get the (first) UserStrings stream
    us: dnfile.stream.UserStringHeap = dn.net.metadata.streams.get(b"#US", None)
    if us:
        # get size of the stream
        size = us.sizeof()
        # First entry (first byte in stream) is empty string, so skip it
        offset = 1
        # while there is still data in the stream
        while offset < size:
            # check if we are at padding bytes near end of stream
            if offset + 4 >= size:
                if b"\x00" == dn.get_data(us.rva + offset, 1):
                    break
            # read the raw string bytes, and provide number of bytes read (includes encoded length)
            item = us.get(offset)
            if item is None:
                print(f"Bad string: offset=0x{offset:08x}")
                break

            if item.value is None:
                print(f"Bad string: {item.raw_data}")
            else:
                # display the decoded string
                print(item.value)
                arr.append(item.value)
            # continue to next entry
            offset += item.raw_size
    return arr

# for each filepath provided on command-line
for fname in sys.argv[1:]:
    rstr = show_strings(fname)
    key = None
    b64_decoded = []
    for r in rstr:
        try:
            rb = base64.b64decode(r)
            if len(rb) == 32:
                key = rb
            b64_decoded.append(rb)
        except:
            pass
    print(f"AES Key: {key}")
    hmac_hash = hashlib.pbkdf2_hmac('SHA1', key, b'DcRatByqwqdanchun', 50000, 32)
    for ct in b64_decoded:
        if(len(ct) > (16 + 32)):
            cipher = AES.new(hmac_hash, AES.MODE_CBC, ct[:16])
            try:
                pt = cipher.decrypt(ct[16:])
                print(unpad(pt[32:],AES.block_size))
            except:
                pass
```
