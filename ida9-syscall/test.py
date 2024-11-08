import idapro, sys, idautils
from numpy import uint32

"""
__int64 __fastcall sub_1800429C7(_BYTE *a1)
{
  int v1; // eax
  unsigned int v2; // edx

  v1 = (char)*a1;
  if ( !*a1 )
    return 0LL;
  v2 = 0;
  do
  {
    ++a1;
    v2 = (0x401 * (v2 + v1)) ^ ((0x401 * (v2 + v1)) >> 6);
    v1 = (char)*a1;
  }
  while ( *a1 );
  return 0x8001 * ((9 * v2) ^ ((9 * v2) >> 11));
"""
def hash_function(string: bytes) -> int:
    value: int = 0
    for char in string:
        value = uint32(0x401 * (value + char)) ^ (uint32(0x401 * (value + char)) >> 6)
    return uint32(0x8001 * (uint32(9 * value) ^ (uint32(9 * value) >> 11)))

"""
__int64 __fastcall mw_hash(__int64 a1)
{
  unsigned __int16 v2; // [rsp+0h] [rbp-18h]
  unsigned int v3; // [rsp+4h] [rbp-14h]
  unsigned int v4; // [rsp+8h] [rbp-10h]

  v4 = 0;
  v3 = 0xE5C53D54;
  while ( *(_BYTE *)(a1 + v4) )
  {
    v2 = *(_WORD *)(a1 + v4++);
    v3 ^= ((v3 << 24) | ((unsigned __int64)v3 >> 8)) + v2;
  }
  return v3;
}
"""
def hash(estr):
    v4 = 0
    v3 = 0xE5C53D54
    estrb = bytes(estr, 'ascii')
    for i in range(0, len(estrb)):
        v2 = int.from_bytes(estrb[i:i+2], byteorder='little')
        v3 ^= ((v3 << 24) | (((v3 & 0xFFFFFFFFFFFFFFFF) >> 8)) + v2) & 0xFFFFFFFF
        v4 += 1
    return v3

idapro.open_database(sys.argv[1], run_auto_analysis=True)
print("enum hashes {")
for ordinal, addr, addr2, name in idautils.Entries():
    print(f"\t{name} = 0x{hash2(name):2x},")
print("}")
