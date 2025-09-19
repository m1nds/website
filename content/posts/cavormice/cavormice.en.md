---
title: "AMSI CTF 2025 - Reverse Engineering - Cavormice"
description: "AMSI CTF 2025"
date: 2025-08-08
draft: false
author: "Lyes BOURENNANI"
---

In this challenge, we were given the `Cavormice.gb` file. When using the `file` command, we can see that the file is a `Game Boy ROM` image.
```bash
$ file Cavormice.gb
Cavormice.gb: Game Boy ROM image (Rev.01) [ROM ONLY], ROM: 256Kbit
```

The file is most likely a game so we can use a GameBoy emulator. We used `mednafen` to emulate the game by simply running the following command.

```bash
$ mednafen Cavormice.gb
```

![](https://i.imgur.com/I7AYYNO.png)


With this information, we searched for the architecture of the GameBoy, which is Sharp SM83. Now, we wanted to find a decompiler for this architecture so we understand what is happening in the binary. We found a plugin for [ghidra](https://github.com/Gekkio/GhidraBoy) which worked pretty well. We also wanted to be able to do a dynamic analysis so we used [BGB](https://bgb.bircd.org/), which is a debugger for GameBoy.

Let's now analyze what is happening !

By running the game, we noticed that after 32 directions taken, the message `You lose…` appears.

![](https://i.imgur.com/Y6Xdgus.png)

Let's now have a look at the code, using the plugin for `GameBoy`.
We came across this function in the game using `Ghidra`.

```c
void FUN_09a7
(void)

{
  undefined extraout_C;
  
  if ((((DAT_c806 & 0x80) != 0 || (byte)(DAT_c806 + (0xf < DAT_c805)) == '\0') && (DAT_c531 == 'a'))
     && (DAT_c532 == -0x3e)) {
    FUN_06fc(0x55);
    FUN_0729();
    FUN_0984(extraout_C);
    DAT_c803 = 0x58;
    DAT_c804 = 0;
    DAT_c805 = 0x97;
    DAT_c806 = 0;
  }
  if ((DAT_c806 & 0x80) != 0 || (byte)(DAT_c806 + (0xf < DAT_c805)) == '\0') {
    FUN_06fc(0x55);
    FUN_0968();
    DAT_c803 = 0x58;
    DAT_c804 = 0;
    DAT_c805 = 0x97;
    DAT_c806 = 0;
  }
  if ((DAT_c806 & 0x80) == 0 && (DAT_c805 < 0x98) <= DAT_c806) {
    FUN_06fc(0x44);
    FUN_0968();
    DAT_c803 = 0x58;
    DAT_c804 = 0;
    DAT_c805 = 0x10;
    DAT_c806 = 0;
  }
  if ((DAT_c804 & 0x80) == 0 && (DAT_c803 < 0xa0) <= DAT_c804) {
    FUN_06fc(0x52);
    FUN_0968();
    DAT_c803 = 8;
    DAT_c804 = 0;
    DAT_c805 = 0x58;
    DAT_c806 = 0;
  }
  if ((DAT_c804 & 0x80) != 0 || (byte)(DAT_c804 + (7 < DAT_c803)) == '\0') {
    FUN_06fc(0x4c);
    FUN_0968();
    DAT_c803 = 0x9f;
    DAT_c804 = 0;
    DAT_c805 = 0x58;
    DAT_c806 = 0;
    return;
  }
  return;
}
```

The function `FUN_06fc` seems very interesting. In fact, the function is given `0x55`, `0x44`, `0x52`, `0x4c` as parameters. If we convert these values in ASCII characters, we obtain respectively `U`, `D`, `R`, `L`. These are the possible directions for each step in the labyrinth. Here is the decompilation of the function.

```c
void FUN_06fc(undefined param_1)

{
  (&DAT_c808)[(char)DAT_c838] = param_1;
  DAT_c838 = DAT_c838 + 1;
  if ((DAT_c838 & 0x80) == 0 && 0x20 < DAT_c838) {
    FUN_063c();
    FUN_065e();
    return;
  }
  return;
}
```

We see that the direction is written in `DAT_c808`. It seems that `FUN_09a7` records the movements made in the labyrinth and using `FUN_06fc`. Another interesting detail about `FUN_09a7` is that in the first condition, it calls for a special function which is not called in the other conditions. It also seems that this call happens when we go upwards in the labyrinth.

```c
undefined FUN_0729(void)

{
  char cVar1;
  int iVar2;
  byte bVar3;
  
  DAT_c807 = 0;
  if (DAT_c838 == ' ') {
    for (iVar2 = 0; bVar3 = (byte)((uint)iVar2 >> 8),
        (byte)(!(bool)(bVar3 >> 7) << 7 | bVar3 & 0x7f) < (byte)(((byte)iVar2 < 0x10) + 0x80U);
        iVar2 = iVar2 + 1) {
      cVar1 = (byte)iVar2 * '\x02';
      if ((&DAT_c828)[iVar2] != ((&DAT_c808)[(char)(cVar1 + 1)] ^ (&DAT_c808)[cVar1])) {
        DAT_c807 = 0;
        return 0;
      }
    }
    DAT_c807 = 1;
  }
  return DAT_c807;
}
```

We can see that the function acts as a check function. The code is a bit unreadable, we deobfuscated the logic for an easier comprehension.
```C

bool check_function() {
    for (int i = 0; i < 16) {
        if (DAT_c828[i] != DAT_c808[2 * i] ^ DAT_c808[2 * i + 1]) {
            return false;
        }
    }
    
    return true;
```

Interesting, we meet again `DAT_c808` which contains the directions taken in the labyrinth. There is an Odd / Even iteration done on the input buffer. Values are XORed with each other. Using XOR properties, we have to retrieve `DAT_c828` to retrieve the correct entries. We have to consider the fact that we are forced to start and end with the `UP (U)` direction because of the layout of the labyrinth, which means we can easily retrieve the values.

We tried to find `DAT_c828` in **Ghidra** but we had that:

![](https://i.imgur.com/e13hLDZ.png)

So we used `BGB` to get the value at runtime:
![](https://i.imgur.com/IBXg4x3.png)



We now create a python script using the data array we just found, and we see what are the values when we `XOR` two different inputs.
```python
data = [0x19, 0x19, 0x8, 0x16, 0x7, 0x00, 0x19, 0x11,
        0x8, 0x16, 0x11, 0x19, 0x00, 0x1E, 0x7, 0x11]


direction = ['U', 'D', 'R', 'L']
for i in direction:
    for j in direction:
        if i != j:
            print(f"{i} {j}: {hex(ord(i) ^ ord(j))}")

```
which gives:
```bash
$ python3 script.py 
U D: 0x11
U R: 0x7
U L: 0x19
D U: 0x11
D R: 0x16
D L: 0x8
R U: 0x7
R D: 0x16
R L: 0x1e
L U: 0x19
L D: 0x8
L R: 0x1e
```
So we just had to find the right combination to get the value wanted in the `data` array.
```python 
data = [0x19, 0x19, 0x8, 0x16, 0x7, 0x00, 0x19, 0x11,
        0x8, 0x16, 0x11, 0x19, 0x00, 0x1E, 0x7, 0x11]


direction = ['U', 'D', 'R', 'L']

setofdirection = {0x19: 'UL', 0x8: 'DL', 0x16: 'DR', 0x7: 'UR', 0x0: 'SameThing', 0x11: 'DU', 0x1E: 'LR'}

for el in data:
    print(f"{setofdirection.get(el, 'Unknown')}", end=' ')
```
which gives:
```bash
$ python3 script.py 
UL UL DL DR UR SameThing UL DU DL DR DU UL SameThing LR UR DU
```
There is also one rule we didn't think about in our script: we need to go `Down` just after going `Up` (except for the first and the last one) because you are locked in the room after going `Up`:
![](https://i.imgur.com/CLFI3cj.png)
So the combination becomes:
```
ULLUDLRDRUDDLUDUDLDRUDLUDDLRRUDU
```
After entering these inputs, we arrived in a room with a chest:
![](https://i.imgur.com/uSHDiKm.png)
![](https://i.imgur.com/FmFnwEM.png)
So the flag is:
```
AMSI{ULLUDLRDRUDDLUDUDLDRUDLUDDLRRUDU}
```
