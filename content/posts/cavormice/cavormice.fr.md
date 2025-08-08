---
title: "AMSI CTF 2025 - Reverse Engineering - Cavormice"
description: "N0PSCTF 2025"
date: 2025-08-08
draft: false
slug: "multi-author"
showAuthor: true
authors:
    - "Lyes BOURENNANI"
    - "alexis"
---

Ce challenge consiste en un fichier nommé `Cavormice.gb`. En utilisant la command `file`, nous pouvons voir que le fichier est une image ROM `Game Boy`.
```bash
$ file Cavormice.gb
Cavormice.gb: Game Boy ROM image (Rev.01) [ROM ONLY], ROM: 256Kbit
```

Le fichier est donc probablement un jeu. Nous pouvons donc utiliser un émulateur pour vérifier cette hypothèse. Nous avons utilison `mednafen` pour émuler le jeu en utilisant la commande suivante.

```bash
$ mednafen Cavormice.gb
```

![](https://i.imgur.com/I7AYYNO.png)

Avec cette information, nous avons chercher l'architecture de la Gameboy, qui est `Sharp SM83`. Maintenant, il nous faut des outils pour nous faciliter l'analyse. Nous sommes donc tomber sur un plugin [ghidra](https://github.com/Gekkio/GhidraBoy) qui a bien marché. Nous avions également prévu de faire de l'analyse dynamique et nous avons utiliser [BGB](https://bgb.bircd.org/) qui est un debugger pour GameBoy.

Maintenant, nous pouvons analyser ce qui ce passe dans le binaire.

En lançant le jeu, on remarque que l'on peut prendre des directions. Au bout de `32 choix`, on nous notifie qu'on a perdu avec le message `You lose…`. Il faut donc trouver le chemin correct pour gagner.

![](https://i.imgur.com/Y6Xdgus.png)

Maintenant, regardons le code en utilisant le plugin. Nous sommes tombés sur une fonction intéressante en utilisant le décompilateur `Ghidra`.

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

La fonction `FUN_06fc` semble très interessante. En effet, la fonction est appellé avec les arguments `0x55`, `0x44`, `0x52`, `0x4c` comme paramètres. Ces valeurs correspondent à des caractères ASCII. On retrouve respectivement `U`, `D`, `R` et `L`. Ces caractères sont possiblements les directions possibles dans le labyrinthe. Voici la décompilation de la fonction.

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

On peut voir que ces directions sont écrites dans `DAT_c808`. Il semblerait que la fonction `FUN_09a7` enregistre les mouvements du labyrinthe. Un autre détail intétessant est le fait que `FUN_09a7` dans la première condition appelle une fonction spéciale qui n'est pas appellé par les autres conditions. On voit que cela est fait quand on prend la direction `Up`.

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

Cette fonction agit comme une fonction de vérification. Nous avons un peu déobfusqué la logique pour donné une meilleure compréhension du code.

```C

bool check_function() {
    for (int i = 0; i < 16) {
        if (DAT_c828[i] != DAT_c808[2 * i] ^ DAT_c808[2 * i + 1]) {
            return false;
        }
    }
    
    return true;
```

On voit quelque chose de très interessant, on retrouve `DAT_c808` qui contient les directions du labyrinthe. On a une itération pair / impare qui compare les valeurs XORés entre elles avec une autre zone mémoire. En utilisant les propriétés du XOR, on peut récupérer les entrés correctes du labyrinthe si l'on retrouve `DAT_c828`. On sait également que l'on commence forcément par un mouvement `Up` dans le jeu. On a vu également qu'il faut finir par un mouvement `Up`. On peut retrouvé les entrées.

Nous avons essayé de récupérer `DAT_c828` mais nous avons eu un problème.

![](https://i.imgur.com/e13hLDZ.png)

Nous avons donc utiliser `BGB` pour récupérer les valeurs à l'exécution.
![](https://i.imgur.com/IBXg4x3.png)

Maintenant que nous avons récupérer les valeurs, nous avons plus qu'a programmer un petit script pour calculer l'entrée valide. Tout d'abord, nous avons calculé les valeurs XORés possibles en utilisant les combinaisons de directions deux à deux possibles.

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

Maintenant, nous n'avons plus qu'a trouvé la bonne combinaison avec les valeurs dans `data`.

So we just had to find the right combination to get the value wanted in the `data` array.

```python 
data = [0x19, 0x19, 0x8, 0x16, 0x7, 0x00, 0x19, 0x11,
        0x8, 0x16, 0x11, 0x19, 0x00, 0x1E, 0x7, 0x11]


direction = ['U', 'D', 'R', 'L']

setofdirection = {0x19: 'UL', 0x8: 'DL', 0x16: 'DR', 0x7: 'UR', 0x0: 'SameThing', 0x11: 'DU', 0x1E: 'LR'}

for el in data:
    print(f"{setofdirection.get(el, 'Unknown')}", end=' ')
```

Ce qui donne.

```bash
$ python3 script.py 
UL UL DL DR UR SameThing UL DU DL DR DU UL SameThing LR UR DU
```

Il manque cependant une règle à laquelle nous n'avons pas pensé : il faut allez en `bas` après avoir été en `haut` (sauf pour le premier et le dernier mouvement) car la salle du dessus bloque le joueur.

![](https://i.imgur.com/CLFI3cj.png)

La combinaison devient donc:

```
ULLUDLRDRUDDLUDUDLDRUDLUDDLRRUDU
```

Une fois que l'on effectue la bonne combinaison, on obtient un coffre dans la salle.

![](https://i.imgur.com/uSHDiKm.png)
![](https://i.imgur.com/FmFnwEM.png)

Le flag est donc:
```
AMSI{ULLUDLRDRUDDLUDUDLDRUDLUDDLRRUDU}
```
