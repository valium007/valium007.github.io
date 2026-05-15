---
title: "Solving a crackme using angr"
date: "2025-04-10"
author: "Valium"
summary: "Using angr symbolic execution to automatically crack a binary reversing challenge from crackmes.one. Using angr symbolic execution to automatically crack a binary reversing challenge from crackmes.one."
tags: ["Reverse Engineering", "angr", "Misc"]
---

# {title}

The crackme given is [this](https://crackmes.one/crackme/67bd52114e1a16f76a1ad5bc)

I'm going to throw this exe in ida. This is how the main function looks like when decompiled.

The output given is not stripped off nor the variables are changed. The function looks exactly like this when decompiled. We are going to move forward and make sense from this.

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  size_t v3; // rbx
  __int64 v4; // rdi
  char accept[40]; // [rsp+10h] [rbp-40h] BYREF
  unsigned __int64 v7; // [rsp+38h] [rbp-18h]

  v7 = __readfsqword(0x28u);
  if ( a1 != 2 )
  {
    puts("Usage: ./crackme <key>");
    exit(-1);
  }
  if ( strlen(a2[1]) <= 5 || strlen(a2[1]) > 0xFE )
    error();
  qmemcpy(accept, "abcdefghijklmnopqrstuvwxyz-", 27);
  v3 = strlen(a2[1]);
  if ( v3 != strspn(a2[1], accept) )
    error();
  strcpy(&dest, a2[1]);
  v4 = (unsigned int)sub_1249();
  if ( !(unsigned int)sub_121D(v4, 2) )
    error();
  if ( !(unsigned int)sub_12CB() )
    error();
  puts("The password was correct");
  return 0;
}
```

`a2[1]` is basically `argv[1]`, the key length should be greater than 5 and less than `0xfe`. `"abcdefghijklmnopqrstuvwxyz-"` is copied into accept, this is probably a charset. Now there are basically some checks. The first one is that the length of key must be equal to the length of the initial portion of our key which consists of only of characters that are of the charset.

our key is then copied into `dest`.

```c
_BOOL8 __fastcall sub_121D(int a1, int a2)
{
  return a1 <= a2 && a1 >= a2;
}
```
```c
__int64 sub_1249()
{
  unsigned int v1; // [rsp+8h] [rbp-18h]
  int i; // [rsp+Ch] [rbp-14h]

  v1 = 0;
  for ( i = 0; i < strlen(dest); ++i )
  {
    if ( dest[i] == 45 )
    {
      if ( !i || i == strlen(dest) - 1 )
        return 0xFFFFFFFFLL;
      ++v1;
    }
  }
  return v1;
}
```

The function checks that if the last and first character of the key is `'-'` then it returns with a 0 value. To make it return 2, the key should only have two `-` and `key[0], key[last] != '-'`.

Now the only check left is this.

```c
__int64 __fastcall sub_1207(char a1)
{
  return (unsigned int)(a1 - 97);
}

_BOOL8 sub_12CB()
{
  int v0; // ebx
  size_t v1; // rax
  char v2; // bl
  int v4; // [rsp+0h] [rbp-20h]
  int i; // [rsp+4h] [rbp-1Ch]
  int v6; // [rsp+8h] [rbp-18h]
  int v7; // [rsp+Ch] [rbp-14h]

  v0 = dword_4020[(int)sub_1207((unsigned int)dest[0])];
  v1 = strlen(dest);
  v6 = v0 ^ byte_4090[(int)sub_1207((unsigned int)dest[v1 - 1])];
  v4 = 0;
  for ( i = 1; i < strlen(dest) - 1; ++i )
  {
    if ( dest[i] != 45 )
    {
      v7 = sub_1207((unsigned int)dest[i]);
      if ( v7 > 13 )
      {
        if ( (i & 1) != 0 )
          v4 -= byte_4090[v7];
        else
          v4 += v7;
      }
      else if ( (i & 1) != 0 )
      {
        v4 -= v7;
      }
      else
      {
        v4 += dword_4020[v7];
      }
    }
  }
  v2 = dest[0];
  return v2 == dest[strlen(dest) - 1] && v4 == v6;
}
```

To make it return true, `key[0] == key[last] & v4 == v6`. Now instead of knowing what leet hax0r xor check is this. We can just solve it using angr.

Im going to copy this whole function and compile it to a c binary.

```c
//crackme.cpp
//g++ crackme.cpp -o crackme
#include <iostream>
#include <cstring>
#include <stdint.h>


uint8_t dword_4020[] = {
	16, 47, 26, 30, 39, 30, 27, 35, 10, 36, 32, 11, 30,
	12, 17, 33, 14, 42, 10, 24, 25, 41, 44, 32, 13, 46,0,0
};
	
uint8_t byte_4090[] = {
	64, 6, 170, 81, 193, 221, 184, 29, 247, 8, 210, 95,
	187, 32, 247, 159, 203, 27, 84, 43, 255, 39, 18, 210, 81,96
};

unsigned int sub_1207(char a){ return (unsigned int)(a-97); }

char key[254];

bool check(){
  char v2; // bl
  int v0 = dword_4020[(int)sub_1207(key[0])];
  int key_len = strlen(key);
  int v6 = v0 ^ byte_4090[(int)sub_1207(key[key_len - 1])];
  int v4 = 0;

	int v7 = 0;

	for ( int i = 1; i < strlen(key) - 1; ++i )
	{
	  if ( key[i] != 45 )
	  {
		v7 = sub_1207(key[i]);
		if ( v7 > 13 )
		{
		  if ( (i & 1) != 0 )
			v4 -= byte_4090[v7];
		  else
			v4 += v7;
		}
		else if ( (i & 1) != 0 )
		{
		  v4 -= v7;
		}
		else
		{
		  v4 += dword_4020[v7];
		}
	  }
	}

  v2 = key[0];
  return v2 == key[strlen(key) - 1] && v4 == v6;

}


int main(int argc, char** argv){

	if(argc!=2){
		printf("usage: %s <key>\n",argv[0]);
		exit(-1);
	}

	strcpy(key,argv[1]);

	if(check()){
		printf("success\n");
                exit(0);
	}

	printf("fail\n");
	return 0;

}
```

Here's the angr script.

```python
import angr
import claripy

input_path = "./crackme"
project = angr.Project(input_path, auto_load_libs=False)
argv1 = claripy.BVS("argv1", 6 * 8)  # 6 bytes * 8 bits

state = project.factory.full_init_state(args=[input_path, argv1])

# Constraints
argv1_bytes = argv1.chop(8)
allowed_chars = b"abcdefghijklmnopqrstuvwxyz-"

for byte in argv1_bytes:
    state.solver.add(claripy.Or(*[byte == c for c in allowed_chars]))

state.solver.add(argv1_bytes[0] == argv1_bytes[-1])
state.solver.add(claripy.Or(*[argv1_bytes[i] == ord('-') for i in range(1, len(argv1_bytes)-1)]))

state.solver.add(argv1_bytes[0] != ord('-'))
state.solver.add(argv1_bytes[1] != ord('-'))
state.solver.add(argv1_bytes[2] != ord('-'))
state.solver.add(argv1_bytes[-1] != ord('-'))

simgr = project.factory.simgr(state)

## Find flag
simgr.explore(find=lambda s: b"success" in s.posix.dumps(1),
              avoid=lambda s: b"fail" in s.posix.dumps(1))

if simgr.found:
    found = simgr.found[0]
    solution = found.solver.eval(argv1, cast_to=bytes)
    print(f"[+] Solution found: {solution}")
else:
    print("[-] No solution found.")
```

Obviously we are not going to make a keygen. We just need a key. Thats why the key length is 6. We added the constraints here instead in the decompiled code.

on running this python script we get a key!

```bash
[+] Solution found: b'ndb--n'
```

running on the actual crackme.
```bash
valium@DESKTOP:~$ ./crackme ndb--n
The password was correct
```