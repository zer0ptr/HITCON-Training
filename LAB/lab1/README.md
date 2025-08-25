题目给出的是一个`32位ELF`格式的可执行程序，用`ida`分析

F5伪代码结果
```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  setvbuf(stdout, 0, 2, 0);
  get_flag();
  return 0;
}
```
主要的功能入口在`get_flag`函数
```C
unsigned int get_flag()
{
  int buf; // [esp+8h] [ebp-80h] BYREF
  int v2; // [esp+Ch] [ebp-7Ch] BYREF
  unsigned int i; // [esp+10h] [ebp-78h]
  int fd; // [esp+14h] [ebp-74h]
  _BYTE v5[11]; // [esp+19h] [ebp-6Fh]
  char v6[15]; // [esp+24h] [ebp-64h] BYREF
  char v7[22]; // [esp+33h] [ebp-55h] BYREF
  char v8[51]; // [esp+49h] [ebp-3Fh] BYREF
  unsigned int v9; // [esp+7Ch] [ebp-Ch]

  v9 = __readgsdword(0x14u);
  v5[0] = 7;
  v5[1] = 59;
  v5[2] = 25;
  v5[3] = 2;
  v5[4] = 11;
  v5[5] = 16;
  v5[6] = 61;
  v5[7] = 30;
  v5[8] = 9;
  v5[9] = 8;
  v5[10] = 18;
  strcpy(v6, "-(Y\n");
  v6[5] = 30;
  v6[6] = 22;
  v6[7] = 0;
  v6[8] = 4;
  v6[9] = 85;
  v6[10] = 22;
  v6[11] = 8;
  v6[12] = 31;
  v6[13] = 7;
  v6[14] = 1;
  strcpy(v7, "\t");
  v7[2] = 126;
  v7[3] = 28;
  v7[4] = 62;
  v7[5] = 10;
  v7[6] = 30;
  v7[7] = 11;
  v7[8] = 107;
  v7[9] = 4;
  v7[10] = 66;
  v7[11] = 60;
  v7[12] = 44;
  v7[13] = 91;
  v7[14] = 49;
  v7[15] = 85;
  v7[16] = 2;
  v7[17] = 30;
  v7[18] = 33;
  v7[19] = 16;
  v7[20] = 76;
  v7[21] = 30;
  strcpy(v8, "BDo_you_know_why_my_teammate_Orange_is_so_angry???");
  fd = open("/dev/urandom", 0);
  read(fd, &buf, 4u);
  printf("Give me maigc :");
  __isoc99_scanf("%d", &v2);
  if ( buf == v2 )
  {
    for ( i = 0; i <= 0x30; ++i )
      putchar(v5[i] ^ v8[i + 1]);
  }
  return __readgsdword(0x14u) ^ v9;
}
```
按照程序逻辑解码即可
```Python
# exp.py
cipher= [7, 59, 25, 2, 11, 16, 61, 30, 9, 8, 18, 45, 40, 89, 10, 0, 30, 22, 0, 4, 85, 22, 8, 31, 7, 1, 9, 0, 126, 28, 62, 10, 30, 11, 107, 4, 66, 60, 44, 91, 49, 85, 2, 30, 33, 16, 76, 30, 66]
key= "Do_you_know_why_my_teammate_Orange_is_so_angry???"
flag=[]
for i in range(0,0x31):
	flag.append(chr(cipher[i] ^ ord(key[i])))
print("flag: "+''.join(flag))
```

flag: `CTF{debugger_1s_so_p0werful_1n_dyn4m1c_4n4lySis!}`