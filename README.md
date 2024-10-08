The directory DGMT contains the reference code of the fully dynamic hash-based group signature DGMT.

In the directory DGMT, first execute the command “sh run.sh”. It will delete all the old directories of DGMT and compiles the makefile.
Then go into the "test" directory and execute ./dgmt_main.c 

This reference code is developed on top of the XMSS reference code available at: https://github.com/XMSS/xmss-referenc

Dependencies: Our code is developed in Ubuntu, a Debian-based system. For the SHA-2 hash functions (i.e. SHA-256 and SHA-512) and AES instructions, 
XMSS reference code and we rely on OpenSSL. Make sure to install the OpenSSL development headers. On Debian-based systems, this is achieved by installing the 
OpenSSL development package libssl-dev.
