# 🧃.c

## Author
Heikki Juva
heikki@juva.lu

## Introduction
This is my submission for MEHU1-hash algorithm, as part of 1st annual "Tiivistekilpailu" (Hashing competition), organized by AB MEHU Limited

## Fancy-sounding principles in this design
1. Design follows Merkle-Damgård construction, of iterating each block of data through all rounds individually
2. Application utilizes ideas from Feistel network, where each round is a function of the previous round
3. Design is based on SPN, Substitution-Permutation Network. Each round consists of subsitution, permutation and round key addition
4. The core inspiration for this masterpiece is based on the ADCS-principle of Kouvosto Telecom; Always Deliver Concrete Service

## Usage
```
🧃 [-d] [-r] [-p] [-f filename | data]

-d is debug mode, shows what's happening
-f reads input from a file. Without it, reads input data from command line
-r is random emoji generator mode. Use with seed data on the command line.
-p shows progress in file input mode
```

## Install
Compiles at least with gcc on OSX: `gcc -o $'\360\237\247\203'.bin $'\360\237\247\203'.c`

## Key generation

### S-box
`head -c 655360 /dev/urandom | LC_CTYPE=C tr -dc '[:print:]' | head -c 65536 > sbox.txt`

### Round s-box
`openssl rand -hex 256`
Copy result to `#define ROUND_SBOX`

### Permutation tables and master key
`openssl rand -hex 16`
Copy result to `#define PERMUTATION`, `#define ROUND_PERMUTATION` and `#define MASTER_KEY`