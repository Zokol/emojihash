/*
    🧃.c

    Author: Heikki Juva
    Date: 2021-10-13

    This is my submission for MEHU1-hash algorithm, as part of 1st annual "Tiivistekilpailu" (Hashing competition), organized by AB MEHU Limited

    Fancy-sounding principles in this design;
    1) Design follows Merkle-Damgård construction, of iterating each block of data through all rounds individually
    2) Application utilizes ideas from Feistel network, where each round is a function of the previous round
    3) Design is based on SPN, Substitution-Permutation Network. Each round consists of subsitution, permutation and round key addition
    4) The core inspiration for this masterpiece is based on the ADCS-principle of Kouvosto Telecom; Always Deliver Concrete Service

    Usage: 🧃 [-d] [-r] [-p] [-f filename | data]

    -d is debug mode, shows what's happening
    -f reads input from a file. Without it, reads input data from command line
    -r is random emoji generator mode. Use with seed data on the command line.
    -p prints progress

    compiles at least with gcc on OSX:   gcc -o $'\360\237\247\203'.bin $'\360\237\247\203'.c
*/

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <wchar.h>
#include <locale.h>
#include <signal.h>

// -----------------------------------
// DEFINITIONS
// -----------------------------------

// MODES
#define ENABLE_SBOX 1
#define ENABLE_PERMUTATION 1
#define ENABLE_ROUND_KEY 1

// Block size
#define BLOCK_SIZE 20

// number of hash rounds
#define ROUNDS 50

// number of times to run data through the algorithm
#define REPEAT_CYCLES 2

// S-box table
#define SBOX_SIZE 65536
char sbox[SBOX_SIZE];

// Permutation table, must match block size
int permutation[BLOCK_SIZE];
#define PERMUTATION "ad087ac2a832b24d8a5f230cfdb7590397b0abb9";

// Master key, must be same length as block size
#define MASTER_KEY "92035d1a0a223c5d5de3a1f48c5b35b806533631";

// S-box table for round key generation, must match alphabet size
#define ROUND_SBOX "f68431917998ec25727963723eedeeaf0385c5a3153f9bc980a6f636f0708b261cea57c2f7014e5331351406fb8fe10524c23205cbb58ed2351314e8d0dd0b0b3ef806da1a0c6b55e9d5a92294046ad7ec3c950a8752cff4680c03fb92ceafa383228f364b63e14f763d8eb1781a8c340f50c0f6e90f30bc6be3123c6cd2b4d31a56c674e587bc48f83721697d174de1ecef337e6b291bda6a7070c7b017ee37b5bf96fd1c0acbf8a6e7c36fc14f7b7f69c2de2c8ec52dd445faebf63b54ff4ac8de07dd15b477fce4fe76b2b67eadd8b9abfe06de35ee47f19c9a44bf9169e8cd862cb63c79868279d0c7402d2dde39547defd21c5f0da924518fa3bc592c96";

// Permutation table for round key generation, must match block size
#define ROUND_PERMUTATION "3eab02947e44ac05d2960c5e6494e40541fd4c29";

// round key store
char round_key_store[ROUNDS][BLOCK_SIZE] = {0};

// Internal state of the hash function, also the final hash value.
char state[BLOCK_SIZE] = {0};

int debug = 0;
int progress_enabled = 0;

// -----------------------------------
// FUNCTIONS
// -----------------------------------

// HELPER FUNCTIONS
void print_state()
{
    extern char state[BLOCK_SIZE];
    for (int i = 0; i < BLOCK_SIZE; i++)
    {
        printf("%02x ", state[i] & 0xFF);
    }
    printf("\n");
}

void print_data(const char data[BLOCK_SIZE])
{
    for (int i = 0; i < BLOCK_SIZE; i++)
    {
        printf("%02x ", data[i] & 0xFF);
    }
    printf("\n");
}

void print_round_keys()
{
    extern char round_key_store[ROUNDS][BLOCK_SIZE];
    for (int i = 0; i < ROUNDS; i++)
    {
        for (int j = 0; j < BLOCK_SIZE; j++)
        {
            printf("%02x ", round_key_store[i][j] & 0xFF);
        }
        printf("\n");
    }
}

void print_progress(int n, int total, time_t start_time)
{
    time_t current_time = time(NULL);
    long elapsed = current_time - start_time;
    // Calculate the progress percentage
    int progress = (int)((double)n / total * 100);
    // printf("\033[1A"); // Move cursor up
    printf("\033[2K"); // Clear the line
    printf("\rProcessed %d%% | %d/%d blocks | %ld seconds elapsed", progress, n, total, elapsed);
    fflush(stdout);
}

// Maps byte to emoji
wchar_t emoji_mapper(char symbol)
{
    wchar_t emoji_start = 0x1F600;
    wchar_t emoji_end = 0x1F64F;
    int index = (u_int16_t)symbol % (emoji_end - emoji_start);
    wchar_t emoji = emoji_start + index;
    return emoji;
}

// Prints emojis from the state
void print_emojis(int random_mode)
{
    setlocale(LC_ALL, "en_US.UTF-8");

    if (random_mode)
    {
        char result = 0x00;
        // Print random emojis
        for (int i = 0; i < BLOCK_SIZE; i++)
        {
            result ^= state[i];
        }
        wprintf(L"%lc", emoji_mapper(result));
    }
    else
    {
        for (int c_i = 0; c_i < BLOCK_SIZE; c_i++)
        {
            wprintf(L"%lc", emoji_mapper(state[c_i]));
        }
    }
}

// Convert a string to 16-bit symbols
uint16_t convert_to_symbols(const char *input)
{
    int input_length = strlen(input);
    if (input_length % 2 == 1) // If input is odd length, pad it with the xor of the first and last byte
    {
        char xor_byte = input[0] ^ input[input_length - 1];
        char *padded_input = malloc(input_length + 1);
        memcpy(padded_input, input, input_length);
        padded_input[input_length] = xor_byte;
        input = padded_input;
        input_length++;
    }
    uint16_t output[input_length / 2];
    int output_i = 0;
    for (int i = 0; i < input_length; i += 2)
    {
        output[output_i] = ((uint16_t)input[i] << 8) | (uint16_t)input[i + 1];
        output_i++;
    }
    return output;
}

// Convert a hexstring to a char sbox table
void hexstring_to_sbox(char *hexstring, char *sbox, int sbox_size)
{
    int len = strlen(hexstring);
    if (len % 2 != 0)
    {
        printf("Error: hexstring length must be even\n");
        raise(SIGINT);
    }
    if (len / 2 > sbox_size)
    {
        printf("Error: hexstring is too long for sbox. %d > %d\n", len / 2, sbox_size);
        raise(SIGINT);
    }
    if (len / 2 < sbox_size)
    {
        printf("Error: hexstring is too short for sbox. %d < %d\n", len / 2, sbox_size);
        raise(SIGINT);
    }
    for (int i = 0; i < len; i += 2)
    {
        char hex[3] = {hexstring[i], hexstring[i + 1], '\0'};
        sbox[i / 2] = (char)strtol(hex, NULL, 16);
    }
}

// Convert a hexstring to an int permutation table
void hexstring_to_permutation(char *hexstring, int *permutation)
{
    int len = strlen(hexstring);
    if (len % 2 != 0)
    {
        printf("Error: hexstring length must be even\n");
        raise(SIGINT);
    }
    if (len / 2 > BLOCK_SIZE)
    {
        printf("Error: hexstring is too long for permutation array\n");
        raise(SIGINT);
    }
    if (len / 2 < BLOCK_SIZE)
    {
        printf("Error: hexstring is too short for permutation array\n");
        raise(SIGINT);
    }
    for (int i = 0; i < len; i += 2)
    {
        char hex[3] = {hexstring[i], hexstring[i + 1], '\0'};
        permutation[i / 2] = (int)strtol(hex, NULL, 16);
    }
}

// Convert a hexstring to a char master key
void hexstring_to_master_key(char *hexstring, char *master_key)
{
    int len = strlen(hexstring);
    if (len % 2 != 0)
    {
        printf("Error: hexstring length must be even\n");
        raise(SIGINT);
    }
    if (len / 2 > BLOCK_SIZE)
    {
        printf("Error: hexstring is too long for master key array\n");
        raise(SIGINT);
    }
    if (len / 2 < BLOCK_SIZE)
    {
        printf("Error: hexstring is too short for master key array\n");
        raise(SIGINT);
    }
    for (int i = 0; i < len; i += 2)
    {
        char hex[3] = {hexstring[i], hexstring[i + 1], '\0'};
        master_key[i / 2] = (char)strtol(hex, NULL, 16);
    }
}

// Key schedule
// Generate round keys from the master key
void generate_keys()
{
    extern char round_key_store[ROUNDS][BLOCK_SIZE]; // Storage for round keys
    extern char sbox[SBOX_SIZE];                     // Substitution bos table
    extern int permutation[BLOCK_SIZE];              // Permutation table
    extern int debug;                                // Debug flag

    int round_permutation[BLOCK_SIZE];
    char round_sbox[SBOX_SIZE];
    char master_key[BLOCK_SIZE];

    char round_permutation_string[] = ROUND_PERMUTATION; // Round permutation table input string
    char round_sbox_string[] = ROUND_SBOX;               // Round substitution table input string
    char master_key_string[] = MASTER_KEY;               // Master key input string
    char permutation_string[] = PERMUTATION;             // Permutation table input string

    FILE *file = fopen("sbox.txt", "rb"); // Read sbox from file
    if (file == NULL)
    {
        perror("Failed to open sbox file. Please initialize sbox.txt with a 65536 bytes of carefully selected random data.");
        raise(SIGINT);
    }
    size_t sbox_input_len = fread(sbox, 1, sizeof(sbox), file);
    fclose(file);
    if (sbox_input_len != sizeof(sbox))
    {
        printf("Error: failed to read %ld bytes from file. %ld bytes read\n", sizeof(sbox), sbox_input_len);
        raise(SIGINT);
    }

    // Parse input strings
    hexstring_to_permutation(round_permutation_string, round_permutation);
    hexstring_to_sbox(round_sbox_string, round_sbox, 256);
    hexstring_to_master_key(master_key_string, master_key);
    hexstring_to_permutation(permutation_string, permutation);

    // Generate round keys from master key
    for (int i = 0; i < ROUNDS; i++) // Initialize round key for every round
    {
        for (int j = 0; j < BLOCK_SIZE; j++) // Initialize round key byte by byte
        {
            round_key_store[i][j] = master_key[(i + j) % BLOCK_SIZE];          // Initialize round key byte with shifted master key
            round_key_store[i][j] ^= round_sbox[round_key_store[i][j] & 0xFF]; // xor the round key byte with the round sbox
        }
        for (int j = 0; j < BLOCK_SIZE; j++) // Shuffle round key with the round permutation table
        {
            round_key_store[i][j] = round_key_store[i][round_permutation[j] % BLOCK_SIZE];
        }
    }

    if (debug)
        print_round_keys();
}

// HASH FUNCTION
// Function to hash a BLOCK_SIZE-byte input block.
void hash(const char block[BLOCK_SIZE], int data_length)
{
    extern char state[BLOCK_SIZE]; // Internal state of the hash function, also the final hash value.
    extern int debug;

    // add padding to state if needed
    if (data_length < BLOCK_SIZE) // is the data smaller than the block size?
    {
        for (int i = data_length; i < BLOCK_SIZE; i++) // for each byte in the block after the data
        {
            if (i == BLOCK_SIZE - 1) // is this last byte?
            {
                state[i] ^= data_length & 0xFF; // xor the state with the data length
            }
            else // Not last byte
            {
                state[i] = 0; // Pad with zeros
            }
        }
    }

    // Rounds
    for (int round_i = 0; round_i < ROUNDS; round_i++)
    {
        if (ENABLE_SBOX)
        {
            // S-box-logic
            // xor the state with the sbox
            for (int i = 0; i < BLOCK_SIZE; i += 2)
            {
                uint8_t h_byte = state[i];
                uint8_t l_byte = state[i + 1];
                uint16_t word = (state[i] << 8) | state[i + 1];
                uint8_t h_sbox_byte = sbox[word];
                uint8_t l_sbox_byte = sbox[word + 1];
                state[i] = h_sbox_byte;
                state[i + 1] = l_sbox_byte;
            }

            if (debug)
            {
                printf("S-box:       ");
                print_state();
            }
        }

        if (ENABLE_PERMUTATION)
        {
            // Permutation-logic
            // Shuffle state with the permutation table
            for (int i = 0; i < BLOCK_SIZE; i++)
            {
                state[i] ^= state[permutation[i] % BLOCK_SIZE];
            }

            if (debug)
            {
                printf("Permutation: ");
                print_state();
            }
        }

        if (ENABLE_ROUND_KEY)
        {
            // Round key-logic
            // xor the state with the round key
            for (int i = 0; i < BLOCK_SIZE; i++)
            {
                state[i] ^= round_key_store[round_i][i];
            }

            if (debug)
            {
                printf("Round key:   ");
                print_state();
            }
        }

        // Finalization-logic
        // xor the the state with the current block
        for (int i = 0; i < BLOCK_SIZE; i++)
        {
            // state[i] ^= block[i];
            // double temp = pow(state[i], block[i]);
            // state[i] = (char)temp % 256;

            state[i] ^= block[i];
        }

        if (debug)
        {
            printf("Finalized:   ");
            print_state();
            printf("-------------\n");
        }
    }
}

// MAIN FUNCTION
int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        printf("Usage: %s [-d] [-r] [-s] [-f filename | data]\n", argv[0]);
        return 1;
    }

    extern char state[BLOCK_SIZE];
    extern int debug;
    extern int progress_enabled;
    int random_mode = 0;
    int read_from_file = 0;
    char data[BLOCK_SIZE] = {0};
    int data_length = 0;
    FILE *file = NULL;

    // Parse arguments
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-d") == 0)
        {
            // Enable debug mode
            debug = 1;
        }
        else if (strcmp(argv[i], "-r") == 0)
        {
            // Enable random generator mode
            random_mode = 1;
        }
        else if (strcmp(argv[i], "-p") == 0)
        {
            // Enable random generator mode
            progress_enabled = 1;
        }
        else if (strcmp(argv[i], "-f") == 0)
        {
            if (i + 1 < argc)
            {
                // Read data from a file
                i++;
                file = fopen(argv[i], "r");
                if (file == NULL)
                {
                    perror("Failed to open file");
                    return 1;
                }
                read_from_file = 1;
            }
            else
            {
                printf("Usage: %s [-d] [-r] [-f filename | data]\n", argv[0]);
                return 1;
            }
        }
    }

    // Generate round keys from master key
    // Parse substitution and permutation tables from input strings
    generate_keys();

    // PRNG-mode
    if (random_mode && argc < 3)
    {
        printf("Note: use random mode with seed data on the command line.\n");
        return 1;
    }

    // Read data from file
    if (read_from_file)
    {
        // Get file size
        fseek(file, 0L, SEEK_END);    // Go to end of file
        long file_size = ftell(file); // Get file size
        fseek(file, 0L, SEEK_SET);    // Reset file pointer to beginning of file

        // Calculate number of blocks to be processed
        int n_blocks = ceil((double)file_size / BLOCK_SIZE);
        int n_blocks_processed = 0;

        time_t start_time = time(NULL);
        time_t last_print_time = time(NULL);

        // Read data from the file
        char ch;
        while (fread(&ch, 1, 1, file) == 1)
        {
            data[data_length] = ch;
            data_length++;

            if (data_length == BLOCK_SIZE)
            {
                if (debug)
                {
                    printf("INPUT:       ");
                    print_data(data);
                    printf("\n");
                }
                hash(data, data_length); // Hash the block
                if (debug)
                {
                    printf("OUTPUT:      ");
                    print_state();
                    printf("\n");
                }
                data_length = 0;
                n_blocks_processed++;

                if (progress_enabled)
                {
                    // Print progress
                    time_t current_time = time(NULL);
                    if (time(NULL) - last_print_time > 0)
                    {
                        print_progress(n_blocks_processed, n_blocks, start_time);
                        last_print_time = time(NULL);
                    }
                }
            }
        }
    }

    // Read data from command line
    else
    {
        // Process the data in BLOCK_SIZE-byte blocks from command line arguments
        for (int i = 1; i < argc; i++) // Go through all arguments
        {
            // Skip option arguments, process only input data
            if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "-r") == 0 || strcmp(argv[i], "-f") == 0)
            {
                continue;
            }

            // argv[i] now has the input data
            char *input_data = argv[i];                 // Pointer to the input data
            int input_data_length = strlen(input_data); // Length of the input data
            for (int k = 0; k < REPEAT_CYCLES; k++)     // Process data more than once, to make sure that changes in last blocks are propagated properly
            {
                for (int j = 0; j < input_data_length; j++) // Go through all bytes in the input data
                {
                    data[data_length] = input_data[j]; // Copy the byte to the data buffer
                    data_length++;                     // Increment the data length

                    if (data_length == BLOCK_SIZE) // Do we have a full block?
                    {

                        if (debug)
                        {
                            printf("INPUT:       ");
                            print_data(data);
                            printf("\n");
                        }
                        hash(data, data_length); // Hash the block
                        if (debug)
                        {
                            printf("OUTPUT:      ");
                            print_state();
                            printf("\n");
                        }
                        data_length = 0;                     // Block has been hashed, reset data length
                        for (int i = 0; i < BLOCK_SIZE; i++) // Clear the data buffer, so that last block does not contain repeated data
                        {
                            data[i] = 0;
                        }
                    }
                }
            }
        }
    }

    // Pad and hash the last block that did not reach BLOCK_SIZE
    if (data_length > 0)
    {
        if (debug)
        {
            printf("LAST BLOCK:  ");
            print_data(data);
            printf("\n");
        }
        hash(data, data_length); // Hash the last block
    }

    // Close input file
    if (read_from_file)
    {
        fclose(file);
    }

    if (debug)
    {
        printf("--- FINAL HASH ---\n");
        print_state();
        printf("");
    }

    // Print the final hash
    print_emojis(random_mode);

    return 0;
}