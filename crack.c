/* * * * * * * * * * * * * * * * * *
 * 
 * crack.c - generates hashes 
 * produces guesses 
 * checks if passwords exit in a list
 * combination of words are created for 4 letter word
 * and 6 letter words
 * if no words are left to guess, brute force starts
 *
 */

// header files used in the program
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "sha256.h"

// global index for mode with 1 arguement
int global_index = 0;

// function delarations * * * * 

void sha_password_file_read(char *shafile, BYTE ** sha_hash_array);
void sha_password_file(char *sha_file_4, char *sha_file_6, BYTE ** sha_hash_array);
void text_password_file_read(char *passwordfile, char *shafile, BYTE ** sha_hash_array, int total_sha_strings);
void convert_to_hash(char *password, BYTE *hash);
void generate_guesses(char *word);
int get_file_size(char *file);
int get_total_string_count(int file_size);
void binary_generator(char *word, char *binary, int word_size, int arguement, int loop_value);
void capitalize_words(char *words, char *binary, int arguement, int loop_value);
void allocate_sha_array(int no_file_strings, int string_size, BYTE ** sha_hash_array);
void generate_sha_word_list(char *passwordfile);
void hash_checker(char *word, int arguement, int loop_value);
void text_file_reader(char *passwordfile, int arguement, int loop_value);
void substitution(char *word, int arguement, int loop_value);
void deletion(char *word, int arguement, int loop_value);
void insertion(char *word, int arguement, int loop_value);
void two_word_substitution(char *word, int arguement, int loop_value);
void two_word_deletion_end(char *word, int arguement, int loop_value);
void word_sorter(char *word, int arguement, int loop_value);
void word_half(char *word, int arguement, int loop_value);
void replace_characters(char *word, int arguement, int loop_value);
void free_sha_array(BYTE ** allocate_sha_array, int no_file_strings, int string_size);
void brute_force(int arguement, int loop_value);
void brute_force_6(int arguement, int loop_value);
void brute_force_4(int arguement, int loop_value);

// main function * * * *

// contains conditions 
int main(int argc, char const *argv[]) {

	// condition for arguement 1 
	if(argc == 1) {

		// initializing arguements
		int arguement = 0;
		int loop_value = 0;

		// initializing the main function to initialize mode 1
		text_file_reader("common_passwords.txt", arguement, loop_value);		

	// condition for arguement 2
	} else if (argc == 2) {

		// initializing arguments
		int arguement = argc;
		int loop_value = atoi(argv[1]);

		// initializing the main function to initialize mode 2
		text_file_reader("common_passwords.txt", arguement, loop_value);	

		// initializing brute force after all words in txt file are used
		brute_force(arguement, loop_value);	

	// condition for arguement 3
	} else if (argc == 3) {
		
		// initializing arrays for text file and hash file	
		char text_file[100] = {'\0'};
		char sha_file[100] = {'\0'};

		// copying command line values into arrays
		strncpy(text_file, argv[1], strlen(argv[1]));
		strncpy(sha_file, argv[2], strlen(argv[2]));

		// geting number of strings in 
		int sha_file_size = get_file_size(sha_file);
		int total_sha_strings = get_total_string_count(sha_file_size);

		// initializing BYTE array and allocating space for hashes
		BYTE ** sha_hash_array = (BYTE **)malloc(total_sha_strings * sizeof(BYTE *));
		allocate_sha_array(total_sha_strings, 32, sha_hash_array);

		// reading password and text files
		sha_password_file_read(sha_file, sha_hash_array);
		text_password_file_read(text_file, sha_file, sha_hash_array, total_sha_strings);

		// freeing BYTE array
		free_sha_array(sha_hash_array, total_sha_strings, 32);

	// printing error if more arguments found	
	} else {

		printf("Error arguments more than 2!\n");
		exit(EXIT_FAILURE);
	}
	
	return 0;
}

// reading all hash files and allocating them to hash array
void sha_password_file(char *sha_file_4, char *sha_file_6, BYTE ** sha_hash_array) {
	
	// initializing variables
	BYTE *shahash = (BYTE *)malloc(SHA256_BLOCK_SIZE * sizeof(BYTE));
	int string_count = 0;
	FILE *file_4;
	FILE *file_6;
	
	// assigning file variables
	file_4 = fopen (sha_file_4, "rb");
	file_6 = fopen (sha_file_6, "rb");
	
	// condition for password file 4
	if(file_4) {

		// read password file for 4 digit passwords into hash array
		while(fread(shahash, 1, SHA256_BLOCK_SIZE, file_4) > 0) {

			for (int i = 0;  i < SHA256_BLOCK_SIZE; i++) {

				sha_hash_array[string_count][i] = shahash[i];		
				
			}

			string_count++;

		}

		// close file
		fclose (file_4);

    // printing error if file not found 
	} else {

		perror("File does not exist!");
		exit(EXIT_FAILURE);
	} 

	// condition for password file 6
	if(file_6) {

		// read password file for 6 digit passwords into hash array
		while(fread(shahash, 1, SHA256_BLOCK_SIZE, file_6) > 0) {

			for (int i = 0;  i < SHA256_BLOCK_SIZE; i++) {

				sha_hash_array[string_count][i] = shahash[i];	

			}

			string_count++;

		}

		// close file
		fclose (file_6);

    // printing error if file not found
	} else {

		perror("File does not exist!");
		exit(EXIT_FAILURE);
	} 

	// free array
	free(shahash);
}

// reading a single hash file 
void sha_password_file_read(char *shafile, BYTE ** sha_hash_array) {

	// initializing variables 
	BYTE *shahash = (BYTE *)malloc(SHA256_BLOCK_SIZE * sizeof(BYTE));
	int string_count = 0;
	FILE *file;

	// assigning file variables
	file = fopen (shafile, "rb");

	// condition for password file
	if(file) {

		// read password file and add hashes into array
		while(fread(shahash, 1, SHA256_BLOCK_SIZE, file) > 0) {
			
			for (int i = 0;  i < SHA256_BLOCK_SIZE; i++) {
				
				sha_hash_array[string_count][i] = shahash[i];		

			}
			
			string_count++;

		}

    	// close file
		fclose (file);

	// printing error if file not found
	} else {

		perror("File does not exist!");
		exit(EXIT_FAILURE);
	} 

	// free array
	free(shahash);
}

// convert words from password files to hash
void convert_to_hash(char *password, BYTE *hash) {
	SHA256_CTX ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, (BYTE *) password, strlen(password));
	sha256_final(&ctx, hash);
}

// read files, convert to hash, compare if hash and if the match exist, print them
void text_password_file_read(char *passwordfile, char *sha_file, BYTE ** sha_hash_array, int total_sha_strings) {

	// initialize variables 
	char word[20] = {'\0'};
	BYTE *hash = (BYTE *)malloc(SHA256_BLOCK_SIZE * sizeof(BYTE));
	FILE *file;

	// open file
	file = fopen (passwordfile, "r");

	// if file exits, then enter
	if(file) {

		// read file
		while((fgets(word, 20, file)) != NULL) {
			
			strtok(word, "\n");
			
			// convert word to hash
			convert_to_hash(word, hash);

			// read hashes
			for (int i = 0; i < total_sha_strings; i++) {
				
				// word exists, print it with index					
				if(memcmp(hash, sha_hash_array[i], SHA256_BLOCK_SIZE) == 0) {

					if(!strncmp(sha_file, "pwd4sha256", 10)) {

						printf("%s %d\n", word, i + 1);

					} else if (!strncmp(sha_file, "pwd6sha256", 10)) {
						
						printf("%s %d\n", word, i + 11);

					} else {
						
						printf("%s %d\n", word, i + 1);
					}
					
				}
			}
			
		}
		// close file
		fclose (file);

	// print error if file not found
	} else {

		perror("File does not exist");
		exit(EXIT_FAILURE);
	} 

	// free array
	free(hash);
} 

// obtains file size
// code inspired from stackoverflow
// https://stackoverflow.com/questions/238603/how-can-i-get-a-files-size-in-c
int get_file_size(char *any_file) {

	if(any_file) {

		struct stat st;
		stat(any_file, &st);
		int file_size = st.st_size;
		
		return file_size;

	} else {
		
		return 0;
	}
	
}	

// get total number of strings in password file
int get_total_string_count(int file_size) {
	
	return file_size/SHA256_BLOCK_SIZE;
}

// allocate BYTE 2D array
void allocate_sha_array(int no_file_strings, int string_size, BYTE ** sha_hash_array) {

	for (int i = 0; i < no_file_strings; i++) {
		
		sha_hash_array[i] = (BYTE *)malloc(string_size * sizeof(BYTE));

	}

}

// free 2D array 
void free_sha_array(BYTE ** sha_hash_array, int no_file_strings, int string_size) {

	for (int i = 0; i < no_file_strings; i++) {

		free(sha_hash_array[i]);
	}
	// free hash array
	free(sha_hash_array);

}

// generate binary recursively to capatilize words
// code inspired from stackoverflow
// https://stackoverflow.com/questions/16150641/how-can-i-generate-4-bit-binary-combination-using-recursion-in-c-for-0-1
void binary_generator(char *word, char *binary, int word_size, int arguement, int loop_value) {
	
	int binary_length = strlen(binary);
	if(word_size > 0) {
		binary[binary_length - word_size] = '0';
		binary_generator(word, binary, word_size - 1, arguement, loop_value);
		binary[binary_length - word_size] = '1';
		binary_generator(word, binary, word_size - 1, arguement, loop_value);
	} else {

		// sending binary to capitalize words function to capitalize words
		capitalize_words(word, binary, arguement, loop_value);
	}
}

// function to capitalize words
void capitalize_words(char *word, char *binary, int arguement, int loop_value) {

	int size = 0;
	size = strlen(word);
	char temp[20] = {'\0'};
	strncpy(temp, word, size);
	for(int i = 0; i < size; i++) {
		char character = binary[i];
		if(character == '1') {

			// only capitalize alphabets
			if((temp[i] >= 'a') && (temp[i] <='z')){

				temp[i] -= 32;

				hash_checker(temp, arguement, loop_value);
			}	
		} 
	}
	
}

// substituting single character in word
void substitution(char *word, int arguement, int loop_value) {

	int word_length = strlen(word);
	char new_word[20] = {'\0'};

	// Set the string with '\0'
	memset(new_word, '\0', word_length + 1);
	strcpy(new_word, word);

	// running loop from ascii 32 to 127
	for(int i = 0; i < word_length; i++) {
		for(int j = 32; j < 127; j++) {
			new_word[i] = j;
			char another_word[20] = {'\0'};
			strcpy(another_word, new_word);

			// passing the original word to check with hashes
			hash_checker(another_word, arguement, loop_value);

			// passing the original word to also capitalize them
			if(strlen(another_word) == 4) {
				char binary_string[] = "0000";
				binary_generator(another_word, binary_string, 4, arguement, loop_value);
			}

			strcpy(new_word, word);
		}
	}

}

// deleting a word for 5 character strings to make 4 character strings
void deletion(char *word, int arguement, int loop_value) {
	
	int word_length = strlen(word);
	char new_word[20] = {'\0'};

	// Set the string with '\0'
	memset(new_word, '\0', word_length);

	strcpy(new_word, word);

	// running loop from ascii 32 to 127
	for(int i = 0; i < word_length; i++) {
		// String function from C library
		// Moves one character in the previous position
		memmove(&new_word[i], &new_word[i + 1], word_length - i);
		char another_word[20] = {'\0'};
		strcpy(another_word, new_word);
		
		// passing the original word to check with hashes
		hash_checker(another_word, arguement, loop_value);

		// passing the original word to also capitalize them
		if(strlen(another_word) == 6) {
			char binary_string[] = "000000";
			binary_generator(another_word, binary_string, 6, arguement, loop_value);
		}

		strcpy(new_word, word);
	}
}

// inserting a word in 5 character strings to make 6 character strings 
void insertion(char *word, int arguement, int loop_value) {

	int word_length = strlen(word);
	char new_word[20] = {'\0'};

	// Set the string with '\0'
	memset(new_word, '\0', word_length + 2); // Set the string with '\0'
	
	int position = 0;
	strcpy(new_word, word);

	// shift position and insert a word
	for(int i = 0; i <= word_length; i++) {
		for(int j = word_length - 1 ; j >= position; j--) {
			new_word[j + 1] = new_word[j];
		}

		// running loop from ascii 32 to 127
		for(int k = 32; k < 127; k++) {
			new_word[position] = k;
			char another_word[12] = {'\0'};

			strcpy(another_word, new_word);
			
			// passing the orginal word to check with hashes
			hash_checker(another_word, arguement, loop_value);
		}

		strcpy(new_word, word);

		position++; 
		
	}
}

// deleting two characters in the end of 8 character and 6 character words
// to make 4 and 6 character words
void two_word_deletion_end(char *word, int arguement, int loop_value) {
	
	int word_length = strlen(word); 
	char another_word[20] = {'\0'};

	strncpy(another_word, word, word_length - 2); 
	
	hash_checker(another_word, arguement, loop_value);
	
}

// cut 8 character strings to 4 character strings
void word_half(char *word, int arguement, int loop_value) {
	
	char another_word[20] = {'\0'};
	strncpy(another_word, word, 4); 

	hash_checker(another_word, arguement, loop_value);

}

// replace characters at specific places
void replace_characters(char *word, int arguement, int loop_value) {
	
	int word_length = strlen(word);
	char another_word[20] = {'\0'};

	// replace only once
	for(int i = 0; i < word_length; i++) {
		if(word[i] == 'e') {
			word[i] = 'w';
			word[i + 2] = 'i';
			strncpy(another_word, word, word_length);
			hash_checker(another_word, arguement, loop_value);
			
			break; 
		}
	}
	
}

// check if hash exists. if it does then print out word
void hash_checker(char *word, int arguement, int loop_value) {

	// if argument 2 has been entered, print out the word directly
	if(arguement == 2) {

		if(global_index < loop_value) {

			printf("%s\n", word);
			
			global_index++;

		} else {
			exit(0);
		}
	// else compare the words with hashes and print	
	} else {

		strtok(word, "\n");	

		// initialize and allocate variables
		char sha_file_4[] = "pwd4sha256";
		char sha_file_6[] = "pwd6sha256";
		int sha_file_size_4 = get_file_size(sha_file_4);
		int total_sha_strings_4 = get_total_string_count(sha_file_size_4);
		int sha_file_size_6 = get_file_size(sha_file_6);
		int total_sha_strings_6 = get_total_string_count(sha_file_size_6);
		int total_sha_strings = total_sha_strings_4 + total_sha_strings_6;
		BYTE ** sha_hash_array = (BYTE **)malloc(total_sha_strings * sizeof(BYTE *));
		allocate_sha_array(total_sha_strings, 32, sha_hash_array);

		sha_password_file(sha_file_4, sha_file_6, sha_hash_array);

		BYTE *hash = (BYTE *)malloc(SHA256_BLOCK_SIZE * sizeof(BYTE));

		// convert words to hashes
		convert_to_hash(word, hash);

		// compare and print hash arrays
		for (int i = 0; i < total_sha_strings; i++) {

			if(memcmp(hash, sha_hash_array[i], SHA256_BLOCK_SIZE) == 0) {

				printf("%s %d\n", word, i + 1);
				
			}
		}

		// free hash arrays
		free(hash);
		free_sha_array(sha_hash_array, total_sha_strings, 32);
	}

}

// function to read text file and pass words to the word sorter that sort 
// words based on string length
void text_file_reader(char *passwordfile, int arguement, int loop_value) {	

	// initializing variables
	char word[20] = {'\0'};
	FILE *file;
	file = fopen (passwordfile, "r");

	if(file) {

		while((fgets(word, 20, file)) != NULL) {
			strtok(word, "\n");	

			// passing words to word sorter
			word_sorter(word, arguement, loop_value);
			bzero(word, 20);
		}

		// closing file
		fclose (file);

	} else {

		perror("File does not exist!");
		exit(EXIT_FAILURE);
	} 
	
}

// sorting words based on string length
void word_sorter(char *word, int arguement, int loop_value) {

	int word_length = strlen(word);

	// for word length 4
	if(word_length == 4) {

		// functions applied to 4 letter words
		hash_checker(word, arguement, loop_value);
		char binary_string[] = "0000";
		binary_generator(word, binary_string, 4, arguement, loop_value);
		substitution(word, arguement, loop_value);
		replace_characters(word, arguement, loop_value);

	// for word length 5	
	} else if(word_length == 5) {

		// functions applied to 5 letter words
		deletion(word, arguement, loop_value);
		insertion(word, arguement, loop_value);

	// for word length 6
	} else if(word_length == 6) {
		
		// functions applied to 6 letter words
		hash_checker(word, arguement, loop_value);
		char binary_string[] = "000000";
		binary_generator(word, binary_string, 6, arguement, loop_value);
		substitution(word, arguement, loop_value);

	// for word length 7
	} else if(word_length == 7) {
		
		// functions applied to 7 letter words
		deletion(word, arguement, loop_value);

	// for word length 8
	} else if(word_length == 8) {

		// functions applied to 8 letter words
		two_word_deletion_end(word, arguement, loop_value);
		word_half(word, arguement, loop_value);

	}

}

// initiates brute force
void brute_force(int arguement, int loop_value) {

	// initiates brute force for 4 letter words
	brute_force_4(arguement, loop_value);

	// initiates brute force for 6 letter words
	brute_force_6(arguement, loop_value);
}

// brute for 4 letter words
void brute_force_4(int arguement, int loop_value) {
	char word[20] = {'\0'};

	// creating every word combination from ascii 32 to 127
	for(int a = 32; a < 127; a++) {
		for(int b = 32; b < 127; b++) {
			for(int c = 32; c < 127; c++) {
				for (int d = 32; d < 127; d++) {
					sprintf(word, "%c%c%c%c",a,b,c,d);
					hash_checker(word, arguement, loop_value);
				}
			}
		}
	} 
}

// brute for 6 letter words
void brute_force_6(int arguement, int loop_value) {

	// creating every word combination from ascii 32 to 127
	char word[20] = {'\0'};
	for(int a = 32; a < 127; a++) {
		for(int b = 32; b < 127; b++) {
			for(int c = 32; c < 127; c++) {
				for (int d = 32; d < 127; d++) {
					for (int e = 32; e < 127; e++) { 
						for (int f = 32; f < 127; f++) {
							sprintf(word, "%c%c%c%c%c%c",a,b,c,d,e,f);
							hash_checker(word, arguement, loop_value);
						}
						
					}
				}
			}
		}
	} 
}


