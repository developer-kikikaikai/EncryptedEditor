#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "encrypt_vim.h"

#define APPNAME "encrypt_vim"

typedef void (*access_file_action_fn)(char *, char*);
extern int optind, opterr;

static void help() {
	printf("Usage: %s [-d or -e][filename]\n", APPNAME);
	printf("Description:\n");
	printf("       encrypt file and open %s editor\n", EDITORNAME);
	printf("Option:\n");
	printf("       -e  only encrypt. open file %s editor without decrypting, and write file with encrypting.\n", EDITORNAME);
	printf("       -d  only decrypt. open file %s editor with decrypting, and write file without encrypting.\n", EDITORNAME);
	exit(0);
}

int main (int argc, char **argv) {
	/*TODO: Think about options only to encrypt/decrypt file*/
	if(argc < 2) help();

	int opt=0;
	/*access file action function setting*/
	access_file_action_fn copy_swap_action = decrypt_file;
	access_file_action_fn flush_file_action = encrypt_file;

	/*disable ? error message*/
	opterr=0;
	while( (opt=getopt(argc, argv, "edh")) != -1 ){
		switch(opt) {
		case 'e':
			/*do encrypt file*/
			copy_swap_action = copy_file;
			break;
		case 'd':
			/*do decrypt file*/
			flush_file_action = copy_file;
			break;
		case 'h':
		default:
			help();
			break;
		}
	}

	/* Need 1. last option=> filename, and 2. use at most 1 option */
	if(optind + 1 != argc || (copy_swap_action == flush_file_action) ) help();

	char *fname = argv[optind];
	char *swap_fname=NULL;

	/*set swap file name*/
	if(asprintf(&swap_fname, ".swp.%s", fname) == -1) return -1;

	/*is it OK to open swap file?*/
	check_swap_file(swap_fname);
	copy_swap_action(fname, swap_fname);
	open_editor(swap_fname);
	flush_file_action(swap_fname, fname);

	/*remove tmp file*/
	unlink(swap_fname);
	free(swap_fname);
	return 0;
}
