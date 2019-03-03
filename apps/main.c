#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "encrypt_vim.h"

#define APPNAME "encrypt_vim"

static void help() {
	printf("Usage: %s [filename]\n", APPNAME);
	printf("       encrypt file and open %s editor\n", EDITORNAME);
	exit(0);
}

int main (int argc, char **argv) {
	/*TODO: Think about options only to encrypt/decrypt file*/
	if(argc != 2) help();

	char *fname = argv[1];
	char *decrypted_fname;
	/*set swap file name*/
	if(asprintf(&decrypted_fname, ".%s.swp", fname) == -1) return -1;

	/*is it OK to open swap file?*/
	check_swap_file(decrypted_fname);
	decrypt_file(fname, decrypted_fname);
	open_editor(decrypted_fname);
	encrypt_file(decrypted_fname, fname);

	/*remove tmp file*/
	unlink(decrypted_fname);
	free(decrypted_fname);
	return 0;
}
