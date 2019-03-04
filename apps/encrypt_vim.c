#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <spawn.h>
#include <sys/types.h> 
#include <sys/wait.h>
#include "encrypt_api.h"
#include "encrypt_vim.h"

#define APPNAME "encrypt_vim"
#define EDITORNAME "/usr/bin/vim"

#define ENC_ALGORITHM ENC_API_ENCRYPT_TYPE_CHACHA20_POLY1305

void check_swap_file(char *swpfname) {
	struct stat fcheck;
	if(stat(swpfname, &fcheck) != 0) {
		return;
	}

	fprintf(stderr, "There is a swap file \"%s\"!\n", swpfname);
	fprintf(stderr, "Is it OK to overwrite it? (Y/N)");
	int ch = getchar();
	if(ch != 'y' && ch != 'Y') {
		exit(0);
	}
}

static int construct_file_mng(char *fname, file_mng_t *fmng) {
	fmng->fd = open(fname, O_RDONLY);
	if(fmng->fd < 0) return -1;

	/*to get file size*/
	FILE * fp = fdopen(fmng->fd, "rb");
	if (fp == NULL) goto err;

	struct stat stbuf;//file size = stbuf.st_size
	if (fstat(fmng->fd, &stbuf) == -1) goto err;

	int page_size = getpagesize();
	fmng->realsize = stbuf.st_size;
	fmng->mapsize = (fmng->realsize/page_size + 1) * page_size;
	fmng->buf = (unsigned char*)mmap(NULL, fmng->mapsize, PROT_READ, MAP_SHARED, fmng->fd, 0);
	if(fmng->buf == MAP_FAILED) goto err;

	/*fp of fdopen has relation of fmng->fd. So the stream fp doesn't close.*/
	return 0;
err:
	/*fp of fdopen has relation of fmng->fd. So the stream fp doesn't close.*/
	close(fmng->fd);
	memset(fmng, 0, sizeof(file_mng_t));
	return -1;
}

static void destruct_file_mng(file_mng_t *fmng) {
	close(fmng->fd);
	munmap(fmng->buf, fmng->mapsize);
}
static int decrypt_buffer(file_mng_t *fmng, unsigned char **buf) {
	return enc_api_decrypt(ENC_ALGORITHM, fmng->buf, fmng->realsize, buf);
}
static int encrypt_buffer(file_mng_t *fmng, unsigned char **buf) {
	return enc_api_encrypt(ENC_ALGORITHM, fmng->buf, fmng->realsize, buf);
}
static int copy_buffer(file_mng_t *fmng, unsigned char **buf) {
	*buf = (unsigned char *)calloc(1, fmng->realsize);
	if(*buf == NULL) return 0;
	memcpy(*buf, fmng->buf, fmng->realsize);
	return (int) fmng->realsize;
}

static void output_file(char *basefile, char *outfile, int (*flush_buffer)(file_mng_t *fmng, unsigned char **buf)) {
	struct stat fcheck;
	if(stat(basefile, &fcheck) != 0) {
		return;
	}

	file_mng_t fmng;
	if(construct_file_mng(basefile, &fmng) != 0) {
		fprintf(stderr, "file %s open error\n", basefile);
		exit(0);
	}

	unsigned char *out_buf=NULL;
	int len=0;
	if(fmng.realsize) {
		len = flush_buffer( &fmng, &out_buf);
		if(len <= 0) {
			fprintf(stderr, "flush file buffer %s error\n", basefile);
			goto err;
		}
	}

	FILE *fp = fopen(outfile, "w");
	if(fp == NULL) {
		fprintf(stderr, "open file %s error\n", outfile);
		goto err;
	}

	if(fmng.realsize) {
		if(fwrite(out_buf, 1, fmng.realsize, fp)<=0) {
			fprintf(stderr, "write file %s error\n", outfile);
			goto err;
		}
	}

	fclose(fp);
	free(out_buf);
	destruct_file_mng(&fmng);
	return ;
err:
	free(out_buf);
	destruct_file_mng(&fmng);
	exit(-1);
}

void decrypt_file(char *basefile, char *decrypted_file) {
	output_file(basefile, decrypted_file, decrypt_buffer);
}

void open_editor(char * decrypted_fname) {
	pid_t pid = fork();
	if(pid==0) {
		char *args[]={
			EDITORNAME,
			decrypted_fname,
			NULL
		};
		execv(args[0], args);
	} else {
		waitpid(pid, NULL, 0);
	}
}

void encrypt_file(char *decrypted_file, char *basefile) {
	output_file(decrypted_file, basefile, encrypt_buffer);
}

void copy_file(char *basefile, char *copyfile) {
	output_file(basefile, copyfile, copy_buffer);
}
