#ifndef ENCRYPT_VIM_H_
#define ENCRYPT_VIM_H_
typedef struct file_mng {
	int fd;
	unsigned char* buf;
	long mapsize;
	long realsize;
} file_mng_t;

#define EDITORNAME "/usr/bin/vim"
void check_swap_file(char *swpfname);
void decrypt_file(char *basefile, char *decrypted_file);
void open_editor(char * decrypted_fname);
void encrypt_file(char *decrypted_file, char *basefile);
void copy_file(char *basefile, char *copyfile);
#endif/*ENCRYPT_VIM_H_*/
