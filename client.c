#include <termios.h>
#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <mcrypt.h>
#include <math.h>
#include <getopt.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netdb.h>
#define BUF_SIZE 4096

char* buffer;
struct termios saved_terminal_attributes;
int log_flag = 0;
int crypt_flag = 0;
int port_num;
char* log_buf;
int log_fd;
int socketfd;
pthread_t thread_id;
int key_len;
ssize_t size;
int keyfd;
char* IV = "AAAAAAAAAAAAAAAA";
int keysize = 16; /* 128 bits */
int buffer_len = 16;
char *key = "0123456789";

int encrypt(
    void* buffer,
    int buffer_len,
    char* IV, 
    char* key,
    int key_len 
){
  MCRYPT td = mcrypt_module_open("blowfish", NULL, "ofb", NULL);
  int blocksize = mcrypt_enc_get_block_size(td);
  if( buffer_len % blocksize != 0 ){return 1;}

  mcrypt_generic_init(td, key, key_len, IV);
  mcrypt_generic(td, buffer, buffer_len);
  mcrypt_generic_deinit (td);
  mcrypt_module_close(td);
  
  return 0;
}

int decrypt(
    void* buffer,
    int buffer_len,
    char* IV, 
    char* key,
    int key_len 
){
  MCRYPT td = mcrypt_module_open("blowfish", NULL, "ofb", NULL);
  int blocksize = mcrypt_enc_get_block_size(td);
  if( buffer_len % blocksize != 0 ){return 1;}
  
  mcrypt_generic_init(td, key, key_len, IV);
  mdecrypt_generic(td, buffer, buffer_len);
  mcrypt_generic_deinit (td);
  mcrypt_module_close(td);
  
  return 0;
}


char* get_key(char *filename){
	char *hello = NULL;
	size_t ssize = 0;
	FILE *fp = fopen(filename, "r");
	fseek(fp, 0, SEEK_END);
	ssize = ftell(fp);
	rewind(fp);
	hello = malloc((ssize + 1) * sizeof(*hello));
	fread(hello, ssize, 1, fp);
	hello[size] = '\0';
	return hello;
}





void reset_input_mode(){
	tcsetattr(STDIN_FILENO, TCSANOW, &saved_terminal_attributes);
}


void connection(int file1, int file2, int process){

	int buffer1 = 0;
	char buffer[BUF_SIZE]={};

	size = read(file1, buffer, 1);
	if(size == 0) {
		write(socketfd, "0", 1);
		close(socketfd);
		exit(1);
	}

	while(size)
	{
		if(crypt_flag && !process) {
			decrypt(buffer + buffer1, buffer_len, IV, key, keysize);
		}

		if(process && *(buffer + buffer1) != '\r' && *(buffer+ buffer1) != '\n') {
			write(STDOUT_FILENO, buffer+buffer1,1); 
		}

		if(log_flag)  { 
			if(process){
				char log_msg[BUF_SIZE] = {};
				int log_msg_size = sprintf(log_msg, "SENT %d BYTES: %s\n", (int) size, buffer);
				write(log_fd, log_msg, log_msg_size);
			}
			else
			{
				char log_msg[BUF_SIZE] = {};
				int log_msg_size = sprintf(log_msg, "RECEIVED %d BYTES: %s\n", (int) size, buffer);
				write(log_fd, log_msg, log_msg_size);

			}


		}

		if(*(buffer + buffer1) == '\004' && process) { 
			pthread_cancel(thread_id);
			close(socketfd);
			exit(0);
		}

		if(*(buffer + buffer1) == '\003' && process) { 
			pthread_cancel(thread_id);
			close(socketfd);
			exit(1);
		}

		if(*(buffer + buffer1) == '\r' || *(buffer+ buffer1) == '\n') 
		{
			char temp_buff[BUF_SIZE] = {};
			temp_buff[1]= 0x0A;
			temp_buff[2] = 0;

			if(!process)
			{
				write(file2, temp_buff, 2);
			}
			else
			{
				write(STDOUT_FILENO, temp_buff, 2);
				write(file2, temp_buff + 1, 1);
			} 

			size = read(file1, buffer,1);
			if(size == 0) { 

					write(socketfd, "0", 1);
					close(socketfd);
					exit(1); 

			}

			buffer1 = 0;
			continue;
		}

		write(file2,buffer+buffer1,1);
		buffer1++;

		size = read(file1, buffer + buffer1,1);

		if(size == 0) { 
				write(socketfd, "0", 1);
				close(socketfd);
				exit(1); 
		}

	}
}


void* fork_parent(void* sock_fd)
{
	connection(*(int *)sock_fd, STDOUT_FILENO,0);
	return 0;
}

int main(int argc, char **argv)
{

	struct termios config_terminal_state;
	struct sockaddr_in server_addr;
	struct hostent* server;

	int c = 0;

	static struct option long_opts[] =
	{
		{"port", required_argument, 0, 'p'},
		{"log", required_argument, 0, 'l'},
		{"encrypt", no_argument, 0, 'e'},
		{0, 0, 0, 0},

	};

	while((c = getopt_long(argc,argv,"",long_opts,NULL)) != -1){
		switch(c){
			case 'p':
				port_num = atoi(optarg);
				break;
			case 'l':
				log_buf = optarg;
				log_flag = 1;
				log_fd = creat(log_buf, S_IRWXU);
				break;
			case 'e':
				crypt_flag = 1;
				break;
			default:
				break;
		}
	}

	//Make terminal non-canonical mode
	tcgetattr(STDIN_FILENO, &saved_terminal_attributes);
	atexit(reset_input_mode);
	tcgetattr(STDIN_FILENO, &config_terminal_state);
	config_terminal_state.c_lflag &= ~(ECHO | ICANON);
	config_terminal_state.c_cc[VMIN] = 1;
	config_terminal_state.c_cc[VTIME] = 0;
	tcsetattr(STDIN_FILENO, TCSANOW, &config_terminal_state);

	//Socket starts here
	socketfd = socket(AF_INET, SOCK_STREAM, 0);
	if(socketfd < 0) { 
		perror("error can not open socket"); 
		exit(0); 
	}

	server = gethostbyname("localhost");

	if(server == NULL) { 
		fprintf(stderr, "can not find host"); 
		exit(0); 
	}

	memset((char*) &server_addr,0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	memcpy((char *) &server_addr.sin_addr.s_addr, (char*) server->h_addr, server->h_length);
	server_addr.sin_port = htons(port_num);

	connect(socketfd,(struct sockaddr *) &server_addr, sizeof(server_addr));

	pthread_create(&thread_id, NULL, fork_parent, &socketfd);

	connection(STDIN_FILENO, socketfd,1);

	exit(0);
}