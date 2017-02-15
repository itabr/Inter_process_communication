#include <stdio.h>
#include <string.h>
#include <mcrypt.h>
#include <pthread.h>
#include <getopt.h>
#include <unistd.h>
#include <math.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <sys/socket.h>
#define BUF_SIZE 4096

char buffer[BUF_SIZE]; 
//pipes used for the chlid and parent to the shell (pipe 1) and from the shell (pipe 2)
int pipe1[2];
int pipe2[2];
int socketfd; 
int n_socketfd;
pid_t pid;
pthread_t thread_id;
int crypt_flag = 0;
ssize_t size;
int li_len;
FILE *keyfd;
int key_len;

char* IV = "AAAAAAAAAAAAAAAA";
char* key = "0123456789";
int keysize = 16; /* 128 bits */
int buffer_len = 16;


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

void connection(int read_fd, int write_fd, int socket_flag)
{
	int size_check = 0;
	size = read(read_fd, buffer, 1);

	if(size == 0) { 
		// close everything
			close(0);
			close(1);
			close(2);
			close(pipe1[1]);
			close(pipe2[0]);
			close(socketfd);

			kill(pid, SIGKILL);
			if(socket_flag) { 
				exit(1); 
			}
			else { 
				pthread_cancel(thread_id);
				exit(2); 
			}
	}

	while(size)
	{

		if(crypt_flag && !socket_flag) {
			key = "0123456789";
			encrypt(buffer, buffer_len, IV, key, keysize);
		}

		write(write_fd,buffer,1);

		size_check++;

		size = read(read_fd, buffer ,1);

		if(size == 0) {
			// close everything
		 	close(0);
			close(1);
			close(2);
			close(pipe1[1]);
			close(pipe2[0]);
			close(socketfd);

			kill(pid, SIGKILL);
			if(socket_flag) { 
				exit(1); 
			}
			else { 
				pthread_cancel(thread_id);
				exit(2); 
			}
		}


	}
}
// child calles fork_child and create the shell
void fork_child(){

  execlp("/bin/bash", "/bin/bash",NULL);
}

//fork_parent write from shell to client socket 
void* fork_parent(){
	connection(pipe2[0],1, 0);
	return 0;
}

int main(int argc, char **argv){

	int c = 0;
	int port_num;
	socklen_t client_len;

	struct sockaddr_in server_addr;
	struct sockaddr_in client_addr;
	static struct option long_opts[] =
	{
		{"port", required_argument, 0, 'p'},
		{"encrypt", no_argument, 0, 'e'},
		{0, 0, 0, 0},
	};

	while((c = getopt_long(argc, argv, "", long_opts, NULL)) != -1)
	{
		switch(c)
		{
			case 'p':
				//Grab port number
				port_num = atoi(optarg);
				break;

			case 'e':
				//Turn on Encryption
				crypt_flag = 1;
				break;

			default:
				break;
		}
	}

	//socket connection
	socketfd = socket(AF_INET, SOCK_STREAM, 0);

	if(socketfd < 0) { 
		perror("Error can not open socket"); 
		exit(1); 
	}

	memset((char*) &server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port_num);
	server_addr.sin_addr.s_addr = INADDR_ANY;

	if(bind(socketfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0){

		perror("Error can not bind socket");
		exit(1);

	}

	//Listening start here
	li_len = 5;
	listen(socketfd, li_len);
	client_len = sizeof(client_addr);

	//streaming data start here
	n_socketfd = accept(socketfd, (struct sockaddr *) &client_addr, &client_len);

	pipe(pipe1);
	pipe(pipe2);

	pid = fork();

	if(pid < 0) { 

		perror("Error forking"); exit(1); 
	}

	//child
	else if(pid == 0)	{

		close(pipe1[1]);      // Child process closes up output side of pipe 1    
        close(pipe2[0]);      // Child process closes up input side of pipe 2

		close(0);
        dup(pipe1[0]);

		close(1);
        dup(pipe2[1]);

		close(2);
        dup(pipe2[1]);

		close(pipe1[0]);
		close(pipe2[1]);

		fork_child();
	}

	//parent
	else{

		close(pipe1[0]);
		close(pipe2[1]);
		pthread_create(&thread_id, NULL, fork_parent, &n_socketfd);
	}
	//Redirect stdin/stdout/stderr to the socket

	close(0);
	dup(n_socketfd);

	close(1);
	dup(n_socketfd);

	close(2);
	dup(n_socketfd);

	close(n_socketfd);

	connection(0, pipe1[1], 1);

	exit(0);
}