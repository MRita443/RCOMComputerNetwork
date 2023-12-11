#ifndef DOWNLOAD_H
#define DOWNLOAD_H

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <regex.h>
#include <netdb.h>

struct server_response
{
    unsigned short int code;
    char server_ip[16];
    unsigned int server_port;
    char message[500];
};

struct urlInfo
{
    char user[100];
    char password[100] ;
    char host[100];
    char urlPath[100];
    char filename[100];
};

#define max(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a > _b ? _a : _b; })

#define SERVER_PORT 6000
#define SERVER_ADDR "192.168.28.96"

#define MAX_FILE_LENGTH 500

#define DEFAULT_PORT 21

// Server Response Codes
#define SERVER_ENTER_PSV 227
#define SERVER_READY_LOGIN 220
#define SERVER_LOGIN_SUCCESSFUL 230

// State machine for parsing server responses
#define ST_READING_CODE 0
#define ST_PARSE_START 1
#define ST_PARSE 2
#define ST_FLUSH_MULT 3
#define ST_FLUSH_SINGLE 4
#define ST_END 5

//State machine for RETR
#define ST_WAIT 0
#define ST_ERROR 1
#define ST_SUCCESS 2
#define ST_FAILURE 3

//State machine for login
#define ST_WAIT_USER 4
#define ST_WAIT_PASS 5
#define ST_WAIT_ACCT 6

// Regexs for parsing URL
#define REGEX_URL_USERNAME_PASSWORD "^ftp://.*:.*@.*/.*$"
#define REGEX_URL_USERNAME "^ftp://[^:]*@.*/.*$"
#define REGEX_URL_NO_USER "^ftp://[^@:]*/.*$"
#define REGEX_IP "^((25[0-5]|(2[0-4]|1[:digit:]|[1-9]|)[:digit:])\\.?\b){4}$"

// Default authentication parameters
#define DEFAULT_USER "anonymous"
#define DEFAULT_PASSWORD "anonymous"

/*
* Function that opens a socket for communication
* @param server_ip, a string containing the server ip
* @param server_port, a unsigned int containing the value of the port
* @param sockfd , an int containing the sock file descriptor
*/
void open_socket(char *server_ip, unsigned int server_port, int *sockfd);

/*
* Gets the response of the server and registers it on a passed server response
* @param response, a server response passed to save the reply of the server
*/
void get_server_response(struct server_response *response);

/*
* Gets the value of the ip based on the give host
* @param host_name, a string containing the name of the server host
* @param ip, a string containing the ip of the server
* @return an int always having the value 0
*/
int get_IP(char *host_name, char *ip);

/*
* Parses a given url to obtain the information it contains
* @param url, a string containing the url passed as a parameter for the download
* @param information, a struct that contains the fields user, pass etc for the given url
*/
void parse_URl(char *url, struct urlInfo *information);

/*
* Sends a command for the server to read and execute 
* @param instruction, a string containing the instruction given
* @param response, a struct containing the response code and, in case of 227, ip and port information
* @return an int with the value of the instruction code
*/
int send_command(char *instruction, struct server_response *response);

/*
* Requests access to a given resource
* @param resource, a string containing the url path containing the desired file
* @param response, a struct containing the response code and, in case of 227, ip and port information
* @return an int with the value of the instruction code
*/
int request_file(char *resource, struct server_response *response, char* filename);

/*
* Logs in the server
* @param user, a string containing the username information
* @param, a string containing the password information
* @return an int containing the response code
*/
int login(char *user, char *pass);

/*
* Fetches the file passed
* @param filename, a string contaning the name of the file that's going to be downloaded
*/
void get_file(char *filename);

/*
* Closes the connection to the server, closing the sockets
*/
void close_connect();
#endif
