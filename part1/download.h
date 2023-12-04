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

#endif