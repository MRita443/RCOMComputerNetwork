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


struct serverResponse
{
    unsigned short int code;
    char *server_ip;
    unsigned short int server_port;
};

struct urlInfo
{
    char *user;
    char *password;
    char *host;
    char *urlPath;
};

#define SERVER_PORT 6000
#define SERVER_ADDR "192.168.28.96"

// Server Response Codes
#define SERVER_ENTER_PSV 227

// State machine states
#define ST_READING_CODE 0
#define ST_PARSE_START 1
#define ST_PARSE 2
#define ST_FLUSH_MULT 3
#define ST_FLUSH_SINGLE 4
#define ST_END 5

// Regexs for parsing URL
#define REGEX_URL_USERNAME_PASSWORD "^ftp:\/\/.*:.*@.*\/.*$"
#define REGEX_URL_USERNAME "^ftp:\/\/[^:]*@.*\/.*$"
#define REGEX_URL_NO_USER "^ftp:\/\/[^@:]*\/.*$"
#define REGEX_IP "^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$"

// Default authentication parameters
#define DEFAULT_USER "anonymous"
#define DEFAULT_PASSWORD "anonymous"

#endif