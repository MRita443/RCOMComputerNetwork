/**      (C)2000-2021 FEUP
 *       tidy up some includes and parameters
 * */

#include <download.h>

int control_socket;
int data_socket;

int openSocket(char *server_ip, unsigned int server_port, int sockfd)
{
    struct sockaddr_in server_addr;

    /*server address handling*/
    bzero((char *)&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(server_ip); /*32 bit Internet address network byte ordered*/
    server_addr.sin_port = htons(server_port);          /*server TCP port must be network byte ordered */

    /*open a TCP socket*/
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("socket()");
        exit(-1);
    }

    /*connect to the server*/
    if (connect(sockfd,
                (struct sockaddr *)&server_addr,
                sizeof(server_addr)) < 0)
    {
        perror("connect()");
        exit(-1);
    }
    return 1;
}

void getServerResponse(struct serverResponse *response)
{
    memset(&response, 0, sizeof(response));

    unsigned int state = ST_READING_CODE;
    unsigned char currByte;
    unsigned char buffer[3];

    unsigned char psvServerInfo[11];
    unsigned char ip1, ip2, ip3, ip4;
    unsigned short port1, port2;

    unsigned char idx = 0;

    while (state != ST_END)
    {
        if (read(control_socket, &currByte, 1) < 0)
        {
            perror("read() server response");
            exit(-1);
        }

        switch (state)
        {
        case ST_READING_CODE:
            if (currByte == ' ' || currByte == '-')
            {
                sscanf(buffer, "%d", &response->code);
                if (response->code == SERVER_ENTER_PSV)
                    state = ST_PARSE_START;
                else if (currByte == ' ')
                    state = ST_FLUSH_SINGLE;
                else
                    state = ST_FLUSH_MULT;
            }
            else
                buffer[idx++] = currByte;
            break;
        case ST_FLUSH_SINGLE:
            if (currByte == '\n')
                state = ST_END;
            break;
        case ST_FLUSH_MULT:
            if (currByte == '\n')
            {
                idx = 0;
                state == ST_READING_CODE;
            }
            break;
        case ST_PARSE_START:
            if (currByte == '(')
            {
                idx = 0;
                state = ST_PARSE;
            }
            break;
        case ST_PARSE:
            if (currByte == ')')
                sscanf(psvServerInfo, "%d,%d,%d,%d,%d,%d", &ip1, &ip2, &ip3, &ip4, &port1, &port2);
            else
                psvServerInfo[idx++] = currByte;
            break;
        case ST_END:
            break;
        }
    }

    if (response->code == SERVER_ENTER_PSV)
    {
        spritnf(response->server_ip, "%d.%d.%d.%d", ip1, ip2, ip3, ip4);
        response->code = 256 * port1 + port2;
    }
}

int getIP(char *hostName, char *ip)
{
    struct hostent *h;

    /**
    * The struct hostent (host entry) with its terms documented

    struct hostent {
        char *h_name;    // Official name of the host.
        char **h_aliases;    // A NULL-terminated array of alternate names for the host.
        int h_addrtype;    // The type of address being returned; usually AF_INET.
        int h_length;    // The length of the address in bytes.
        char **h_addr_list;    // A zero-terminated array of network addresses for the host.
        // Host addresses are in Network Byte Order.
    };

    #define h_addr h_addr_list[0]	The first address in h_addr_list.
    */

    if ((h = gethostbyname(hostName)) == NULL)
    {
        herror("gethostbyname()");
        exit(-1);
    }

    printf("Host name  : %s\n", h->h_name);
    printf("IP Address : %s\n", inet_ntoa(*((struct in_addr *)h->h_addr_list[0])));

    strcpy(ip, inet_ntoa(*((struct in_addr *)h->h_addr_list[0])));

    return 0;
}

void parseURl(char *url, struct urlInfo *information)
{
    regex_t urlUsernamePassword;
    regex_t urlUsername;
    regex_t urlNoUser;
    regex_t ip;

    regcomp(&urlUsernamePassword, REGEX_URL_USERNAME_PASSWORD, REG_NEWLINE);
    regcomp(&urlUsername, REGEX_URL_USERNAME, REG_NEWLINE);
    regcomp(&urlNoUser, REGEX_URL_NO_USER, REG_NEWLINE);
    regcomp(&ip, REGEX_IP, REG_NEWLINE);

    if (regexec(&urlUsernamePassword, url, 0, NULL, 0) == 0) // ftp://<user>:<password>@<host>/<url-path>
    {
        sscanf(url, "%*[^/]//%[^:]", information->user);
        sscanf(url, "%*[^/]//%*[^:]%[^@]", information->password);
        sscanf(url, "%*[^@]%[^/]", information->host);
        sscanf(url, "%*[^@]%*[^/]%s", information->urlPath);
    }
    else if (regexec(&urlUsername, url, 0, NULL, 0) == 0) // ftp://<user>@<host>/<url-path>
    {
        sscanf(url, "%*[^/]//%[^@]", information->user);
        sscanf(url, "%*[^@]%[^/]", information->host);
        sscanf(url, "%*[^@]%*[^/]%s", information->urlPath);

        information->password = DEFAULT_PASSWORD;
    }
    else if (regexec(&urlNoUser, url, 0, NULL, 0) == 0) // ftp://<host>/<url-path>
    {
        sscanf(url, "%*[^:]//%[^/]", information->host);
        sscanf(url, "%*[^:]//%*[^/]%s", information->urlPath);

        information->user = DEFAULT_USER;
        information->password = DEFAULT_PASSWORD;
    }
    else
    {
        printf("Invalid URL format\n");
        exit(-1);
    }

    if (regexec(&ip, information->host, 0, NULL, 0) == REG_NOMATCH) // Host is not an IP
    {
        char *ip;

        if (getIP(information->host, &ip) == 0)
        {
            strcpy(information->host, ip);
        }
    }

    /*
    No username, no password
    Username, no password
    Both empty

    Host with IP
    Host with name

    Host name max 255
    alfabeto upper ou lower, digitos, - , .
    ultimo char nao é - nem .

    Tem username e password: ^ftp:\/\/.*:.*@.*\/.*$

    - Username: "%*[^/]//%[^:]"
    - Pass: "%*[^/]//%*[^:]%[^@]"
    - Host: "%*[^@]%[^/]"
    - Path: "%*[^@]%*[^/]%s"

    Tem username e não password: ^ftp:\/\/[^:]*@.*\/.*$

    - Username: "%*[^/]//%[^@]"
    - Host: "%*[^@]%[^/]"
    - Path: "%*[^@]%*[^/]%s"

    Sem username e password ^ftp:\/\/[^@:]*\/.*$

    - Host: "%*[^:]//%[^/]"
    - Path: "%*[^:]//%*[^/]%s"

    Ver se é um IP ^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$
    */
}

int main(int argc, char **argv)
{

    if (argc > 1)
        printf("**** No arguments needed. They will be ignored. Carrying ON.\n");

    char buf[] = "Mensagem de teste na travessia da pilha TCP/IP\n";
    size_t bytes;

    /*send a string to the server*/
    bytes = write(sockfd, buf, strlen(buf));
    if (bytes > 0)
        printf("Bytes escritos %ld\n", bytes);
    else
    {
        perror("write()");
        exit(-1);
    }

    if (close(sockfd) < 0)
    {
        perror("close()");
        exit(-1);
    }
    return 0;
}
