/**      (C)2000-2021 FEUP
 *       tidy up some includes and parameters
 * */

#include "download.h"

int control_socket;
int data_socket;

void open_socket(char *server_ip, unsigned int server_port, int *sockfd)
{
    struct sockaddr_in server_addr;

    /*server address handling*/
    bzero((char *)&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(server_ip); /*32 bit Internet address network byte ordered*/
    server_addr.sin_port = htons(server_port);          /*server TCP port must be network byte ordered */

    /*open a TCP socket*/
    if ((*sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("socket()");
        exit(-1);
    }

    /*connect to the server*/
    if (connect(*sockfd,
                (struct sockaddr *)&server_addr,
                sizeof(server_addr)) < 0)
    {
        perror("connect()");
        exit(-1);
    }
}

void get_server_response(struct server_response *response)
{
    response->code = 0;
    memset(response->message, 0, sizeof(response->message));
    memset(response->server_ip, 0, sizeof(response->server_ip));
    response->server_port = 0;

    unsigned short state = ST_READING_CODE;
    char curr_byte;
    unsigned char file_content[4];
    memset(&file_content, 0, sizeof(file_content));

    unsigned char psv_server_info[25];
    unsigned short ip1, ip2, ip3, ip4;
    unsigned short port1, port2;

    unsigned char idx = 0;
    unsigned short idx_msg = 0;

    short n;

    while (state != ST_END)
    {

        n = read(control_socket, &curr_byte, 1);

        if (n < 0)
        {
            perror("read() server response");
            exit(-1);
        }

        if (n > 0)
        {

            printf("%d\n", state);
            printf("curr_byte %c\n", curr_byte);

            switch (state)
            {
            case ST_READING_CODE:
                if (curr_byte == ' ' || curr_byte == '-')
                {
                    sscanf(file_content, "%hu", &response->code);
                    printf("Read code %hu\n", response->code);

                    if (response->code == SERVER_ENTER_PSV)
                        state = ST_PARSE_START;
                    else if (curr_byte == ' ')
                        state = ST_FLUSH_SINGLE;
                    else
                        state = ST_FLUSH_MULT;
                }
                else
                    file_content[idx++] = curr_byte;
                break;
            case ST_FLUSH_SINGLE:
                response->message[idx_msg++] = curr_byte;
                if (curr_byte == '\n')
                {
                    state = ST_END;
                }
                break;
            case ST_FLUSH_MULT:
                response->message[idx_msg++] = curr_byte;
                if (curr_byte == '\n')
                {
                    idx = 0;
                    state = ST_READING_CODE;
                }
                break;
            case ST_PARSE_START:
                response->message[idx_msg++] = curr_byte;
                if (curr_byte == '(')
                {
                    idx = 0;
                    state = ST_PARSE;
                }
                break;
            case ST_PARSE:
                response->message[idx_msg++] = curr_byte;
                if (curr_byte == ')')
                {
                    sscanf(psv_server_info, "%hu,%hu,%hu,%hu,%hu,%hu", &ip1, &ip2, &ip3, &ip4, &port1, &port2);
                    printf("READ PASV INFO\n");
                    state = ST_END;
                    printf("State %d\n", state);
                }
                else
                    psv_server_info[idx++] = curr_byte;
                break;
            case ST_END:
                break;
            }
        }
    }

    if (response->code == SERVER_ENTER_PSV)
    {
        sprintf(response->server_ip, "%hu.%hu.%hu.%hu", ip1, ip2, ip3, ip4);
        response->server_port = 256 * port1 + port2;
    }
}

int get_IP(char *host_name, char *ip)
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

    if ((h = gethostbyname(host_name)) == NULL)
    {
        herror("gethostbyname()");
        exit(-1);
    }

    strcpy(ip, inet_ntoa(*((struct in_addr *)h->h_addr_list[0])));

    return 0;
}

void parse_URl(char *url, struct urlInfo *information)
{
    regex_t url_username_password;
    regex_t url_username;
    regex_t url_no_user;
    regex_t ip;

    regcomp(&url_username_password, REGEX_URL_USERNAME_PASSWORD, REG_EXTENDED);
    regcomp(&url_username, REGEX_URL_USERNAME, REG_EXTENDED);
    regcomp(&url_no_user, REGEX_URL_NO_USER, REG_EXTENDED);
    regcomp(&ip, REGEX_IP, REG_EXTENDED);

    if (regexec(&url_username_password, url, 0, NULL, 0) == 0) // ftp://<user>:<password>@<host>/<url-path>
    {
        sscanf(url, "%*[^/]//%[^:]", information->user);
        sscanf(url, "%*[^/]//%*[^:]:%[^@]", information->password);
        sscanf(url, "%*[^@]@%[^/]", information->host);
        sscanf(url, "%*[^@]%*[^/]%s", information->urlPath);
    }
    else if (regexec(&url_username, url, 0, NULL, 0) == 0) // ftp://<user>@<host>/<url-path>
    {
        sscanf(url, "%*[^/]//%[^@]", information->user);
        sscanf(url, "%*[^@]@%[^/]", information->host);
        sscanf(url, "%*[^@]%*[^/]%s", information->urlPath);

        strcpy(information->password, DEFAULT_PASSWORD);
    }
    else if (regexec(&url_no_user, url, 0, NULL, 0) == 0) // ftp://<host>/<url-path>
    {
        sscanf(url, "%*[^/]//%[^/]", information->host);
        sscanf(url, "%*[^/]//%*[^/]%s", information->urlPath);

        strcpy(information->user, DEFAULT_USER);
        strcpy(information->password, DEFAULT_PASSWORD);
    }
    else
    {
        printf("Invalid URL format\n");
        exit(-1);
    }

    if (regexec(&ip, information->host, 0, NULL, 0) == REG_NOMATCH) // Host is not an IP
    {
        char ip[16];

        if (get_IP(information->host, ip) == 0)
        {
            strcpy(information->host, ip);
        }
    }

    char *filename = strrchr(information->urlPath, '/'); // Pointer to the last instance of '/' in the url path, aka, a pointer to the start of the file name
    filename ? strcpy(information->filename, filename + 1) : strcpy(information->filename, information->urlPath);

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

int send_command(char *instruction, struct server_response *response)
{
    char command[6];

    sprintf(command, "%s\n", instruction);
    if (write(control_socket, command, strlen(command)) == -1)
    {
        perror("write() server command\n");
        exit(-1);
    }
    else
    {
        unsigned char state = ST_WAIT;

        while (state != ST_SUCCESS)
        {
            unsigned char response_type;

            if (state != ST_FAILURE && state != ST_ERROR)
            {
                get_server_response(response);
                response_type = response->code / 100;
                printf("response_type %d\n", response_type);
            }

            switch (state)
            {
            case ST_WAIT:
                switch (response_type)
                {
                case 1:
                case 3:
                    state = ST_ERROR;
                    break;

                case 2:
                    state = ST_SUCCESS;
                    break;
                case 4:
                case 5:
                    state = ST_FAILURE;
                    break;
                }
                break;
            case ST_ERROR:
                printf("Error in command %s: %s", instruction, response->message);
                exit(-1);
                break;
            case ST_SUCCESS:
                // printf("Success: %s", response->message);
                break;
            case ST_FAILURE:
                printf("Failure in command %s: %s", instruction, response->message);
                exit(-1);
                break;
            }
        }
        return response->code;
    }
}

int request_file(char *resource, struct server_response *response)
{

    char command[strlen(resource) + 7];

    sprintf(command, "RETR %s\n", resource);

    if (write(control_socket, command, strlen(command)) == -1)
    {
        perror("write() server command\n");
        exit(-1);
    }

    unsigned char state = ST_WAIT;

    while (state == ST_WAIT)
    {
        unsigned char response_type;

        if (state != ST_FAILURE && state != ST_ERROR)
        {
            get_server_response(response);
            response_type = response->code / 100;
        }

        switch (state)
        {
        case ST_WAIT:
            switch (response_type)
            {
            case 1:
                break;
            case 2:
                state = ST_SUCCESS;
                break;
            case 3:
                state = ST_ERROR;
                break;
            case 4:
            case 5:
                state = ST_FAILURE;
                break;
            }
            break;
        case ST_ERROR:
            printf("Error in command RETR: %s", response->message);
            exit(-1);
            break;
        case ST_SUCCESS:
            // printf("Success: %s", response->message);
            break;
        case ST_FAILURE:
            printf("Failure in command RETR: %s", response->message);
            exit(-1);
            break;
        }
    }
    return response->code;
}

int login(char *user, char *pass)
{
    char command[max(strlen(user), strlen(pass)) + 7];
    sprintf(command, "USER %s\n", user);
    if (write(control_socket, command, strlen(command)) == -1)
    {
        perror("write() server command");
        exit(-1);
    }

    unsigned char state = ST_WAIT_USER;
    struct server_response response;

    while (state != ST_SUCCESS)
    {
        unsigned char response_type;

        if (state != ST_FAILURE && state != ST_ERROR)
        {
            get_server_response(&response);
            response_type = response.code / 100;
        }

        switch (state)
        {
        case ST_WAIT_USER:

            switch (response_type)
            {
            case 1:
                state = ST_ERROR;
                break;
            case 2:
                state = ST_SUCCESS;
                break;
            case 4:
            case 5:
                state = ST_FAILURE;
                break;
            case 3:
                sprintf(command, "PASS %s\n", pass);
                if (write(control_socket, command, strlen(command)) == -1)
                {
                    perror("write() server command");
                    exit(-1);
                }
                state = ST_WAIT_PASS;
                break;
            }
            break;
        case ST_WAIT_PASS:
            switch (response_type)
            {
            case 1:
                state = ST_ERROR;
                break;
            case 2:
                state = ST_SUCCESS;
                break;
            case 3:
                char input[100];
                printf("The server is requesting your account name: ");
                scanf("%s", input);

                sprintf(command, "ACCT %s\n", pass);
                if (write(control_socket, command, strlen(command)) == -1)
                {
                    perror("write() server command");
                    exit(-1);
                }
                state = ST_WAIT_ACCT;
                break;
            case 4:
            case 5:
                state = ST_FAILURE;
                break;
            }
            break;
        case ST_WAIT_ACCT:
            switch (response_type)
            {
            case 1:
            case 3:
                state = ST_ERROR;
                break;
            case 2:
                state = ST_SUCCESS;
                break;
            case 4:
            case 5:
                state = ST_FAILURE;
                break;
            }
            break;
        case ST_ERROR:
            printf("Error Login: %s\n", response.message);
            exit(-1);
            break;
        case ST_SUCCESS:
            // printf("Success: %s\n", response.message);
            break;
        case ST_FAILURE:
            printf("Failure Login: %s\n", response.message);
            exit(-1);
            break;
        }
    }
    return response.code;
}

void get_file(char *filename)
{

    FILE *file = fopen(filename, "wb+");
    if (file == NULL)
    {
        printf("Error: Opening file %s\n", filename);
        exit(-1);
    }

    char file_content[MAX_FILE_LENGTH];

    unsigned short size;
    while (size = read(data_socket, file_content, MAX_FILE_LENGTH))
    {
        if (fwrite(file_content, size, 1, file) < 0)
        {
            printf("Error: Writing to file %s\n", filename);
            exit(-1);
        }
    }
    fclose(file);
}

void close_connect()
{
    struct server_response temp;
    send_command("QUIT", &temp);
    if (close(control_socket) < 0 || close(data_socket) < 0)
    {
        perror("close()");
        exit(-1);
    }
}

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("Wrong format. Usage: ./download  ftp://[<user>:<password>@]<host>/<url-path>\n");
        exit(-1);
    }

    struct urlInfo arguments;
    struct server_response response;

    parse_URl(argv[1], &arguments);

    open_socket(arguments.host, DEFAULT_PORT, &control_socket);

    get_server_response(&response);
    if (response.code != SERVER_READY_LOGIN)
    {
        printf("Error connecting to server\n");
        exit(-1);
    };

    printf("1\n");

    if (login(arguments.user, arguments.password) != SERVER_LOGIN_SUCCESSFUL)
    {
        printf("Error logging in to server\n");
        exit(-1);
    };

    printf("2\n");

    send_command("PASV", &response);

    printf("3\n");

    open_socket(response.server_ip, response.server_port, &data_socket);

    printf("4\n");

    request_file(arguments.urlPath, &response);

    printf("5\n");

    get_file(arguments.filename);

    printf("6\n");

    close_connect();

    return 0;
}
