/* * * * * * * * * * * * * * * * * *
 * 
 * dh.c - for diffiehelman key exchange 
 * code is taken from lab file client.c file
 *
 */

// header files used in the program
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <math.h>

// defining constant arguments
#define HASH_SIZE 100
#define HEX_BASE 16
#define DECIMAL_BASE 10

// function delarations * * * * 

int compute_modular_exponentiational (int g_value, unsigned int b_value, int p_value);
int generate_b_value();


int main(int argc, char const *argv[]) {

    // initialize variables
    int dh_component = 0;
    int b_value = generate_b_value();
    dh_component = compute_modular_exponentiational(15, b_value, 97);

    // create socket
    int sockfd, portno, n;
    struct sockaddr_in serv_addr;
    struct hostent * server;
    char buffer[256];

    if(argc < 3) {
        fprintf(stderr, "usage %s hostname port\n", argv[0]);
        exit(0);
    }

    portno = atoi(argv[2]);


    // Translate host name into peer's IP address
    // This is name translation service by the operating system

    server = gethostbyname(argv[1]);

    if (server == NULL) {
     fprintf(stderr, "ERROR, no such host\n");
     exit(0);
    }

    // Building data structures for socket 
    bzero((char *)&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy(server->h_addr_list[0], (char *)&serv_addr.sin_addr.s_addr, server->h_length);
    serv_addr.sin_port = htons(portno);

    // Create TCP socket -- active open
    // Preliminary steps: Setup: creation of active open socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0) {
        perror("ERROR opening socket");
        exit(0);
    }

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("ERROR connecting");
        exit(0);
    }

    // Do processing
    
    // Enter Username 

    bzero(buffer, 256);

    strcpy(buffer, "mayanks1\n");

    printf("Sending username \n");

    n = write(sockfd, buffer, strlen(buffer));

    if (n < 0) {
        perror("ERROR writing to socket");
        exit(0);
    }

    // send data 

    printf("Sending data \n");

    bzero(buffer, 256);

    // convert data to string

    sprintf(buffer, "%d\n", dh_component);

    n = write(sockfd, buffer, strlen(buffer));

    if (n < 0) {
        perror("ERROR writing to socket");
        exit(0);
    }


    // Read Data 

    bzero(buffer, 256);

    n = read(sockfd, buffer, 255);

    if (n < 0) {
        perror("ERROR reading from socket");
        exit(0);
    }

    printf("Data received: %s\n", buffer);

    // Re-send data 

    // code inspired from stackoverflow
    // https://stackoverflow.com/questions/29547115/how-to-convert-string-to-hex-value-in-c/29547549
    int new_g_value = (int )strtol(buffer, NULL, DECIMAL_BASE);

    int new_diffie_component = 0;

    new_diffie_component = compute_modular_exponentiational(new_g_value, b_value, 97);

    printf("Sending new gmod \n");

    bzero(buffer, 256);

    sprintf(buffer, "%d\n", new_diffie_component);

    n = write(sockfd, buffer, strlen(buffer));

    if (n < 0) {
        perror("ERROR writing to socket");
        exit(0);
    }

    // Read Status 

    bzero(buffer, 256);

    n = read(sockfd, buffer, 255);

    if (n < 0) {
        perror("ERROR reading from socket");
        exit(0);
    }

    printf("Status report: %s\n", buffer);

    return 0;
}

// Modular Exponentiation code (Power in Modular Arithmetic)
// Code inspired from geeksforgeeks
// https://www.geeksforgeeks.org/modular-exponentiation-power-in-modular-arithmetic/
int compute_modular_exponentiational (int g_value, unsigned int b_value, int p_value) {
    
    // Initialize result 
    int dh = 1;      

    // Update g_value if it is more than or equal to p_value
    g_value = g_value % p_value;   

    while (b_value > 0) { 
        
        // If b_value is odd, multiply g_value with result 
        if (b_value & 1) {

            dh = (dh * g_value) % p_value; 
        
        }

        // g_value must be even now 
        // b_value = b_value/2 
        b_value = b_value >> 1; 
        g_value = (g_value * g_value) % p_value;   
    } 

    return dh; 
} 

// generate b value for diffiehelman key exchange 
int generate_b_value() {

    int b_value = 0;

    // read sha256 hash from command line
    // Used awk to to get the hash from command line
    // https://www.shellhacks.com/awk-print-column-change-field-separator-linux-bash/

    // Used system from open group 
    // https://pubs.opengroup.org/onlinepubs/009695399/functions/system.html
    int stat = system("openssl sha256 dh.c | awk -F '= ' '{print $2}' > test.txt");

    char b_hash[100] = {'\0'};
    char b_hex[10] = {'\0'};
    FILE *command_file;

    // reading the byte from another file
    command_file = fopen("test.txt", "r");

    // if file exists, get the hex value
    if(command_file) {
        
        size_t size = fread(b_hash, 1, HASH_SIZE, command_file);

        strncpy(b_hex, b_hash, 2);
        printf("%s\n", b_hex);

        // code inspired from stackoverflow
        // https://stackoverflow.com/questions/29547115/how-to-convert-string-to-hex-value-in-c/29547549
        b_value = (int )strtol(b_hex, NULL, HEX_BASE);

        // close file
        fclose (command_file);
        
    } else {
        perror("FIle does not exit!");
        exit(EXIT_FAILURE);
    }

    return b_value;
}
