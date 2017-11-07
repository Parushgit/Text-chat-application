#include "../include/global.h"
#include "../include/logger.h"
#include<sys/types.h>
#include<netinet/in.h>
#include<unistd.h>
#include<stdio.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<strings.h>
#include<string.h>
#include<arpa/inet.h>
#include<netdb.h>
#include<ctype.h>

#define TRUE 1
#define MSG_SIZE 256
#define BUFFER_SIZE 300
#define BACKLOG 5
#define CMD_SIZE 100
#define STDIN 0
#define DELIM "."
#define STDIN_CLIENT 0


void showIP()
{
    struct sockaddr_in hints;
    int udpsocket;
    char printableip[16];

    udpsocket = socket(AF_INET, SOCK_DGRAM, 0);
    if(udpsocket == -1)
    {
        //die("socket");
        //printf("Died\n");
    }

    memset((char *) &hints, 0, sizeof(hints));
    hints.sin_family = AF_INET;
    hints.sin_port = htons(53);
    inet_pton(AF_INET, "8.8.8.8", &(hints.sin_addr));

    if((connect(udpsocket, (struct sockaddr *) &hints, sizeof(hints))) >= 0)
    {
        struct sockaddr_in newStruct;
        int length = sizeof(struct sockaddr);
        if(getsockname(udpsocket, (struct sockaddr *)&newStruct, &length) == -1)
        {
            //perror("getsockname");
        }
        
        inet_ntop(AF_INET, &(newStruct.sin_addr), printableip, sizeof(printableip));
        
        cse4589_print_and_log("IP:%s\n", printableip);
    }

}

int ascii_only(const char *s)
{
    while (*s) {
        if (isascii(*s++) == 0) return 0;
    }
    return 1;
}

int digits(int port)
{
    int count = 0;
    while(port != 0)
    {
        // n = n/10
        port /= 10;
        ++count;
    }
    return count;
}

struct listOfClients
{
    int port;
    char ipAddress[200];
    int listeningPort_newMethod;
    int socketDescriptor;
    char hostName[200];
    int num_msg_send;
    int num_msg_recv;
    struct listOfClients *next;
    char status_log[100];
    int blocked;
};

struct listOfClients *root = NULL;
struct listOfClients *root_client = NULL;
int j, clientsocket, loggedoutPort;

/* function to swap data of two nodes a and b*/
/*(References - http://www.geeksforgeeks.org/bubble-sort/ )*/
void swap(struct listOfClients *a, struct listOfClients *b)
{
    int temp = a->listeningPort_newMethod;
    a->listeningPort_newMethod = b->listeningPort_newMethod;
    b->listeningPort_newMethod = temp;
}
/*(References - http://www.geeksforgeeks.org/bubble-sort/ )*/
void bubbleSort(struct listOfClients *start)
{
    int swapped, i;
    struct listOfClients *ptr1;
    struct listOfClients *lptr = NULL;
    struct listOfClients *ptr2;
 
    /* Checking for empty list */
    if (ptr1 == NULL)
        return;
 
    do
    {
        swapped = 0;
        ptr1 = start;
 
        while (ptr1->next != lptr)
        {
            ptr2 = ptr1->next;
            if (ptr1->listeningPort_newMethod > ptr2->listeningPort_newMethod)
            { 
                swap(ptr1, ptr1->next);
                swapped = 1;
            }
            ptr1 = ptr1->next;
        }
        lptr = ptr1;
    }
    while (swapped);
}

/* function to insert a new_node in a list. Note that this
  function expects a pointer to head_ref as this can modify the
  head of the input linked list (similar to push())*/
/*(References - http://www.geeksforgeeks.org/insertion-sort/ )*/
void sortedInsert(struct listOfClients** head_ref, struct listOfClients* new_node)
{
      struct listOfClients* current;
      /* Special case for the head end */
      if (*head_ref == NULL || (*head_ref)->listeningPort_newMethod >= new_node->listeningPort_newMethod)
      {
          new_node->next = *head_ref;
          *head_ref = new_node;
      }
      else
      {
          /* Locate the node before the point of insertion */
          current = *head_ref;
          while (current->next!=NULL &&
                 current->next->listeningPort_newMethod < new_node->listeningPort_newMethod)
          {
              current = current->next;
          }
          new_node->next = current->next;
          current->next = new_node;
      }
}

/*(References - http://www.geeksforgeeks.org/insertion-sort/ )*/
void insertionsort(struct listOfClients **head_ref)
{
    // Initialize sorted linked list
    struct listOfClients *sorted = NULL;
 
    // Traverse the given linked list and insert every
    // node to sorted
    struct listOfClients *current = *head_ref;
    while (current != NULL)
    {
        // Store next for next iteration
        struct listOfClients *next = current->next;
 
        // insert current in sorted linked list
        sortedInsert(&sorted, current);
 
        // Update current
        current = next;
    }
 
    // Update head_ref to point to sorted linked list
    *head_ref = sorted;
}

int valid_digit(char *ip_str)
{
    while (*ip_str) {
        if (*ip_str >= '0' && *ip_str <= '9')
            ++ip_str;
        else
            return 0;
    }
    return 1;
}

/*(References - http://www.geeksforgeeks.org/program-to-validate-an-ip-address/ )*/
int isValidIP(char *ip_str)
{
    int i, num, dots = 0;
    char *ptr;
 
    if (ip_str == NULL)
        return 0;
 
    // See following link for strtok()
    // http://pubs.opengroup.org/onlinepubs/009695399/functions/strtok_r.html
    ptr = strtok(ip_str, DELIM);
 
    if (ptr == NULL)
        return 0;
 
    while (ptr) {
 
        /* after parsing string, it must contain only digits */
        if (!valid_digit(ptr))
            return 0;
 
        num = atoi(ptr);
 
        /* check for valid IP */
        if (num >= 0 && num <= 255) {
            /* parse remaining string */
            ptr = strtok(NULL, DELIM);
            if (ptr != NULL)
                ++dots;
        } else
            return 0;
    }
 
    /* valid IP string must contain 3 dots */
    if (dots != 3)
        return 0;
    return 1;

}

int connect_to_host(char *server_ip, int server_port, int fdsocket)
{
    fdsocket = socket(AF_INET, SOCK_STREAM, 0);
    if(fdsocket < 0)
    {
    //cse4589_print_and_log("[LOGIN:ERROR]\n");
    //cse4589_print_and_log("[LOGIN:END]\n");
    }
    int len;
    struct sockaddr_in remote_server_addr;

    bzero(&remote_server_addr, sizeof(remote_server_addr));
    remote_server_addr.sin_family = AF_INET;
    inet_pton(AF_INET, server_ip, &remote_server_addr.sin_addr);
    remote_server_addr.sin_port = htons(server_port);
    //printf("%d : \n", connect(fdsocket, (struct sockaddr*)&remote_server_addr, sizeof(remote_server_addr)));
    if(connect(fdsocket, (struct sockaddr*)&remote_server_addr, sizeof(remote_server_addr)) < 0)
    {
        //cse4589_print_and_log("[LOGIN:ERROR]\n");
        //cse4589_print_and_log("[LOGIN:END]\n");
    }
        //perror("Connect failed");

    return fdsocket;
}
/*(References - http://www.geeksforgeeks.org/linked-list-set-3-deleting-node/ )*/
void deleteNode(struct listOfClients **head_ref, int key)
{
    // Store head node
    struct listOfClients* ptr1 = *head_ref, *prev;
 
    // If head node itself holds the key to be deleted
    if (ptr1 != NULL && ptr1->socketDescriptor == key)
    {
        *head_ref = ptr1->next;   // Changed head
        free(ptr1);               // free old head
        return;
    }
 
    // Search for the key to be deleted, keep track of the
    // previous node as we need to change 'prev->next'
    while (ptr1 != NULL && ptr1->socketDescriptor != key)
    {
        prev = ptr1;
        ptr1 = ptr1->next;
    }
 
    // If key was not present in linked list
    if (ptr1 == NULL) return;
 
    // Unlink the node from linked list
    prev->next = ptr1->next;
 
    free(ptr1);  // Free memory
}

/*References - Beej*/
int sendall(int s, char *buf, int len)
{
        //printf("Inside SendAll\n");
        int total = 0; // how many bytes we've sent
        int bytesleft = len; // how many we have left to send
        int n;
        while(total < len) {
            //printf("Sending\n");
        n = send(s, buf+total, bytesleft, 0);
        if (n == -1) { break; }
        total += n;
        bytesleft -= n;
        }
        len = total; // return number actually sent here
        return n==-1?-1:0; // return -1 on failure, 0 on success
        
}

int recvall(int s, char *buf, int len)
{
        //printf("Inside RecvAll\n");
        int total = 0; // how many bytes we've sent
        int bytesleft = len; // how many we have left to receive
        //printf("Length time : %d\n", bytesleft);
        int n;
        while(total < len) {
            //printf("Inside Check\n");
        n = recv(s, buf+total, bytesleft, 0);
        //printf("INSIDE RCV : %d\n", n);
        //printf("INSIDE RCV : %s\n", buf);
        if (n == -1 || n == 0) { break; }
        total += n;
        bytesleft -= n;
        }
        buf[len] = '\0';
        len = total; // return number actually sent here
        return (n==-1 || n==0)?-1:0; // return -1 on failure, 0 on success
        
}

void InsertNewNodeIntoArray(struct listOfClients *new_node, int socket)
{
    char PortInChar[20];
    struct hostent *he;
    struct in_addr ipv4addr;  
    char createNode[256]; //= malloc(sizeof(char*)*BUFFER_SIZE);
    memset(createNode, 0, BUFFER_SIZE);
    strcat(createNode, "@LIST|");
    while(new_node != NULL)
    {
        //hostname_to_ip(r->hostName, r->ipAddress); 
        sprintf(PortInChar, "%d", new_node->listeningPort_newMethod);
        inet_pton(AF_INET, new_node->ipAddress, &ipv4addr);
        he = gethostbyaddr(&ipv4addr, sizeof ipv4addr, AF_INET);
        strcpy(new_node->hostName, he->h_name);
        strcat(createNode, new_node->hostName);
        strcat(createNode, "_");
        strcat(createNode, new_node->ipAddress);
        strcat(createNode, "_");
        strcat(createNode, PortInChar);
        strcat(createNode, "_");
        strcat(createNode, ";");
        new_node = new_node->next;
    }
    int node_size = strlen(createNode);

    char* temp1;
    temp1 = malloc(strlen(createNode) + 10);
    char len[5];
    
    sprintf(len, "%-5d", node_size);
    strcpy(temp1, len);
    strcat(temp1, createNode);
    strcpy(createNode,temp1); 

    node_size += 5;
    int success = sendall(socket, createNode, node_size);
    if(success == -1)
    {
         //perror("send");
    }
       
    return;
}

void connect_server(int port)
{
    int server_socket, head_socket, selret, sock_index, fdaccept=0, caddr_len, i;
    struct sockaddr_in server_addr, client_addr;
    fd_set master_list, watch_list;
    //printf("HELLO\n");
 
    //root = NULL;
 
    char ipValue[200];
 
    /* Socket */
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if(server_socket < 0)
    {}
        //perror("Cannot create socket");
 
    /* Fill up sockaddr_in struct */
    bzero(&server_addr, sizeof(server_addr));
 
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(port);
 
    /* Bind */
    if(bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0 )
    {}
        //perror("Bind failed");
 
    /* Listen */
    if(listen(server_socket, BACKLOG) < 0)
    {}
        //perror("Unable to listen on port");
 
    /* ---------------------------------------------------------------------------- */
 
    /* Zero select FD sets */
    FD_ZERO(&master_list);
    FD_ZERO(&watch_list);
    
    /* Register the listening socket */
    FD_SET(server_socket, &master_list);
    /* Register STDIN */
    FD_SET(STDIN, &master_list);
 
    head_socket = server_socket;
 
    while(TRUE)
    {
        memcpy(&watch_list, &master_list, sizeof(master_list));
 
        //printf("\n[PA1-Server@CSE489/589]$ ");
        //fflush(stdout);
 
        /* select() system call. This will BLOCK */
        selret = select(head_socket + 1, &watch_list, NULL, NULL, NULL);
        if(selret < 0)
            {//perror("select failed.");
    }
 
        /* Check if we have sockets/STDIN to process */
        if(selret > 0)
        {
            /* Loop through socket descriptors to check which ones are ready */
            for(sock_index=0; sock_index<=head_socket; sock_index+=1)
            {
 
                if(FD_ISSET(sock_index, &watch_list))
                {
 
                    /* Check if new command on STDIN */
                    if (sock_index == STDIN)
                    {
 
                                    char inputstr[250];
                                    if(fgets(inputstr, 300, stdin)!=NULL)
                                    {
                                        strtok(inputstr, "\n");
                                    }
                                    char *token;
                                    char dividedStrings[4];
                                    i = 0;
                                    /* walk through other tokens */
                            
                                    char *p = strtok(inputstr, " ");
                                    char *array[3];
                  
                                    while (p != NULL)
                                    {
                                        array[i++] = p;
                                        p = strtok (NULL, " ");
                                    }
                     
                                    if(strcmp(array[0], "IP") == 0)
                                    {
                                        cse4589_print_and_log("[IP:SUCCESS]\n", array[0]);
                                        showIP();
                                        cse4589_print_and_log("[IP:END]\n", array[0]);
                                    }
                                    if(strcmp(array[0], "AUTHOR") == 0)
                                    {
                                        char your_ubit_name[50];
                                        strcpy(your_ubit_name, "parushga");
                                        cse4589_print_and_log("[%s:SUCCESS]\n", array[0]);
                                        cse4589_print_and_log("I, %s, have read and understood the course academic integrity policy.\n", your_ubit_name);
                                        cse4589_print_and_log("[%s:END]\n", array[0]);
                                        //printf("I, PARUSH GARG, have read and understood the course academic integrity policy.\n");
                                    }
                                    if(strcmp(array[0], "PORT")==0)
                                    {
                                        cse4589_print_and_log("[%s:SUCCESS]\n", array[0]);
                                        cse4589_print_and_log("PORT:%d\n", port);
                                        cse4589_print_and_log("[%s:END]\n", array[0]);
                                        //printf("PORT: %d\n", port);
                                    }
                                    if(strcmp(array[0], "LIST") == 0)
                                    {
                                        cse4589_print_and_log("[%s:SUCCESS]\n", array[0]);
                                        struct listOfClients *r;
                                        //r = root;
                                        insertionsort(&root);
                                        r = root;
                                       
                                        j=1;
            
                                        struct hostent *he;
                                        struct in_addr ipv4addr;
            
                                        while(r!=NULL)
                                        {   
                                        //hostname_to_ip(r->hostName, r->ipAddress); 
                                        inet_pton(AF_INET, r->ipAddress, &ipv4addr);
                                        he = gethostbyaddr(&ipv4addr, sizeof ipv4addr, AF_INET);
                                        strcpy(r->hostName, he->h_name);
                                        
                                        cse4589_print_and_log("%-5d%-35s%-20s%-8d\n", j, r->hostName, r->ipAddress, r->listeningPort_newMethod);
                                        r = r->next;
                                        j++;
                                        }
                                        cse4589_print_and_log("[%s:END]\n", array[0]);
                                    }
                                    if(strcmp(array[0], "STATISTICS") == 0)
                                    {
                                        
                                        cse4589_print_and_log("[%s:SUCCESS]\n", array[0]);
                                        struct listOfClients *rStatistics;
                                        insertionsort(&root);
                                       
                                        rStatistics = root;
                                        
                                        j=1;
            
                                        struct hostent *he;
                                        struct in_addr ipv4addr;
            
                                        while(rStatistics!=NULL)
                                        {   
                                        //hostname_to_ip(r->hostName, r->ipAddress); 
                                        inet_pton(AF_INET, rStatistics->ipAddress, &ipv4addr);
                                        he = gethostbyaddr(&ipv4addr, sizeof ipv4addr, AF_INET);
                                        strcpy(rStatistics->hostName, he->h_name);
                                        cse4589_print_and_log("%-5d%-35s%-8d%-8d%-8s\n", j, rStatistics->hostName, rStatistics->num_msg_send, rStatistics->num_msg_recv, rStatistics->status_log);
                                        rStatistics = rStatistics->next;
                                        j++;
                                        }
                                        cse4589_print_and_log("[%s:END]\n", array[0]);
                                    }
                    }
                    /* Check if new client is requesting connection */
                    else if(sock_index == server_socket)
                    {
                        //printf("INSIDE NEW NODE\n");
                        caddr_len = sizeof(client_addr);
                        fdaccept = accept(server_socket, (struct sockaddr *)&client_addr, &caddr_len);
                        if(fdaccept < 0)
                        {}
                            //perror("Accept failed.");
 
                            struct listOfClients* temp;
                            temp = (struct listOfClients *) malloc(sizeof(struct listOfClients));
                            temp -> port = client_addr.sin_port;
                            temp -> listeningPort_newMethod = 0;
                            temp -> num_msg_send = 0;
                            temp-> num_msg_recv = 0;
                            temp->blocked = 0;
                            strcpy(temp -> status_log, "logged-in");
                            inet_ntop(AF_INET, &(client_addr.sin_addr), temp->ipAddress, 200);
                            temp -> socketDescriptor = fdaccept;
                            //temp -> ipAddress = client_addr.sin_addr;
                            if(root == NULL)
                            {
                                root = temp;
                                temp -> next = NULL;
                            }
                            else
                            {
                                temp -> next = root;
                                root = temp;
                            }
                                                 
 
                        /* Add to watched socket list */
                        FD_SET(fdaccept, &master_list);
                        if(fdaccept > head_socket) head_socket = fdaccept;
                    }
                    /* Read from existing clients */
                    else
                    {
                       // printf("Inside Server\n");
                        /* Initialize buffer to receieve response */
                        char *buffer = (char*) malloc(sizeof(char)*BUFFER_SIZE);
                        memset(buffer, '\0', BUFFER_SIZE);

                        char *buffer_len = (char*) malloc(sizeof(char)*5);
                        memset(buffer_len, '\0', 5);
                     
                        //printf("Inside Server\n");
                        int msg_len_rcvd = recvall(sock_index, buffer_len, 5);
                        //printf("Value returned : %d\n", msg_len_rcvd);
                        int msg_len;
                        //printf("Value function : %d\n", msg_len_rcvd);
                        if(msg_len_rcvd == 0)
                        {
                            msg_len = atoi(buffer_len);
                            //printf("Message Length: %d\n", msg_len);
                            //if(msg_len >= 257)
                            
                                //cse4589_print_and_log("[SEND:ERROR]\n");
                            
                                        int recv_result = recvall(sock_index, buffer, msg_len);
                                    
                                        //Process incoming data from existing clients here ...
                                        char receivedString[300];
                                        
                                        int flag = 0;
                                        
                                        strcpy(receivedString,&buffer[0]);
                                        //printf("%s\n", receivedString);
                                        for(i=0;i<strlen(receivedString);i++)
                                        {   
            
                                            if(receivedString[i] == ':')
                                            {
                                                flag = 1;
                                                break;
                                            }
                                        }
                                        //printf("%d \n", flag);
                                        if(flag == 0)
                                        {
                                                        struct listOfClients *r_assignLport;
                                                        r_assignLport = root;
                                                        if(r_assignLport == NULL)
                                                        {
                                                            //printf("NOTHING\n");
                                                        }
                                            
                                                        while(r_assignLport!=NULL)
                                                        {
                                                            if(r_assignLport->listeningPort_newMethod == 0)
                                                                {
                                                                    r_assignLport->listeningPort_newMethod = atoi(buffer);
                                                                }
                                                                r_assignLport = r_assignLport->next;
                                                        }
                                                        InsertNewNodeIntoArray(root, sock_index);
                                        }
                                            //Process incoming data from existing clients here ...
                                            //Split IP and message
                                        else
                                        {
                                                buffer = &receivedString;
                                                i = 0;
                                                /* walk through other tokens */
                                            
                                                char *p = strtok(buffer, ":");
                                                char *array[2];
                                            
                                                while (p != NULL)
                                                {
                                                    array[i++] = p;
                                                    p = strtok(NULL, ":");
                                                }
                    
                                                struct listOfClients *ro;
                                                struct listOfClients *rotest;
                                                struct listOfClients *robroadcast;
                                                robroadcast = root;
                                                rotest = root;
                                                ro = root;
                                                if(ro == NULL)
                                                {
                                                    //printf("NOTHING\n");
                                                }
                                
                                                int lengthofMessage = strlen(array[1]);
                                                int ret;

                                                if(strcmp(array[0], "BROADCAST") == 0)
                                                {

                                                    char ipTo[20];
                                                    strcpy(ipTo, "255.255.255.255");
                                                    struct hostent *he;
                                                    struct in_addr ipv4addr;
                                                    char senderIP[300];
                                                    while(robroadcast != NULL)
                                                        {
                                                            if(robroadcast->socketDescriptor == sock_index)
                                                            {
                                                                robroadcast->num_msg_send += 1;
                                                                strcpy(senderIP, robroadcast->ipAddress);
                                                                break;
                                                            }
                                                            robroadcast = robroadcast->next;
                                                        }
                                
                                                    robroadcast = root;
                                                    //printf("Inside Broadcast\n");
                                                    char osenderIP[20];
                                                    strcpy(osenderIP, senderIP);
                                                    char *append = "@BCT|";
                                                    strcat(senderIP, ":");
                                                    strcat(senderIP, array[1]);
                                                    char* temp;
                                                    temp = malloc(strlen(senderIP) + strlen(append) + 1);
                                                    //char temp[300];
                                                    strcpy(temp, append);
                                                    strcat(temp, senderIP);
                                                    strcpy(senderIP,temp); 
                                                    //free(temp);     
                                                    //lengthofMessage = strlen(senderIP); 

                                                    char* temp1;
                                                    temp1 = malloc(strlen(senderIP) + 10);
                                                    // //char temp[300];
                                                    char len[5];
                                                    
                                                    sprintf(len, "%-5d", strlen(senderIP));
                                                    strcpy(temp1, len);
                                                    strcat(temp1, senderIP);
                                                    strcpy(senderIP,temp1); 
                                                    lengthofMessage = strlen(senderIP); 
                                                    //lengthofMessage += 5;
                                                    free(temp1);

                                                    while(robroadcast!=NULL)
                                                    {
                                                        inet_pton(AF_INET, robroadcast->ipAddress, &ipv4addr);
                                                        he = gethostbyaddr(&ipv4addr, sizeof ipv4addr, AF_INET);
                                                        strcpy(robroadcast->hostName, he->h_name);
                                                        //printf("SockIndex: %d\n", sock_index);
                                            
                                                        if(robroadcast->socketDescriptor != sock_index)
                                                        {
                                                                ret = sendall(robroadcast->socketDescriptor, senderIP, lengthofMessage);
                                                                if(ret == -1)
                                                                {
                                                                //perror("SEND");
                                                                }
                                                                else
                                                                {
                                                                    robroadcast->num_msg_recv += 1;
                                                                }
                                                            }   
                                                        //printf("FD : %d\n", robroadcast->socketDescriptor);
                                                        robroadcast = robroadcast->next;
                                                    }
                                                    cse4589_print_and_log("[RELAYED:SUCCESS]\n");
                                                    cse4589_print_and_log("msg from:%s, to:%s\n[msg]:%s\n", osenderIP, ipTo, array[1]);
                                                    cse4589_print_and_log("[RELAYED:END]\n");
                                                }

                                                else if(strcmp(array[0], "REFRESH") == 0)
                                                {
                                                    //printf("Hello Refresh in server\n");
                                                    InsertNewNodeIntoArray(root, sock_index);

                                                }

                                                else if(strcmp(array[0], "LOGOUT") == 0)
                                                {
                                                    //printf("Hello Refresh in server\n");
                                                   struct listOfClients* list_server;
                                                   list_server = root;

                                                   while(list_server != NULL)
                                                   {
                                                       if(list_server->socketDescriptor == sock_index)
                                                       {
                                                           strcpy(list_server->status_log, "logged-out");
                                                           break;
                                                       }
                                                       list_server = list_server -> next;
                                                   }

                                                }

                                                else
                                                {
                                                    char senderIP[300];
                                                    while(rotest!=NULL)
                                                    {
                                                        if(sock_index == rotest->socketDescriptor)
                                                        {
                                                            //printf("I am inside addition\n");
                                                            rotest->num_msg_send += 1;
                                                            strcpy(senderIP, rotest->ipAddress);
                                                            //printf("SENDER IP : %s", senderIP);
                                                        }
                                                        rotest = rotest->next;
                                                    }
                                                    char copy_senderIP[30];
                                                    strcpy(copy_senderIP, senderIP);
                                                    rotest = root;

                                                    while(rotest!=NULL)
                                                    {
                                                        
                                                        if(strcmp(rotest->ipAddress, array[0]) == 0)
                                                        {
                                                            //printf("IP Address matched : %s", rotest->ipAddress);
                                                            strcat(senderIP, ":");
                                                            strcat(senderIP, array[1]);
                                                            char *append = "@MSG|";
                                                            char* temp;
                                                            temp = malloc(strlen(senderIP) +strlen(append) + 1);
                                                            strcpy(temp, append);
                                                            strcat(temp, senderIP);
                                                            strcpy(senderIP,temp);  
                                                            //printf("FINAL MESSAGE : %s\n", senderIP);
                                                            free(temp);     
                                                            
                                                            
                                                            char* temp1;
                                                            temp1 = malloc(strlen(senderIP) + 10);
                                                            // //char temp[300];
                                                            char len[5];
                                                            
                                                            sprintf(len, "%-5d", strlen(senderIP));
                                                            strcpy(temp1, len);
                                                            strcat(temp1, senderIP);
                                                            strcpy(senderIP,temp1); 
                                                            lengthofMessage = strlen(senderIP); 
                                                            //lengthofMessage += 5;
                                                            free(temp1);
                                                            //printf("String formed : %s\n", senderIP);

                                                            //strcat("@MSG_", array[1]);
                                                            ret = sendall(rotest->socketDescriptor, senderIP, lengthofMessage);
                                                            if(ret == -1){

                                                            
                                                            //perror("SEND");
                                                            }
                                                            else
                                                            {
                                                                rotest->num_msg_recv += 1;
                                                                cse4589_print_and_log("[RELAYED:SUCCESS]\n");
                                                                cse4589_print_and_log("msg from:%s, to:%s\n[msg]:%s\n", copy_senderIP, array[0], array[1]);
                                                                cse4589_print_and_log("[RELAYED:END]\n");
                                                                //printf("SEND VALUE : %d\n", ret);
                                                                break;
                                                            }
                                                    
                                                        }
                                                        rotest = rotest->next;
                                                    }
                                                }
                    
                                        }
                                    // }
                            
                        }
                        else
                        {
                            //printf("Hello Exit\n");
                            struct listOfClients *r_close;
                            r_close = root;
                            //bubbleSort(r);
                            //insertionsort(&r);
                            j=1;

                            struct hostent *he;
                            struct in_addr ipv4addr;

                            deleteNode(&r_close, sock_index); 
                            //printf("Inside Delete Node\n");

                            root = r_close;

                            close(sock_index);
                            
                       
    
                                /* Remove from watched list */
                            FD_CLR(sock_index, &master_list);
                        }
                    
                    }
                }
            }
        }
    }
}

int numbers_only(const char *s)
{
    while (*s) {
        if (isdigit(*s++) == 0) return 0;
    }
    return 1;
}

void connect_client(int port)
{
    int returnCSocket, sockfd;
    int head_socket, selret, sock_index, fdaccept=0, caddr_len;
    struct sockaddr_in server_addr, client_addr;
    char broadcast_msg[600];

    //int clientsocket;
    
    //printf("CLIENT SOCKET - %d\n", clientsocket);
    if(clientsocket < 0)
    {
    //perror("Failed to create socket");
    }
    //printf("Hello\n");
    fd_set master_list, watch_list;
    //printf("Hello\n");

    /* Zero select FD sets */
     FD_ZERO(&master_list);
     FD_ZERO(&watch_list);
     FD_SET(STDIN, &master_list);
     char listeningPort[1000];

 
    //head_socket = clientsocket;
    head_socket = STDIN;
    //int fdmax;

    while(TRUE)
    {
      
        memcpy(&watch_list, &master_list, sizeof(master_list));
       
        selret = select(head_socket+1, &watch_list, NULL, NULL, NULL);
     

        if(selret < 0)
        {
            //perror("select failed.");        int nfds, i;

        }

        if(selret > 0)
        {
            //printf("Hello\n");
                /* Loop through socket descriptors to check which ones are ready */
                for(sock_index=0; sock_index <=head_socket; sock_index+=1)
                {
                    //printf("Hello\n");
                    //printf("Hello\n");
                    if(FD_ISSET(sock_index, &watch_list))
                    {
                            /* Check if new command on STDIN */
                            if (sock_index == STDIN)
                            {
                                //printf("HEAD SOCKETSTDIN\n");
                                
                                char inputstr[300];
                                //printf("\n[PA1-Client@CSE489/589]$ ");
                                //printf("Client1\n");
                                fflush(stdout);
                                if(fgets(inputstr, 350, stdin)!=NULL)
                                {
                                strtok(inputstr, "\n");
                                }
                                //printf("Client1\n");
                                int i;
                                char *token;
                                char dividedStrings[4];
                                i = 0;
                                /* walk through other tokens */
                            
                                char *p = strtok (inputstr, " ");
                                char *array[3];
                                char delimiter = ' ';
                                //printf("Client1\n");
                                while (p != NULL)
                                {
                                    array[i++] = p;

                                    if(strcmp(array[0], "BROADCAST") == 0)
                                    {
                                        array[1] = strtok (NULL, "");
                                        break;
                                    }    
                                    
                                    if(i<=1)
                                    {
                                        p = strtok (NULL, " ");
                                    }
                                    else
                                        p = strtok (NULL, "");
                                }
                                
                            
                                if(strcmp(array[0], "IP") == 0)
                                {
                                    cse4589_print_and_log("[IP:SUCCESS]\n", array[0]);
                                    showIP();
                                    cse4589_print_and_log("[IP:END]\n", array[0]);
                                }
                                if(strcmp(array[0], "AUTHOR") == 0)
                                {
                                    //printf("I, PARUSH GARG, have read and understood the course academic integrity policy.\n");
                                    char your_ubit_name[50];
                                    strcpy(your_ubit_name, "parushga");
                                    cse4589_print_and_log("[%s:SUCCESS]\n", array[0]);
                                    cse4589_print_and_log("I, %s, have read and understood the course academic integrity policy.\n", your_ubit_name);
                                    cse4589_print_and_log("[%s:END]\n", array[0]);
                                }
                                if(strcmp(array[0], "PORT")==0)
                                {
                                    cse4589_print_and_log("[%s:SUCCESS]\n", array[0]);
                                    cse4589_print_and_log("PORT:%d\n", port);
                                    cse4589_print_and_log("[%s:END]\n", array[0]);
                                    //printf("PORT: %d\n", port);
                                }
                                if(strcmp(array[0], "EXIT")==0)
                                {
                                        close(clientsocket);
                                        FD_CLR(clientsocket, &master_list);
                                        cse4589_print_and_log("[%s:SUCCESS]\n", array[0]);
                                        //FD_CLR(csocket, &watch_list);
                                        cse4589_print_and_log("[%s:END]\n", array[0]);
                                        exit(0);
                                }
                                if(strcmp(array[0], "LOGIN")==0)
                                {
                                    int validIP;
                                    int logged_status = 0;
                                    struct listOfClients* list_login;
                                    list_login = root_client;
                                    while(list_login != NULL)
                                    {
                                        if(list_login->listeningPort_newMethod == port)
                                        {
                                            if(strcmp(list_login->status_log, "logged-out") == 0)
                                            {
                                                logged_status = 1;
                                                break;
                                            }
                                        }
                                        list_login = list_login->next;
                                    }
                                    //server = connect_to_host("192.168.0.22", atoi(array[2])); //128.205.32.8 //192.168.0,22
                                    char ipToBeChecked[200];
                                    strcpy(ipToBeChecked, array[1]);
                                    validIP = isValidIP(ipToBeChecked);
                                    if((validIP) && numbers_only(array[2]))//(digits(atoi(array[2])) >= 4))//  && numbers_only(array[2])
                                    {
                                        if(logged_status == 0)
                                        {
                                                returnCSocket = connect_to_host(array[1], atoi(array[2]), clientsocket); //128.205.32.8 //192.168.0,22
                                                if (returnCSocket >= 0)
                                                {
                                                cse4589_print_and_log("[%s:SUCCESS]\n", array[0]);
                                                FD_SET(returnCSocket, &master_list);

                                                if(returnCSocket > head_socket){
                                                    //printf("Return Socket : %d\n", returnCSocket);
                                                    head_socket = returnCSocket;
                                                    //printf("Head Socket : %d\n", head_socket);
                                                }

                                                sprintf(listeningPort, "%d", port);

                                                char* temp1;
                                                temp1 = malloc(strlen(listeningPort) + 10);
                                                // //char temp[300];
                                                char len[5];
                                                
                                                sprintf(len, "%-5d", strlen(listeningPort));
                                                strcpy(temp1, len);
                                                strcat(temp1, listeningPort);
                                                strcpy(listeningPort,temp1); 
                                   
                                                if(send(returnCSocket, listeningPort, strlen(listeningPort),0) == strlen(listeningPort))
                                                cse4589_print_and_log("[%s:END]\n", array[0]);
                                                }
                                        }
                                        else
                                        {
                                            cse4589_print_and_log("[%s:SUCCESS]\n", array[0]);
                                            cse4589_print_and_log("[%s:END]\n", array[0]);
                                        }
                                    }
                                    else
                                    {
                                        cse4589_print_and_log("[%s:ERROR]\n", array[0]);
                                        cse4589_print_and_log("[%s:END]\n", array[0]);
                                    }
                                }  

                                if(strcmp(array[0], "LOGOUT") == 0)
                                {
                                    char msg_ref [20];
                                    
                                    strcpy(msg_ref, "LOGOUT:");
                                    
                                    char* temp1;
                                    temp1 = malloc(strlen(msg_ref) + 10);
                                    // //char temp[300];
                                    char len[5];
                                    
                                    sprintf(len, "%-5d", strlen(msg_ref));
                                    strcpy(temp1, len);
                                    strcat(temp1, msg_ref);
                                    strcpy(msg_ref,temp1); 
                                    //printf("String formed : %s\n", msg_ref);
                                    free(temp1);

                                    if(send(returnCSocket, msg_ref, strlen(msg_ref), 0) == strlen(msg_ref))
                                    {
                                        cse4589_print_and_log("[%s:SUCCESS]\n", array[0]);
                                    }
                                    //cse4589_print_and_log("[%s:SUCCESS]\n", array[0]);
                                    cse4589_print_and_log("[%s:END]\n", array[0]);
                                } 

                                if(strcmp(array[0], "REFRESH") == 0)
                                {
                                        char msg_ref [20];

                                        strcpy(msg_ref, "REFRESH:");
                                        
                                        char* temp1;
                                        temp1 = malloc(strlen(msg_ref) + 10);
                                      
                                        char len[5];
                                        
                                        sprintf(len, "%-5d", strlen(msg_ref));
                                        strcpy(temp1, len);
                                        strcat(temp1, msg_ref);
                                        strcpy(msg_ref,temp1); 
                                        //printf("String formed : %s\n", msg_ref);
                                        free(temp1);

                                        if(send(returnCSocket, msg_ref, strlen(msg_ref), 0) == strlen(msg_ref))
                                        {
                                            cse4589_print_and_log("[REFRESH:SUCCESS]\n");
                                        }
                                        else
                                        {
                                            cse4589_print_and_log("[REFRESH:ERROR]\n");
                                            //cse4589_print_and_log("[REFRESH:END]\n");
                                        }

                                        cse4589_print_and_log("[%s:END]\n", array[0]);
                                    // }
                                } 
                                
                                if(strcmp(array[0], "LIST") == 0)
                                {
                                    cse4589_print_and_log("[%s:SUCCESS]\n", array[0]);
                                    fflush(stdout);
                                    struct listOfClients *list_client;
                                    
                                    //bubbleSort(r);
                                    insertionsort(&root_client);
                                    list_client = root_client;

                                    j=1;
                                    struct hostent *he;
                                    struct in_addr ipv4addr;
        
                                    while(list_client!=NULL)
                                    {  
                                    cse4589_print_and_log("%-5d%-35s%-20s%-8d\n", j, list_client->hostName, list_client->ipAddress, list_client->listeningPort_newMethod);
                                    list_client = list_client->next;
                                    j++;
                                    }
                                    cse4589_print_and_log("[%s:END]\n", array[0]);
                                }                                
                                
                                if(strcmp(array[0], "SEND") == 0)
                                {
                                    //printf("HelloSend\n");
                                    char finalMessage[280];
                                    char *pchar = (char*) malloc(sizeof(char)*BUFFER_SIZE);
                                    //printf("HelloSend\n");
                                    memset(pchar, '\0', BUFFER_SIZE);
                                    //printf("ARRAY2: %s\n", array[2]);
                                    if(strlen(array[2])>=257){
                                        cse4589_print_and_log("[%s:ERROR]\n",array[0]);
                                        cse4589_print_and_log("[%s:END]\n", array[0]);
                                        continue;
                                    }
                                    else
                                    {
                                        int validate=0;
                                        //server = connect_to_host("192.168.0.22", atoi(array[2])); //128.205.32.8 //192.168.0,2
                                        
                                        char ipToBeChecked[200];
                                        //printf("IP - %s:\n", array[1]);
                                        strcpy(ipToBeChecked, array[1]);
                                        //printf("IP - %s:\n", ipToBeChecked);
                                        char checkIp[200];
                                        strcpy(checkIp, ipToBeChecked);
                                     
                                        if(isValidIP(checkIp) && ascii_only(array[2]))
                                        {
                                            // printf("Inside Send1\n");

                                            struct listOfClients* list_c;
                                            list_c = root_client;
                                            
                                            while(list_c != NULL)
                                            {
                                                
                                                int lenip = strlen(ipToBeChecked);
                                                int lenip_node = strlen(list_c->ipAddress);
                                                if(strcmp(ipToBeChecked, list_c->ipAddress) == 0)
                                                 {
                                                     validate = 1;
                                                 }
                                               
                                                list_c = list_c -> next;
                                            }
                                            //printf("VALIDATE - %d\n", validate);
                                            if(validate == 0)
                                            {
                                                 cse4589_print_and_log("[%s:ERROR]\n", array[0]);
                                                 cse4589_print_and_log("[%s:END]\n",array[0]);
                                            }
                                            else
                                            {
                                                strcpy(finalMessage, array[1]);
                                                strcat(finalMessage, ":");
                                                strcat(finalMessage, array[2]);
                                                
                                                //char* temp;
                                                //temp = malloc(strlen(finalMessage) + 10);
                                                // //char temp[300];
                                                //char len[5];

                                                char* temp1;
                                                temp1 = malloc(strlen(finalMessage) + 10);
                                                // //char temp[300];
                                                char len[5];
                                                
                                                sprintf(len, "%-5d", strlen(finalMessage));
                                                strcpy(temp1, len);
                                                strcat(temp1, finalMessage);
                                                strcpy(finalMessage,temp1); 
                                                //printf("String formed : %s\n", finalMessage);
                                                free(temp1);

                                                int length_ip_msg = strlen(finalMessage);
                                               
                                                if(sendall(returnCSocket, finalMessage, length_ip_msg) <0)
                                                    {
                                                        cse4589_print_and_log("[%s:ERROR]\n", array[0]);
                                                        cse4589_print_and_log("[%s:END]\n",array[0]);
                                                    }
                                                else
                                                {
                                                    cse4589_print_and_log("[%s:SUCCESS]\n", array[0]);
                                                    cse4589_print_and_log("[%s:END]\n", array[0]);
                                                }
                                                //fflush(stdout);
                                                //free(temp);
                                                free(pchar);
                                                
                                            }
                                        }
                                        else
                                        {
                                            cse4589_print_and_log("[%s:ERROR]\n", array[0]);
                                            cse4589_print_and_log("[%s:END]\n",array[0]);
                                        }
                                    }
                                }

                                if(strcmp(array[0], "BROADCAST") == 0)
                                {
                                    cse4589_print_and_log("[%s:SUCCESS]\n", array[0]);
                                  

                                    char *pcharbroadcast = (char*) malloc(sizeof(char)*BUFFER_SIZE);
                                    memset(pcharbroadcast, '\0', BUFFER_SIZE);
                                    if(strlen(array[1])>256){
                                        //printf("Size of message is too big. Try again!\n");
                                        continue;
                                    }
                                    else
                                    {
                                        strcpy(broadcast_msg, array[0]);
                                        strcat(broadcast_msg, ":");
                                        strcat(broadcast_msg, array[1]);
                                        //strcat(finalMessage, finalsecondMessage);
                                        //printf("\nBroadcasting it to the remote server ... ");


                                        char* temp1;
                                        temp1 = malloc(strlen(broadcast_msg) + 10);
                                        // //char temp[300];
                                        char len[5];
                                        
                                        sprintf(len, "%-5d", strlen(broadcast_msg));
                                        strcpy(temp1, len);
                                        strcat(temp1, broadcast_msg);
                                        strcpy(broadcast_msg,temp1); 
                                        //printf("String formed : %s\n", finalMessage);
                                        free(temp1);

                                        int length = strlen(broadcast_msg);


                                        *pcharbroadcast = strtok(broadcast_msg, "\n");
                        
                                            if(sendall(returnCSocket, broadcast_msg, length) == 0)
                                            {
                                                //printf("\nBroadcast Done!\n");
                                            }
                                        fflush(stdout);
                                        //free(temp);
                                        free(pcharbroadcast);
                                    }



                                    cse4589_print_and_log("[%s:END]\n", array[0]);
                                } 

                                if(strcmp(array[0], "BLOCK") == 0)
                                {
                                    char ipToBeChecked[200];
                                    strcpy(ipToBeChecked, array[1]);
                                    if(isValidIP(ipToBeChecked))
                                    {
                                        int validate=0;
                                        struct listOfClients* list_c;
                                        list_c = root_client;
                                        
                                        while(list_c != NULL)
                                        {
                                            int lenip = strlen(ipToBeChecked);
                                            int lenip_node = strlen(list_c->ipAddress);
                                            if(strcmp(ipToBeChecked, list_c->ipAddress) == 0)
                                             {
                                                 validate = 1;
                                             }
                                            list_c = list_c -> next;
                                        }
                                        //printf("VALIDATE - %d\n", validate);
                                        if(validate == 0)
                                        {
                                             cse4589_print_and_log("[%s:ERROR]\n", array[0]);
                                             cse4589_print_and_log("[%s:END]\n",array[0]);
                                        }
                                        else
                                        {
                                        cse4589_print_and_log("[%s:SUCCESS]\n", array[0]);
                                        
                                        cse4589_print_and_log("[%s:END]\n", array[0]);
                                        }
                                    }
                                    else
                                    {
                                        cse4589_print_and_log("[%s:ERROR]\n", array[0]);
                                        cse4589_print_and_log("[%s:END]\n",array[0]);
                                    }
                                } 

                                if(strcmp(array[0], "BLOCKED") == 0)
                                {
                                    char ipToBeChecked[200];
                                    strcpy(ipToBeChecked, array[1]);
                                    if(isValidIP(ipToBeChecked))
                                    {
                                        int validate=0;
                                        struct listOfClients* list_c;
                                        list_c = root_client;
                                        
                                        while(list_c != NULL)
                                        {
                                            int lenip = strlen(ipToBeChecked);
                                            int lenip_node = strlen(list_c->ipAddress);
                                            if(strcmp(ipToBeChecked, list_c->ipAddress) == 0)
                                             {
                                                 validate = 1;
                                             }
                                            list_c = list_c -> next;
                                        }
                                        //printf("VALIDATE - %d\n", validate);
                                        if(validate == 0)
                                        {
                                             cse4589_print_and_log("[%s:ERROR]\n", array[0]);
                                             cse4589_print_and_log("[%s:END]\n",array[0]);
                                        }
                                        else
                                        {
                                        cse4589_print_and_log("[%s:SUCCESS]\n", array[0]);
                                        cse4589_print_and_log("[%s:END]\n", array[0]);
                                        }
                                    }
                                    else
                                    {
                                        cse4589_print_and_log("[%s:ERROR]\n", array[0]);
                                        cse4589_print_and_log("[%s:END]\n",array[0]);
                                    }
                                } 

                                if(strcmp(array[0], "UNBLOCK") == 0)
                                {
                                    char ipToBeChecked[200];
                                    strcpy(ipToBeChecked, array[1]);
                                    if(isValidIP(ipToBeChecked))
                                    {
                                        int validate=0;
                                        struct listOfClients* list_c;
                                        list_c = root_client;
                                        
                                        while(list_c != NULL)
                                        {
                                            int lenip = strlen(ipToBeChecked);
                                            int lenip_node = strlen(list_c->ipAddress);
                                            if(strcmp(ipToBeChecked, list_c->ipAddress) == 0)
                                             {
                                                 validate = 1;
                                             }
                                            list_c = list_c -> next;
                                        }
                                        //printf("VALIDATE - %d\n", validate);
                                        if(validate == 0)
                                        {
                                             cse4589_print_and_log("[%s:ERROR]\n", array[0]);
                                             cse4589_print_and_log("[%s:END]\n",array[0]);
                                        }
                                        else
                                        {
                                        cse4589_print_and_log("[%s:SUCCESS]\n", array[0]);
                                        cse4589_print_and_log("[%s:END]\n", array[0]);
                                        }
                                    }
                                    else
                                    {
                                        cse4589_print_and_log("[%s:ERROR]\n", array[0]);
                                        cse4589_print_and_log("[%s:END]\n",array[0]);
                                    }
                                } 
                                //comment
                                //fflush(stdout);
                            }
                            
                            else
                            {
                                char *buffer = (char*) malloc(sizeof(char)*BUFFER_SIZE);
                                memset(buffer, '\0', BUFFER_SIZE);

                                char *buffer_msg = (char*) malloc(sizeof(char)*BUFFER_SIZE);
                                memset(buffer_msg, '\0', BUFFER_SIZE);

                                char copyBuffer[256];
                                //printf("I am here \n");

                                int msg_len_rcvd = recvall(sock_index, buffer, 5);
                                int msg_len = atoi(buffer);

                                //printf("Length rcvd : %d\n", msg_len);
                        
                                if(msg_len_rcvd == 0)
                                {
                                      //printf("Server respond\n");
                                      int rcv_string = recvall(sock_index, buffer_msg, msg_len);
                                      //printf("Server responded: %s\n", buffer_msg);
                                      strcpy(copyBuffer, &buffer_msg[0]);
                                      //if(strcmp(p, "@LIST") == 0)
                                      free(buffer);
                                      free(buffer_msg);
                                          char *split = strtok(copyBuffer, "|");
                                          if(strcmp(split, "@LIST") == 0)
                                            {
                                                root_client = NULL;
                    
                                                split = strtok(NULL, "");
                                          

                                                char command_data[256];
                                                strcpy(command_data, split);
                                           

                                                char *end_ptr;
                                                char *token_node = strtok_r(command_data, ";", &end_ptr);
                                                while(token_node != NULL)
                                                {
                                                    struct listOfClients* temp_client;
                                                    int flag = 1;
                                                    temp_client = (struct listOfClients *) malloc(sizeof(struct listOfClients));
                                                    char *end_node;
                                                    //printf("NODE 1 : %s\n", token_node);
                                                    char *token_values = strtok_r(token_node, "_", &end_node);
                                                    while(token_values != NULL)
                                                    {
                                                                if(flag == 1)
                                                                {
                                                              
                                                                strcpy(temp_client->hostName, token_values);
                                                              
                                                                }
                                                                else if(flag == 2)
                                                                {
                                                               
                                                                strcpy(temp_client->ipAddress, token_values); 
                                                           
                                                                }
                                                                else
                                                                {
                                                             
                                                                temp_client->listeningPort_newMethod = atoi(token_values);
                                                              
                                                                }
                                                                flag++;
                                                             
                                                                token_values = strtok_r(NULL, "_", &end_node);
                                                    }
                                                                if(root_client == NULL)
                                                                {
                                                                    root_client = temp_client;
                                                                    temp_client -> next = NULL;
                                                                
                                                                }
                                                                else
                                                                {
                                                                 
                                                                    temp_client -> next = root_client;
                                                                    root_client = temp_client;
                                                                }
                                                           
                                                    token_node = strtok_r(NULL, ";", &end_ptr);
                                                    
                                                }

                                            }

                                          else if(strcmp(split, "@BCT") == 0)
                                                {
                                                   
                                                    split = strtok(NULL, "");
                                                    char header[256];
                                                    strcpy(header, split);
                                                    char *ipFrom, *msg;
                                                    ipFrom = strtok(header, ":");
                                                    msg = strtok(NULL, "");
                                                    cse4589_print_and_log("[RECEIVED:SUCCESS]\n");
                                                    cse4589_print_and_log("msg from:%s\n[msg]:%s\n", ipFrom, msg);
                                                    cse4589_print_and_log("[RECEIVED:END]\n");
                                                }
                                          else
                                                {
                                                split = strtok(NULL, "");
                                                char header[256];
                                                strcpy(header, split);
                                                char *ipFrom, *msg;
                                                ipFrom = strtok(header, ":");
                                                msg = strtok(NULL, "");

                                                cse4589_print_and_log("[RECEIVED:SUCCESS]\n");
                                                cse4589_print_and_log("msg from:%s\n[msg]:%s\n", ipFrom, msg);
                                                cse4589_print_and_log("[RECEIVED:END]\n");
                                                }
                                                            
                                }
                                                  
                            }

                    }
                                      fflush(stdout);
                }

        }  
                          
    }
}
/**
* main function
*
* @param  argc Number of arguments
* @param  argv The argument list
* @return 0 EXIT_SUCCESS
*/


int main(int argc, char **argv)
{
     /*Init. Logger*/
     cse4589_init_log(argv[2]);
     /*Clear LOGFILE*/
     fclose(fopen(LOGFILE, "w"));

     /*Start Here*/

     if(argc!=3)
     {
         //printf("Usage: ./[filename] s/c port\n");
         exit(1);
     }
     
     int num;
     sscanf(argv[2],"%d",&num);
 
     if(strcmp(argv[1], "s") == 0)
     {
         //printf("Server\n");
         connect_server(num);
     }
 
     if(strcmp(argv[1], "c") == 0)
     {
         clientsocket = socket(AF_INET, SOCK_STREAM, 0);
         //printf("Client\n");
         connect_client(num);
         //connect_cl(num);
     }
 
     return 0;
}


