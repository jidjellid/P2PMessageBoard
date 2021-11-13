#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <math.h>
#include <float.h>
#include <limits.h>
#include <inttypes.h>
#include <fcntl.h>
#include "../rfc6234/sha224-256.c"
#include <signal.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <poll.h>

//Structure used to represent data
struct triplet{
    unsigned char id [8];
    unsigned short seqNo;
    char data [192];
    time_t lastUpdate;
    uint8_t dataSize;
    unsigned char hash [16];
};

//Structure used to represent a node in the network
struct node{
    char ip [INET6_ADDRSTRLEN];
    char port [INET6_ADDRSTRLEN];
    int isPermanent;
    time_t lastSeen;
};

//Values for the neighbors and publication list
int posTrip = 0;//Number of data in the publications list
int posNode = 0;//Number of data in the neighbour list

struct node * neighbors;
struct triplet * publications;
int pubSize = 100;

//Doubles the size of the publication table
void extendsPublications(){
    pubSize = pubSize * 2;
    publications = realloc(publications, pubSize*sizeof(struct triplet)); 
}

//Check if seqNo1 is bigger than seqNo2, works like seqNo1 > seqNo2 unless seqNo1 is bigger than seqNo2 by 32768 or more, where seqNo2 is now considered bigger
int isBigger(unsigned short seqNo1, unsigned short seqNo2){
    unsigned short x = seqNo2 - seqNo1;
    if((x % 65536) < 32768){
        return -1;
    }
    return 1;
}

//Takes a triplet and puts it trunkated hash inside hash
void hashTriplet(unsigned char * id, unsigned short seqNo, char * data, uint8_t dataSize, unsigned char * hash){

    SHA256Context ctx;
    SHA256Reset(&ctx);

    //HASH ID
    SHA256Input(&ctx, (uint8_t *)id, sizeof(uint64_t));

    //HASH SEQNO
    unsigned short x = htons(seqNo);
    SHA256Input(&ctx, (uint8_t *)&x, sizeof(unsigned short));

    //HASH MESSAGE
    SHA256Input(&ctx, (uint8_t *)data, dataSize);
    
    //Get the results and cut the first 16 bytes
    unsigned char tempHash[32];
    SHA256Result(&ctx, tempHash);
    memcpy(hash,tempHash,16);//Might be useless but I don't want to accidentaly smash my memory and bug everything out
}

//Put the hash of the network inside hash
void hashNetwork(unsigned char * hash){
    SHA256Context ctx;
    SHA256Reset(&ctx);

    for(int i = 0; i < posTrip; i++){
        SHA256Input(&ctx, publications[i].hash, 16);
    }

    unsigned char tempFinalHash[32];
    SHA256Result(&ctx, tempFinalHash);
    memcpy(hash,tempFinalHash,16);
}

//Print the hexadecimal representation of size byte starting at the array pointer
void printHexArray(unsigned char * array, int size){
    for(int i = 0; i < size; i++){
        printf("%02X",array[i]);
    }
}

//Print every node in the neighbour table
void printNodeList(){
    printf("*******************\n");
    for(int i = 0; i < posNode; i++){
        struct node temp = neighbors[i];
        struct tm* tm_info = localtime(&temp.lastSeen);
        char buffer[26];
        strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", tm_info);
        printf("%i : %s, %s, permanent : %i, last seen : %s\n",i,temp.ip, temp.port, temp.isPermanent, buffer);
    }
    printf("*******************\n");
}

//Print dataSize bytes of data starting at data ignoring returns to line
void printData(char * data, uint8_t dataSize){
    for(int y = 0; y < dataSize; y++){
        if(data[y] == '\n'){
            printf(" ");
        } else {
            printf("%c",data[y]);
        }
    }
}

//Print every triplet in the publication table
void printPubList(){
        
    system("clear");//Remove that for more prints
    printf("*******************\n");
    for(int i = 0; i < posTrip; i++){
        struct tm* tm_info = localtime(&publications[i].lastUpdate);
        char buffer[26];
        strftime(buffer, 26, "%d/%m %H:%M:%S", tm_info);
        printf("%s (",buffer);
        printHexArray(publications[i].id,8);
        printf(", %hu, ",publications[i].seqNo);
        printData(publications[i].data,publications[i].dataSize);
        printf(")\n");
    }
    printf("\nTotal node seen : %i\n",posTrip);
    printf("*******************\n");
}

//Takes an id and returns an int such as publication[int] = wantedTriplet
int getTriplet(unsigned char * id){//Takes an id and outputs an int for publications
    for(int i = 0; i < posTrip; i++){
        if(memcmp(publications[i].id,id,8) == 0){
            return i;
        }
    }
    return -1;
}

//Save the very first publication to the file in ../resources/data if the folder resources exists
void saveData(){
    FILE * f1 = fopen("resources/data.txt","w");
    if(f1){
        char id [16];
        for(int i = 0; i < 8; i++){
            sprintf(&id[i*2],"%02X",publications[0].id[i]);
        }
        FILE * f2 = fopen("resources/data.txt","w");
        fprintf(f2, "%s\n%hu\n%s", id,publications[0].seqNo,publications[0].data);
        fclose(f2);
        fclose(f1);
    }
}

//Takes an id, a seqNo and a char array and put it in the publication table
//If a triplet already exists for a given id, the triplet is replaced only if seqNo > triplet.seqNo
void addTriplet(unsigned char * id, unsigned short seqNo, char * data, uint8_t dataSize, unsigned char * hash){
    
    //Make sure the datasize isn't somehow wrong
    if(dataSize > 192 || dataSize < 0){
        return;
    } else 

    //Check if the publication table is big enough to host the new data, else make it bigger
    if(posTrip >= pubSize){
        extendsPublications();
    }

    int val = getTriplet(id);

    if(val == -1){//If the new data isn't already in the table
        publications[posTrip].lastUpdate = time(0);
        memcpy(publications[posTrip].id,id,8);
        publications[posTrip].seqNo = seqNo;
        memcpy(publications[posTrip].data, data, dataSize);
        publications[posTrip].dataSize = dataSize;
        memcpy(publications[posTrip].hash,hash,16);
        posTrip++;
    } else {//If the id of the data is already in the table
        if(isBigger(seqNo,publications[val].seqNo) == 1){//If the seqNo is bigger
            if(memcmp(publications[val].id,publications[0].id,8) == 0){//If the id is mine
                publications[val].lastUpdate = time(0);
                publications[val].seqNo = (seqNo + 1) % 65535;
                hashTriplet(publications[val].id,publications[val].seqNo,publications[val].data,publications[val].dataSize,publications[val].hash);
                saveData();
            } else {//else if not mine
                publications[val].seqNo = seqNo;
                memcpy(publications[val].data, data, dataSize);
                publications[val].lastUpdate = time(0);
                publications[val].dataSize = dataSize;
                memcpy(publications[val].hash, hash, 16);
            }
        }
    }
}

//Add a node to the neighbour table based on info in client
void addNode(struct sockaddr_storage * client, socklen_t client_len){
    if(posNode < 15){
        getnameinfo((struct sockaddr *) client, client_len, neighbors[posNode].ip, sizeof(neighbors[posNode].ip), neighbors[posNode].port, sizeof(neighbors[posNode].port),NI_NUMERICHOST);

        if(posNode == 0){
            neighbors[posNode].isPermanent = 1;
        } else {
            neighbors[posNode].isPermanent = 0;
        }
        neighbors[posNode].lastSeen = time(0);
        posNode++;
    }
}

//Find a node in the neighbour table based on the info in client, returns -1 for no results or a int of neighbour[int] if a node is found
int findNode(struct sockaddr_storage * client, socklen_t client_len){
    char tempIp [INET6_ADDRSTRLEN];
    char tempPort [INET6_ADDRSTRLEN];

    getnameinfo((struct sockaddr *) client, client_len, tempIp, sizeof(tempIp), tempPort, sizeof(tempPort), NI_NUMERICHOST);
    
    for(int i = 0; i < posNode; i++){
       if(strcmp(neighbors[i].ip,tempIp) == 0 && strcmp(neighbors[i].port,tempPort) == 0){
            return i;
        }
    }
    return -1;
}

//Delete the node at neighbour[val]
void deleteNode(int val){
    if(val < 14){
        memcpy(&neighbors[val],&neighbors[val+1],sizeof(struct node) * (14 - val));
        posNode--;
    } else {
        memset(&neighbors[val], 0, sizeof(struct node));
        posNode--;
    }
    
}

//Pick a random int to be used for neighbour[int], returns -1 if list is empty
int pickRandomNode(){
    if(posNode == 0){
        return -1;//No nodes put in the list
    } else {
        return rand() % posNode;
    }
}

void buildPad1(unsigned char * buf){
    buf[0] = 0;
}

void buildPadN(unsigned char * buf, int n){
    buf[0] = 1;
    buf[1] = n;
    
    memset(&buf[2],0,n);
}

void buildNeighbourRequest(unsigned char * buf){
    buf[0] = 2;
    buf[1] = 0;
}

//Build a random neighbour to send, except n
void buildNeighbour(unsigned char * buf, int n){
    buf[0] = 3;
    buf[1] = 18;

    //Get a node
    int randNode = pickRandomNode();
    while(randNode == n){
        randNode = pickRandomNode();
    }

    struct node val = neighbors[randNode];

    inet_pton(AF_INET6,val.ip,&buf[2]);
    
    unsigned short port = htons(strtoul(val.port, NULL, 10));
    memcpy(&buf[18], &port, sizeof(unsigned short));//Copies the port into the buffer, takes 2 bytes
};

void buildNetworkHash(unsigned char * buf){
    buf[0] = 4;
    buf[1] = 16;
    hashNetwork(&buf[2]);
}

void buildNetworkStateRequest(unsigned char * buf){
    buf[0] = 5;
    buf[1] = 0;
}

void buildNodeHash(unsigned char * buf, int node){
    buf[0] = 6;
    buf[1] = 26;

    struct triplet tempPub = publications[node];

    memcpy(&buf[2], tempPub.id, 8);
    unsigned short x = htons(tempPub.seqNo);
    memcpy(&buf[10], &x, sizeof(unsigned short));
    //hashTriplet(tempPub.id,tempPub.seqNo,tempPub.data,tempPub.dataSize,&buf[12]);
    memcpy(&buf[12],tempPub.hash,16);
};

void buildNodeStateRequest(unsigned char * buf, unsigned char * id){
    buf[0] = 7;
    buf[1] = 8;
    memcpy(&buf[2], id, 8);
}

void buildNodeState(unsigned char * buf, int node){
    struct triplet tempPub = publications[node];

    buf[0] = 8;
    buf[1] = 26 + tempPub.dataSize;

    memcpy(&buf[2], tempPub.id, 8);
    unsigned short x = htons(tempPub.seqNo);
    memcpy(&buf[10], &x, sizeof(unsigned short));
    memcpy(&buf[12], tempPub.hash,16);
    memcpy(&buf[28], tempPub.data, tempPub.dataSize);
    unsigned char tempHash [16];
    hashTriplet(tempPub.id,tempPub.seqNo,tempPub.data,tempPub.dataSize,tempHash);
}

void buildWarning(unsigned char * buf, char * message){
    buf[0] = 9;
    buf[1] = strlen(message);
    strcpy((char *)&buf[2], message);
}

void buildHeader(unsigned char * buf, uint16_t val){//Build the header of a packet
    buf[0] = 95;
    buf[1] = 1;
    unsigned short temp = htons(val);
    memcpy(&buf[2], &temp, sizeof(uint16_t));
}

//Send replySize bytes from tempReply pointer to the adress in client from the socket s
void prepareAndSend(unsigned char * tempReply, int s, struct sockaddr * client, socklen_t client_len, unsigned int replySize){
    if(replySize > 4){
        unsigned char reply[replySize];
        buildHeader(reply,replySize-4);
        memcpy(&reply[4],&tempReply[4],replySize-4);

        int r = sendto(s, reply, sizeof(reply), 0, client, client_len);
        if (r < 0){
            perror("error : sendto\n");
        }
    }
}

//Handle a whole packet and make sure every TLV inside it is treated, reply are sent to client
void handle_client(unsigned char * buf, int s, struct sockaddr * client, socklen_t client_len, int truePacketSize){

    unsigned short headerPacketSize = ntohs(*((uint16_t *)&buf[-2]));
    unsigned char tempReply [1024];//Temporary buffer for the answer
    unsigned short replyPos = 4;//Position in the tempReply buffer, assuming the header is in
    unsigned short bufPos = 0;//Position in the buf buffer, should always be a the start of a TLV

    //Check the size of the header
    if(headerPacketSize != truePacketSize-4){
        char message [192] = "Size indicated in the header differ real packet size";
        replyPos = 4 + strlen(message);
        buildWarning(&tempReply[replyPos],message);
        prepareAndSend(tempReply,s,client,client_len,replyPos);
        return;
    }

    //While every TLV inside the buffer isn't treated
    while(bufPos < headerPacketSize){
        
        uint8_t type = buf[bufPos];//1 Byte
        uint8_t tlvSize = buf[bufPos+1];//1 Byte, size without the 2 bit TLV header

        //If bufPos + the size of the next TLV exceed the size of the packet
        if(bufPos + tlvSize + 2 > headerPacketSize){
            prepareAndSend(tempReply,s,client,client_len,replyPos);
            char message [192] = "TLV beyond packet size";
            replyPos = 4 + strlen(message);
            buildWarning(&tempReply[replyPos],message);
            break;
        }
        
        //If the type seen in the TLV is unknown
        if(type < 0 || type > 9){
            prepareAndSend(tempReply,s,client,client_len,replyPos);
            char message [192] = "Unexpected content : type seen is < 0 or > 9";
            replyPos = 4 + strlen(message);
            buildWarning(&tempReply[replyPos],message);
            break;
        }

        //If the size of the TLV is too big for any possible TLV
        if(tlvSize < 0 || tlvSize > 222){
            prepareAndSend(tempReply,s,client,client_len,replyPos);
            char message [192] = "Unexpected content : TLV Size exceeds maximum possible size";
            replyPos = 4 + strlen(message);
            buildWarning(&tempReply[replyPos],message);
            break;
        }

        if(type == 0){
            bufPos += 1;
            //Do nothings whatsoever
        } else if (type == 1){
            bufPos += 2+tlvSize;
            //Same but longer

        } else if (type == 2){
            //Check if the TLV seen isn't bigger than the packet received
            if(bufPos + 2 > truePacketSize - 4){
                prepareAndSend(tempReply,s,client,client_len,replyPos);
                char message [192] = "Unexpected content : TLV Size beyond packet end";
                replyPos = 4 + strlen(message);
                buildWarning(&tempReply[replyPos],message);
                break; 
            }

            //Send if the reply buffer is full
            if(replyPos+20 > sizeof(tempReply)){
                prepareAndSend(tempReply,s,client,client_len,replyPos);
                replyPos = 4;
            }

            //Add desired response to the reply buffer
            if(posNode > 1){
                int val = findNode((struct sockaddr_storage *)client, client_len);
                buildNeighbour(&tempReply[replyPos],val);
                replyPos += 20;
            }
        
            bufPos += 2+tlvSize;

        } else if (type == 3){
            if(bufPos + 20 > truePacketSize - 4){
               prepareAndSend(tempReply,s,client,client_len,replyPos);
                char message [192] = "Unexpected content : TLV Size beyond packet end";
                replyPos = 4 + strlen(message);
                buildWarning(&tempReply[replyPos],message);
                break; 
            }

            unsigned char reply[22];
            buildHeader(reply,18);
            buildNetworkHash(&reply[4]);

            char neighbourIp [INET6_ADDRSTRLEN];
            char neighbourPort [INET6_ADDRSTRLEN];
            memset(neighbourIp,0,46);

            inet_ntop(AF_INET6,&buf[bufPos + 2],neighbourIp,client_len);
            sprintf(neighbourPort,"%hu",ntohs(*((uint16_t *)&buf[bufPos + 18])));
            
            struct addrinfo hints, *servinfo;
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_DGRAM;

            int r = getaddrinfo(neighbourIp, neighbourPort, &hints, &servinfo);
            if(r < 0){
                fprintf(stderr, "Error at type 3 | getaddrinfo : %s\n", gai_strerror(r));
                return;
            }

            sendto(s, reply, sizeof(reply), 0, servinfo->ai_addr, servinfo->ai_addrlen);
            if(r < 0){
                printf("Error at type 3 | sendto\n");
                return;
            }
            
            bufPos += 2+tlvSize;

        } else if (type == 4){

            if(bufPos + 18 > truePacketSize - 4){
               prepareAndSend(tempReply,s,client,client_len,replyPos);
                char message [192] = "Unexpected content : TLV Size beyond packet end";
                replyPos = 4 + strlen(message);
                buildWarning(&tempReply[replyPos],message);
                break; 
            }

            unsigned char myNetworkHash [16];
            unsigned char hisNetworkHash [16];

            memcpy(hisNetworkHash,&buf[bufPos + 2],16);
            hashNetwork(myNetworkHash);

            //Compare network hashes and ask for stuff if they do not match
            if(memcmp(myNetworkHash,hisNetworkHash,16) != 0){ 
                if(replyPos+2 > sizeof(tempReply)){//2 is the size of a TLV Network State Request
                    prepareAndSend(tempReply,s,client,client_len,replyPos);
                    replyPos = 4;
                }
                buildNetworkStateRequest(&tempReply[replyPos]);
                replyPos += 2;
            }
            
            bufPos += 2+tlvSize;
            
        } else if (type == 5){
            if(bufPos + 2 > truePacketSize - 4){
               prepareAndSend(tempReply,s,client,client_len,replyPos);
                char message [192] = "Unexpected content : TLV Size beyond packet end";
                replyPos = 4 + strlen(message);
                buildWarning(&tempReply[replyPos],message);
                break; 
            }

            int requestDealt = 0;//Nb of request we dealt with
            while(requestDealt < posTrip){//While there are still undealt request in the buffer
                if(replyPos+28 > sizeof(tempReply)){
                    prepareAndSend(tempReply,s,client,client_len,replyPos);
                    replyPos = 4;
                }
                    
                while(replyPos < sizeof(tempReply) && requestDealt < posTrip){//While data can still be put in our temporary buffer
                    if(replyPos + 28 < sizeof(tempReply)){//If the data we're going to put won't exceed the size of the buffer
                        buildNodeHash(&tempReply[replyPos],requestDealt);
                        replyPos += 28;//Update the size of our updated buffer
                        requestDealt++;
                    } else {
                        break;//Can't put any more data
                    }
                }
            }
            
            bufPos += 2+tlvSize;

        } else if (type == 6){
            if(bufPos + 28 > truePacketSize - 4){
               prepareAndSend(tempReply,s,client,client_len,replyPos);
                char message [192] = "Unexpected content : TLV Size beyond packet end";
                replyPos = 4 + strlen(message);
                buildWarning(&tempReply[replyPos],message);
                break; 
            }

            if(replyPos+10 > sizeof(tempReply)){
                prepareAndSend(tempReply,s,client,client_len,replyPos);
                replyPos = 4;
            }

            unsigned char * id = &buf[bufPos + 2];
            unsigned short seqNo = ntohs(*((unsigned short *)&buf[bufPos+10]));
            unsigned char * annoncedHash = &buf[bufPos+12];

            int pubNb = getTriplet(id);

            //Only ask for a node state if : Don't known this id OR his seqNo is bigger than mine OR the hash of the data is different from mine
            if(pubNb == -1 || isBigger(seqNo,publications[pubNb].seqNo) == 1 || memcmp(publications[pubNb].hash,annoncedHash,16) != 0){
                buildNodeStateRequest(&tempReply[replyPos],id);
                replyPos += 10;
            }           

            bufPos += 2+tlvSize;

        } else if (type == 7){
            if(bufPos + 10 > truePacketSize - 4){
                prepareAndSend(tempReply,s,client,client_len,replyPos);
                char message [192] = "Unexpected content : TLV Size beyond packet end";
                replyPos = 4 + strlen(message);
                buildWarning(&tempReply[replyPos],message);
                break; 
            }
            
            unsigned char * id = &buf[bufPos + 2];
            int pubNb = getTriplet(id);

            if(replyPos + 28 + publications[pubNb].dataSize > sizeof(tempReply)){
                prepareAndSend(tempReply,s,client,client_len,replyPos);
                replyPos = 4;
            }

            buildNodeState(&tempReply[replyPos],pubNb);
            replyPos += 28 + publications[pubNb].dataSize;

            bufPos += 2+tlvSize;
        
        } else if (type == 8){
            if(buf[bufPos+1]-26 > 192 || buf[bufPos+1]-26 < 0){
                prepareAndSend(tempReply,s,client,client_len,replyPos);
                char message [192] = "Unexpected content : Data size exceeds 192 characters";
                replyPos = 4 + strlen(message);
                buildWarning(&tempReply[replyPos],message);
                break;
            } else if(bufPos + 28 + buf[bufPos+1]-26 > truePacketSize - 4) {
                prepareAndSend(tempReply,s,client,client_len,replyPos);
                char message [192] = "Unexpected content : TLV Size beyond packet end";
                replyPos = 4 + strlen(message);
                buildWarning(&tempReply[replyPos],message);
                break; 
            }
        
            unsigned char * id = &buf[bufPos + 2];
            unsigned short seqNo = ntohs(*((unsigned short *)&buf[bufPos+10]));
            char * data = (char *)&buf[bufPos+28];
            uint8_t dataSize = buf[bufPos+1]-26;

            int pubPos = getTriplet(id);

            unsigned char * annoncedHash = &buf[bufPos+12];
            unsigned char calculatedHash [16];

            if(pubPos != -1){//If this ID is already in my list
                if(memcmp(publications[pubPos].hash,annoncedHash,16) != 0){//Compare his hashes and my stocked one, if they are different
                    hashTriplet(id,seqNo,data,dataSize,calculatedHash);//Recalculate the hash with the new values
                    if(memcmp(calculatedHash,annoncedHash,16) == 0){//Recompare the new hashes to make sure they match
                        if(isBigger(seqNo,publications[0].seqNo) == 1){//If his seqNo is bigger than the one i have
                            addTriplet(id,seqNo,data,dataSize,annoncedHash);//Update the data
                        }
                    } else {//The hash in the TLV is incorrect, sending out warning
                        prepareAndSend(tempReply,s,client,client_len,replyPos);
                        char message [192] = "Wrong hash detected";
                        replyPos = 4 + strlen(message);
                        buildWarning(&tempReply[replyPos],message);
                    }
                }
            } else {//If i don't already have the id in my list
                hashTriplet(id,seqNo,data,dataSize,calculatedHash);//Hash it
                if(memcmp(calculatedHash,annoncedHash,16) == 0){//Make sure they match
                    addTriplet(id,seqNo,data,dataSize,annoncedHash);//Add the new data
                }  else {
                    prepareAndSend(tempReply,s,client,client_len,replyPos);
                    char message [192] = "Wrong hash detected";
                    replyPos = 4 + strlen(message);
                    buildWarning(&tempReply[replyPos],message);
                }
            }

            bufPos += 2+tlvSize;
            
        } else if (type == 9){
            printf("TLV Warning Received : ");
            printData((char *)&buf[2],(uint8_t)buf[1]);
            printf("\n");
            bufPos += 2+tlvSize;
        }
    }
    
    prepareAndSend(tempReply,s,client,client_len,replyPos);
}

//Check if the header is fine
int stripUDP(unsigned char * buf, int len){
    if(buf[0] != 95 || buf[1] != 1 || *((unsigned short *)&buf[2]) > len+4){
        return -1;
    } else {
        return 1;
    }
}

//Manage the neighbour list, kicking dead clients and sending TLV Network hashes to alive ones
//Also sends TLV Neighbour Request to known clients
void manageList(time_t * t, int s, int argc, char const *argv[]){
    if(time(0) > *t+20 || posNode == 0){
        *t = time(0);
        
        struct addrinfo clientHints, *clientServer;
        
        memset(&clientHints, 0, sizeof clientHints);
        clientHints.ai_family = AF_UNSPEC;
        clientHints.ai_socktype = SOCK_DGRAM;

        for(int i = 0; i < posNode; i++){//Check if node isn't timed out yet
            if((time(0) - neighbors[i].lastSeen) >= 70 && neighbors[i].isPermanent == 0){
                deleteNode(i);
            } else if(posTrip > 0){
                unsigned char reply[22];
                buildHeader(reply,18);
                buildNetworkHash(&reply[4]);

                int r = getaddrinfo(neighbors[i].ip, neighbors[i].port, &clientHints, &clientServer);
                if(r < 0){
                    return;
                }

                sendto(s, reply, sizeof(reply), 0, clientServer->ai_addr, clientServer->ai_addrlen);
                if(r < 0){
                    return;
                }
            }
        }


        if(posNode < 5){//Search for more if less than 5 nodes are in found
            unsigned char reply[6];
            buildHeader(reply,2);
            
            if(posNode == 0){
                buildNetworkStateRequest(&reply[4]);
            
                if(argc > 2){
                    printf("List is empty, sending TLV Neighbour Request at '%s:%s'\n",argv[1], argv[2]);

                    int r = getaddrinfo(argv[1], argv[2], &clientHints, &clientServer);
                    if(r < 0){
                        fprintf(stderr, "Error at ManageList | getaddrinfo : %s\n", gai_strerror(r));
                        return;
                    }
                } else {
                    printf("List is empty, sending TLV Neighbour Request at 'jch.irif.fr:1212'\n");

                    int r = getaddrinfo("jch.irif.fr", "1212", &clientHints, &clientServer);
                    if(r < 0){
                        fprintf(stderr, "Error at ManageList | getaddrinfo : %s\n", gai_strerror(r));
                        return;
                    }
                }  

                int r = sendto(s, reply, sizeof(reply), 0, clientServer->ai_addr, clientServer->ai_addrlen);
                if(r < 0){
                    return;
                }
            } else {
                int val = pickRandomNode();
                if(val != -1){
                    buildNeighbourRequest(&reply[4]);

                    int r = getaddrinfo(neighbors[val].ip, neighbors[val].port, &clientHints, &clientServer);
                    if(r < 0){
                        perror("Error : getaddrinfo");
                        return;
                    }

                    sendto(s, reply, sizeof(reply), 0, clientServer->ai_addr, clientServer->ai_addrlen);   
                    if(r < 0){
                        perror("Errorrr : sendTo");
                        return;
                    }
                }
            }
        }
    } 
}

//Update myMessage and it's related publication with the one in data
void updateMyMessage(char * data){
       
    publications[0].seqNo = (publications[0].seqNo + 1) % 65535;
    memcpy(publications[0].data, data, 192);
    if(publications[0].data[strlen(data)-1] == '\n'){
        publications[0].data[strlen(data)-1] = '\0';//This is here so that the return to line isn't counted in the text
    }
    publications[0].dataSize = strlen(publications[0].data);
    hashTriplet(publications[0].id,publications[0].seqNo,publications[0].data,publications[0].dataSize,publications[0].hash);
    saveData();
}

//Generate an id on the next 8 bytes starting at id
void generateId(unsigned char * id){
    for(int i = 0; i < 8; i++){
        id[i] = rand() % 255;
    }
}

int main(int argc, char const *argv[]){
    srand(time(NULL));

    //Set up pipes to communicate between father/son to change data
    int descripteurTube[2];
    char messageLire[192], messageEcrire[1000];

    if(pipe(descripteurTube) != 0){
        exit(0);
    }

    if(fcntl(descripteurTube[0], F_SETFL, O_NONBLOCK) < 0) {
        exit(0);
    }
        
    //Set up the fork
    pid_t pid_fils;
    pid_fils = fork();

    if(pid_fils == -1){
        perror("fork() failed\n");
        exit(0);
    } else if(pid_fils == 0){//Son
        prctl(PR_SET_PDEATHSIG, SIGHUP);//Kills the process if the father dies
        fflush(stdout);//Allows for printf to display 
        close(descripteurTube[1]);//Close this end of the pipe

        //Server part initialisation
        int sock = socket(AF_INET6, SOCK_DGRAM, 0);
        if (sock < 0){
            perror("error : socket");
            close(sock);
            exit(0);
        }

        struct sockaddr_in6 server;
        memset(&server, 0, sizeof(server));
        server.sin6_family = AF_INET6;
        server.sin6_port = htons(2020);

        int r = bind(sock, (struct sockaddr*)&server, sizeof(server));
        if (r < 0){
            close(sock);
            perror("error : recvfrom");
            exit(0);
        }

        neighbors = malloc(sizeof(struct node) * 15);
        publications = malloc(sizeof(struct triplet) * pubSize);

        //Loads up the file in ../resources/data.txt or generates one with a new ID if it does not exist
        FILE * f;
        f = fopen("resources/data.txt","r");
        if(f != 0){
            char id [192];
            char seqNo [192];
            char data [192];

            fgets(id,192,f);
            fgets(seqNo,192,f);
            fgets(data,192,f);

            unsigned char myId [8];
            unsigned short mySeqNo = atoi(seqNo);

            char * pos = id;

            for (size_t count = 0; count < sizeof myId / sizeof *myId; count++){
                sscanf(pos, "%02x", (unsigned int *)&myId[count]);
                pos += 2;
            }

            unsigned char hash [16];
        
            hashTriplet(myId,mySeqNo,data,strlen(data),hash);
            addTriplet(myId,mySeqNo,data,strlen(data),hash);
            fclose(f);
        } else {//No data found, generate new data
            unsigned char id [8];
            unsigned short seqNo = 1;
            char data [192] = "Premier lancement";
            generateId(id);

            unsigned char hash[16];
            hashTriplet(id, seqNo, data, strlen(data), hash);
            addTriplet(id, seqNo, data, strlen(data), hash);
            saveData();
        }
        printPubList();

        //Main loop initialisation
        time_t timer = time(0);
        struct pollfd fd;
        int res;
        fd.fd = sock;
        fd.events = POLLIN;

        printf("Started client\n\n");
    
        //**Main loop start**

        while (1){//Main loop

            //This part only triggers when something is written in the terminal
            if(read(descripteurTube[0], messageLire, 192) != -1){
                if(strlen(messageLire) > 1){//If there's a message
                    system("clear");
                    updateMyMessage(messageLire);
                    printPubList();
                    printf("\n");
                    printNodeList();
                    printf("\n\n");
                    timer = time(0) - 30;
                    if(strcmp(messageLire,"exit\n") == 0){
                        free(publications);
                        free(neighbors);
                        exit(0);
                    }
                } else {//If the only entry is a backspace
                    system("clear");
                    printPubList();
                    printf("\n");
                    printNodeList();
                }
            }
            
            manageList(&timer, sock, argc, argv);

            res = poll(&fd, 1, 1000);//Timemout every 1 seconds

            if(res == 0){
                
            } else {
                struct sockaddr_storage their_addr;             
                socklen_t addr_len;
                unsigned char buf[1024];

                int size = recvfrom(sock, buf, 1024, 0, (struct sockaddr *)&their_addr, &addr_len);
                if (size < 0){
                    continue;
                }
                
                socklen_t client_len = sizeof(their_addr);
                if(stripUDP(buf, r)){//Check if the UDP packet has the header
                    int n = findNode(&their_addr, client_len);
                    if(n != -1){ //Check if fthe message received is from a known node
                        neighbors[n].lastSeen = time(0);
                    } else{ //packet is from an unknown sender
                        if (posNode < 15){ //if space is available in the node table
                            addNode(&their_addr, client_len);
                            printNodeList();
                        }
                    }
                    handle_client(&buf[4],sock,(struct sockaddr *)&their_addr, client_len, size);
                }

                manageList(&timer, sock, argc, argv);
            }
        }
    } else {//Father
        close(descripteurTube[0]);

        while(1){
            fgets(messageEcrire,1000,stdin);
            write(descripteurTube[1], messageEcrire, 192);
            if(strcmp(messageEcrire,"exit\n") == 0){
                printf("Stopping\n");
                exit(0);
            }
        }

    }

    return 0;
}