#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <assert.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

char *appid[] = {
    "604505634",
    "604505619",
    "604505683",
    "604505531",
    "604505612",
    "604505536",
    "604505713",
    "604505682",
    "604505659",
    "604505567",
    "604505691",
    "604505663",
    "604505573",
    "604505520",
    "604505624",
    "604505702",
    "604505626",
    "604505737",
    "604505651",
    "604505617",
    "604505590",
    "604505700",
    "604505535",
    "604505553",
    "604505694",
    "604505521",
    "604505645",
    "604505646",
    "604505656",
    "604505584",
    "604505582",
    "604505710",
    "604505623",
    "604505628",
    "604505604",
    "604505721",
    "604505562",
    "604505638",
    "604505570",
    "604505615",
    "604505696",
    "604505608",
    "604505565",
    "604505698",
    "604505640",
    "604505650",
    "604505653",
    "604505677",
    "604505516",
    "604505575",
    "604505586",
    "604505699",
    "604505733",
    "604505632",
    "604505609",
    "604505703",
    "604505605",
    "604505686",
    "604505731",
    "604505734",
    "604505739",
    "604505571",
    "604505690",
    "604505630",
    "604505611",
    "604505730",
    "604505662",
    "604505513",
    "604505580",
    "604505557",
    "604505649",
    "604505537",
    "604505655",
    "604505572",
    "604505704",
    "604505515",
    "604505593",
    "604505709",
    "604505711",
    "604505715",
    "604505627",
    "604505581",
    "604505583",
    "604505636",
    "604505740",
    "604505505",
    "604505728",
    "604505542",
    "604505578",
    "604505538",
    "604505614",
    "604505673",
    "604505552",
    "604505526",
    "604505670",
    "604505688",
    "604505621",
    "604505509",
    "604505697",
    "604505665",
    "604505606",
    "604505512",
    "604505732",
    "604505639",
    "604505508",
    "604505544",
    "604505601",
    "604505724",
    "604505729",
    "604505618",
    "604505588",
    "604505597",
    "604505555",
    "604505551",
    "604505541",
    "604505600",
    "604505576",
    "604505726",
    "604505561",
    "604505675",
    "604505718",
    "604505556",
    "604505517",
    "604505693",
    "604505592",
    "604505644",
    "604505533",
    "604505568",
    "604505506",
    "604505547",
    "604505647",
    "604505735",
    "604505522",
    "604505723",
    "604505667",
    "604505595",
    "604505708",
    "604505701",
    "604505566",
    "604505574",
    "604505637",
    "604505524",
    "604505625",
    "604505720",
    "604505707",
    "604505569",
    "604505712",
    "604505518",
    "604505658",
    "604505725",
    "604505669",
    "604505558",
    "604505546",
    "604505613",
    "604505529",
    "604505633",
    "604505652",
    "604505716",
    "604505654",
    "604505736",
    "604505549",
    "604505722",
    "604505598",
    "604505602",
    "604505599",
    "604505657",
    "604505528",
    "604505616",
    "604505519",
    "604505705",
    "604505511",
    "604505523",
    "604505603",
    "604505620",
    "604505717",
    "604505660",
    "604505607",
    "604505714",
    "604505629",
    "604505543",
    "604505539",
    "604505676",
    "604505635",
    "604505596",
    "604505540",
    "604505695",
    "604505594",
    "604505684",
    "604505514",
    "604505671",
    "604505510",
    "604505589",
    "604505689",
    "604505591",
    "604505563",
    "604505738",
    "604505648",
    "604505530",
    "604505643",
    "604505610",
    "604505525",
    "604505719",
    "604505622",
    "604505587",
    "604505666",
    "604505507",
    "604505661",
    "604505534",
    "604505672",
    "604505678",
    "604505706",
    "604505527",
    "604505674",
    "604505559",
    "604505545",
    "604505685",
    "604505692",
    "604505687",
    "604505679",
    "604505532",
    "604505641",
    "604505668",
    "604505550",
    "604505642",
    "604505727",
    "604505680",
    "604505585",
    "604505554",
    "604505579",
    "604505664",
    "604505681",
    "604505560",
    "604505631",
    "604505548",
    "604505564",
    "604505577",
};

int SetNonBlocking(int fd)
{
    int old_option = fcntl( fd, F_GETFL );
    int new_option = old_option | O_NONBLOCK;
    fcntl( fd, F_SETFL, new_option );
    return old_option;
}

void run_child()
{
    struct sockaddr_in address;
    memset( &address, 0, sizeof( address ) );
    address.sin_family = AF_INET;
    inet_pton( AF_INET, "127.0.0.1", &address.sin_addr );
    address.sin_port = htons( 12345 );
    int m_sockfd = -1;
    m_sockfd = socket( PF_INET, SOCK_STREAM, 0 );
    printf( "connectting main password server\n" );
    if( m_sockfd < 0 )
    {
        close(m_sockfd);
        return;
    }

    int reuse = 1, on = 1;
    setsockopt(m_sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    //SetNonBlocking(m_sockfd);
    //setsockopt(m_sockfd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on));

    if (  connect( m_sockfd, ( struct sockaddr* )&address, sizeof( address ) ) == 0  )
    {
        printf( "build connection successfully\n");
    } else {
        printf("connect fail\n");
    }

    int i;
    char sendData[256] = {0};
    for (i = 27; i < 28; i++) {
        int *pHeader = (int*)sendData;
        *pHeader = htonl(0x2000);
        pHeader += 1;
        int len = 0;
        len = sizeof(int) * 2;
        //len = strlen(appid[i]) + strlen("2478cbd7fe8f4f22810664407e01f437") + sizeof(int) * 2;
        //*pHeader = htonl(len);
        memcpy(sendData + len, "604505738"/*appid[i]*/, strlen("604505738")/*strlen(appid[i])*/);
        len += strlen(appid[i]);
        memcpy(sendData + len, "=", strlen("="));
        len += strlen("=");
        memcpy(sendData + len, "2478cbd7fe8f4f22810664407e01f437", strlen("2478cbd7fe8f4f22810664407e01f437"));
        len += strlen("2478cbd7fe8f4f22810664407e01f437");
        *pHeader = htonl(len);
        int sendlen = send(m_sockfd, sendData, len, 0);
        printf("client send:%s %d\n", sendData + 8, sendlen);

        char buf[128] = {0};
        int ret = recv(m_sockfd, buf, 128, 0);
        if (ret == 0) {
            printf("server close\n");
            break;
        }
        printf("get password: %s\n", buf);
        memset(sendData, '\0', 256);
        //usleep(50000);
        //sleep(1);
    }
    close(m_sockfd);
    printf("child process pid:%u test over\n", getpid());
    fflush(stdout);
    exit(0);
}

void run_parent()
{
    while (1)
        continue;
}

void usage(char *format)
{
    printf("%s\n", format);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        usage("[usage]: ./test number");
        return 1;
    }

    /*
    struct sockaddr_in address;
    memset( &address, 0, sizeof( address ) );
    address.sin_family = AF_INET;
    inet_pton( AF_INET, "127.0.0.1", &address.sin_addr );
    address.sin_port = htons( 12345 );
    int m_sockfd = -1;
    m_sockfd = socket( PF_INET, SOCK_STREAM, 0 );
    printf( "connectting main password server\n" );
    if( m_sockfd < 0 )
    {
        close(m_sockfd);
        return -1;
    }

    //reuse = 1, on = 1;
    //setsockopt(m_sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    //setsockopt(m_sockfd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on));

    if (  connect( m_sockfd, ( struct sockaddr* )&address, sizeof( address ) ) == 0  )
    {
        printf( "build connection successfully\n");
    } else {
        printf("connect fail\n");
    }
    */

    pid_t pid;
    int i;
    for (i = 0; i < atoi(argv[1]); ++i) {
        pid = fork();
        if (pid == 0) {
            run_child();
        }
        else {
            //printf("create child process pid:%u\n", pid);
            continue;
        }
    }
    run_parent();

    return 0;
}
