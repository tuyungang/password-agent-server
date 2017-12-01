/* *******************************************************
 * Call Center On Demand Product Series
 * Copyright (C) 2017 HonDa(Guangzhou.) Technology Ltd., Co.
 * All right reserved
 *
 * @file main.c
 * @brief 
 * @author tuyungang
 * @version v1.0
 * @date 2017-12-01
 * 
 * TODO: main
 * 
 * *******************************************************
 */
#include "thread_pool.h"
#include "ini_config.h"

#define USER_LIMIT 1000
#define TASK_LIMIT 1000
#define MAX_FD     1000

static int sig_pipefd[2];

extern char m_DownStream_Buffer[128];

extern char g_LoginName[10];
extern char g_LoginPassword[128];
extern char g_MasterIP[32];
extern char g_StandbyIP[32];
extern char g_Port[10];
extern char g_SystemName[10];
extern char g_SafeBoxID[128];
extern char g_CurAbsolutePath[256];
extern char g_LogAbsolutePath[256];
extern char g_CacheFileAbsolutePath[256];

void *StartThreadPool()
{
    agent_threadpool_conf_t thread_conf = {10,0,0};
    agent_threadpool_t *pool = agent_threadpool_init(&thread_conf);
    if (pool == NULL) {
        return NULL;
    }
    return (void*)pool;
}
static void SigalHandler(int sig)
{
    int save_errno = errno;
    int msg = sig;
    send( sig_pipefd[1], ( char* )&msg, 1, 0 );
    errno = save_errno;
}

void addsig( int sig, void( handler )(int), bool restart)
{
    struct sigaction sa;
    memset( &sa, '\0', sizeof( sa ) );
    sa.sa_handler = handler;
    if( restart )
    {
        sa.sa_flags |= SA_RESTART;
    }
    sigfillset( &sa.sa_mask );
    assert( sigaction( sig, &sa, NULL ) != -1 );
}

int setnonblocking( int fd )
{
    int old_option = fcntl( fd, F_GETFL );
    int new_option = old_option | O_NONBLOCK;
    fcntl( fd, F_SETFL, new_option );
    return old_option;
}

void TaskInit(agent_task_t *ptask, int sockfd, struct pollfd *pfd)
{
    //ptask->DownStreamPfd = pfd;
    ptask->argv = NULL;
    ptask->handler = NULL;
    ptask->ReceiveRequest = Req_ReceiveRequest;
    ptask->ProcessRequest = Req_ProcessRequest;
    ptask->sockfd = sockfd;
    ptask->UpstreamSockfd = -1;
    ptask->lAppID = 0;
    //memset(ptask->szPassword, '\0', 64);
    memset(ptask->szVaultID, '\0', 128);
    //memset(ptask->SeqNumber, '\0', 32);
    memset(ptask->DownStreamBuffer, '\0', 256);
    memset(ptask->UpStreamBuffer, '\0', 1024);
    ptask->next = NULL;
    ptask->bIsActiveUpdate = false;
    ptask->GetFormFlag = 0;
}

void CheckIsDirExist()
{
    //char g_CurAbsolutePath[256];
    //char g_LogAbsolutePath[256];
    //char g_CacheFileAbsolutePath[256];

    memset(g_CurAbsolutePath, '\0', 256);
    memset(g_LogAbsolutePath, '\0', 256);
    memset(g_CacheFileAbsolutePath, '\0', 256);
    if (NULL == getcwd(g_CurAbsolutePath, 256)) {
    }
    sprintf(g_LogAbsolutePath, "%s/%s",g_CurAbsolutePath, "log");
    if (opendir(g_LogAbsolutePath) == NULL) {
        mkdir((const char*)g_LogAbsolutePath, S_IRWXU|S_IRWXG|S_IRWXO);
    }
    sprintf(g_CacheFileAbsolutePath, "%s/%s",g_CurAbsolutePath, "pswcache");
    if (opendir(g_CacheFileAbsolutePath) == NULL) {
        mkdir((const char*)g_CacheFileAbsolutePath, S_IRWXU|S_IRWXG|S_IRWXO);
    }
}

bool GetIniConfig()
{
    bool bRet;
    memset(g_LoginName, '\0', 10);
    memset(g_LoginPassword, '\0', 128);
    memset(g_MasterIP, '\0', 32);
    memset(g_StandbyIP, '\0', 32);
    memset(g_Port, '\0', 10);
    memset(g_SystemName, '\0', 10);
    memset(g_SafeBoxID, '\0', 128);

    bRet = InitIniConfig();
    if (bRet) {
        GetIniKeyString("[service]", "login_name", g_LoginName);
        printf("%s\n",g_LoginName);
        GetIniKeyString("[service]", "password", g_LoginPassword);
        printf("%s\n",g_LoginPassword);
        GetIniKeyString("[service]", "master_ip", g_MasterIP);
        printf("%s\n",g_MasterIP);
        GetIniKeyString("[service]", "standby_ip", g_StandbyIP);
        printf("%s\n",g_StandbyIP);
        GetIniKeyString("[service]", "port", g_Port);
        printf("%s\n",g_Port);
        GetIniKeyString("[service]", "system_name", g_SystemName);
        printf("%s\n",g_SystemName);
        GetIniKeyString("[service]", "safe_box_id", g_SafeBoxID);
        printf("%s\n",g_SafeBoxID);

    } else {
        memcpy(g_LoginName, "aimuser", strlen("aimuser"));
        memcpy(g_LoginPassword, "7da43a4dc548515c5616d928e968ddfbc9b20d96", strlen("7da43a4dc548515c5616d928e968ddfbc9b20d96"));
        memcpy(g_MasterIP, "192.168.2.3", strlen("192.168.2.3"));
        memcpy(g_StandbyIP, "192.168.2.3", strlen("192.168.2.3"));
        memcpy(g_SystemName, "huawei@aim", strlen("huawei@aim"));
        memcpy(g_SafeBoxID, "2478cbd7fe8f4f22810664407e01f437", strlen("2478cbd7fe8f4f22810664407e01f437"));
    }

    return true;
}

int main(int argc, char **argv)
{
    bool bRet;
    CheckIsDirExist();
    GetIniConfig();

    agent_threadpool_t *pool = NULL;
REPOOLINIT:
    pool = (agent_threadpool_t *)StartThreadPool();
    if (pool == NULL) {
        printf("thread pool init failed, once again!\n");
        goto REPOOLINIT;
        //return -1;
    }
    printf("thread pool init successfully!\n");

    int ret = socketpair( PF_UNIX, SOCK_STREAM, 0, sig_pipefd );
    assert( ret != -1 );

    //addsig( SIGPIPE, SIG_IGN, false);
    //addsig( SIGTERM, SigalHandler, true );
    //addsig( SIGINT, SigalHandler, true );
    //setnonblocking( sig_pipefd[0] );

    //bool bRet;
    struct timespec ts;
    struct timeval  tp;
    gettimeofday(&tp, NULL);
    ts.tv_sec = tp.tv_sec + 10;
    ts.tv_nsec = tp.tv_usec * 1000;
    while (1) {
        pthread_mutex_lock( &pool->OnceUpdateMutex );
        ret = pthread_cond_timedwait( &pool->OnceUpdateCond, &pool->OnceUpdateMutex, &ts);
        pthread_mutex_unlock( &pool->OnceUpdateMutex );
        if (ret == 0) {
            printf("main thread cache\n");
            bRet = pool->UpdateLocalPswCache((void*)pool);
            if (!bRet) {
                //log();
            } else {
                printf("main thread updating password cache\n");
                //log();
                sleep(3);
            }
            break;
        }
        break;
    }

    const char* local_ip = "127.0.0.1";
    int port = atoi( "12345" );
    int m_listenfd = socket( PF_INET, SOCK_STREAM, 0 );
    assert( m_listenfd >= 0 );
    struct linger tmp = { 1, 0 };
    setsockopt( m_listenfd, SOL_SOCKET, SO_LINGER, &tmp, sizeof( tmp ) );

    ret = 0;
    struct sockaddr_in address;
    //bzero( &address, sizeof( address ) );
    memset( &address, 0, sizeof( address ) );
    address.sin_family = AF_INET;
    inet_pton( AF_INET, local_ip, &address.sin_addr );
    address.sin_port = htons( port );

    ret = bind( m_listenfd, ( struct sockaddr* )&address, sizeof( address ) );
    assert( ret >= 0 );

    ret = listen( m_listenfd, 5 );
    assert( ret >= 0 );

    agent_task_t task[TASK_LIMIT];

    int task_counter = 0;
    struct pollfd m_pollfds[USER_LIMIT+1];
    int i;
    for (i = 2; i <= USER_LIMIT; ++i) {
        m_pollfds[i].fd = -1;
        m_pollfds[i].events = 0;
    }
    m_pollfds[0].fd = m_listenfd;
    m_pollfds[0].events = POLLIN | POLLERR | POLLHUP;
    m_pollfds[0].revents = 0;

    m_pollfds[1].fd = sig_pipefd[0];
    m_pollfds[1].events = POLLIN | POLLERR | POLLHUP;
    m_pollfds[1].revents = 0;

    //RunPoll();
    bool m_stop = false;
    while (!m_stop)
    {
        int ret = poll(m_pollfds, task_counter + 1, -1);
        if (ret < 0) {
            printf("poll failure\n");
            //Log();
            m_stop = true;
            //break;
        }
        int i;
        for (i = 0; i < task_counter + 1; ++i)
        {
            int sockfd = m_pollfds[i].fd;
            if ((m_pollfds[i].fd == m_listenfd) && ((m_pollfds[i].revents & POLLIN) == POLLIN)) {
                struct sockaddr_in client_address;
                socklen_t client_addrlength = sizeof( client_address );
                int connfd = accept( m_listenfd, ( struct sockaddr* )&client_address, &client_addrlength );
                if ( connfd < 0 )
                {
                    printf( "errno is: %d\n", errno );
                    continue;
                }

                if( task_counter >= MAX_FD )
                {
                    close(sockfd);
                    send(sockfd, "Internal server busy", strlen("Internal server busy"), 0);
                    //show_error( connfd, "Internal server busy" );
                    continue;
                }
                
                SetNonBlocking(connfd);
                task_counter++;
                //addfd(m_pollfds[task_counter], connfd);
                m_pollfds[task_counter].fd = connfd;
                m_pollfds[task_counter].events = POLLIN | POLLERR | POLLHUP;
                m_pollfds[task_counter].revents = 0;
                TaskInit(&task[connfd], connfd, &m_pollfds[task_counter]);
                printf("a client come\n");
                break;
            }
            if ((m_pollfds[i].fd == sig_pipefd[0]) && (m_pollfds[i].revents & POLLIN)) {
                int sig;
                char signals[1024];
                ret = recv( sig_pipefd[0], signals, sizeof( signals ), 0 );
                if( ret <= 0 ) {
                    continue;
                } else {
                    int j;
                    for( j = 0; j < ret; ++j ) {
                        switch( signals[j] )
                        {
                            case SIGTERM:
                            case SIGINT:
                            {
                                m_stop = true;
                                agent_threadpool_destroy(pool);
                                break;
                            }
                            default:
                            {
                                break;
                            } 
                        }   
                    }
                }
            }
            else if (m_pollfds[i].revents & POLLERR) {
                printf("get an error from %d\n", m_pollfds[i].fd);
                char errors[100];
                memset(errors, '\0', 100);
                socklen_t length = sizeof(errors);
                if (getsockopt(m_pollfds[i].fd, SOL_SOCKET, SO_ERROR, &errors, &length) < 0) {
                    printf("get socket option failed\n");
                }
                continue;
            }
            else if (m_pollfds[i].revents & POLLHUP) {
                task[m_pollfds[i].fd] = task[m_pollfds[task_counter].fd];
                if (m_pollfds[i].fd != -1)
                    close(m_pollfds[i].fd);
                m_pollfds[i] = m_pollfds[task_counter];
                i--;
                task_counter--;
                printf("a client left %d\n", __LINE__);
            }
            else if (m_pollfds[i].revents & POLLIN) {
                if (task[sockfd].ReceiveRequest(&task[sockfd], pool)) {
                    agent_threadpool_add_task(pool, NULL, (void*)&(task[sockfd]));
                }
                else
                {
                    //users[sockfd].close_conn();
                    task[m_pollfds[i].fd] = task[m_pollfds[task_counter].fd];
                    if (task[m_pollfds[i].fd].sockfd != -1)
                        close(m_pollfds[i].fd);
                    m_pollfds[i] = m_pollfds[task_counter];
                    i--;
                    task_counter--;
                    printf("a client left %d\n", __LINE__);
                }
            }
            else if (m_pollfds[i].revents & POLLOUT) {
                printf("pollout %d\n", __LINE__);
                int nSendLen = strlen(m_DownStream_Buffer);
                while (nSendLen > 0)
                {
                    int nRealSend = send(m_pollfds[i].fd, m_DownStream_Buffer, nSendLen, 0);
                    if (nRealSend == -1)
                    {
                        if (m_pollfds[i].fd != -1)
                        {
                            //close(ptask->sockfd);
                            //ptask->sockfd = -1;
                            break;
                        }
                        //m_pool->Log("send req data info failed!");
                        break;
                    }
                    nSendLen -= nRealSend;
                }
                //memset(m_DownStream_Buffer, '\0', 128);
                task[m_pollfds[i].fd] = task[m_pollfds[task_counter].fd];
                if (task[m_pollfds[i].fd].sockfd != -1)
                    close(m_pollfds[i].fd);
                m_pollfds[i] = m_pollfds[task_counter];
                i--;
                task_counter--;
                //printf("a client left %d\n", __LINE__);

            }
        }
    }
    printf("agent server exit!\n");
    return 0;
}

