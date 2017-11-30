#ifndef _THREAD_POOL_H
#define _THREAD_POOL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <sys/poll.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <fcntl.h>
#include <syslog.h>
#include <ctype.h>
#include <sys/time.h>
#include <semaphore.h>
#include <dirent.h>

#include "cryptdatafunc.h"
#include "libxml/parser.h"
#include "libxml/parser.h"
#include "sys_queue.h"

#define MAX_TASK_SIZE 99999999
#define RETRY_CONNECT_MAX_COUNT 3
//#define MAX_EVENT_NUMBER 10000

static 	pthread_key_t  key;
typedef void* (*CB_FUN)(void *);
typedef bool (*TSK_FUN)(void *, void *);
//typedef bool (*TSK_FUN_PROCESS)(void *, void *, int *);
typedef bool (*POOL_UPDATE_FUN)(void *);

typedef struct _sPthreadFdInfo
{
    pthread_t fd;
    int isOnline;
}sPthreadFdInfo, *psPthreadFdInfo;

typedef struct _sLocalPswCacheInfo
{
    TAILQ_ENTRY(_sLocalPswCacheInfo) next;
    long        lAppID;
    char        szPassword[64];
    char        szVaultID[128];
    time_t      tmChange;
    CB_FUN      handler;
    unsigned int lock;   
}sLocalPswCacheInfo, *psLocalPswCacheInfo;

typedef struct task
{
    //struct pollfd *DownStreamPfd;
	void		     *argv; 
	CB_FUN		     handler; 
    TSK_FUN          ReceiveRequest;
    TSK_FUN          ProcessRequest;
	struct task      *next; 
    int              sockfd;
    int              UpstreamSockfd;
    long             lAppID;
    //char           szPassword[64];
    char             szVaultID[128];
    //char           SeqNumber[32];
    char             DownStreamBuffer[256];
    char             UpStreamBuffer[1024];
    bool             bIsActiveUpdate;
    int              GetFormFlag;
}myproxy_task_t;

typedef struct _sLogInfo
{
    TAILQ_ENTRY(_sLogInfo) next;
    char                  logBuffer[256];
    CB_FUN                handler;
    unsigned int          lock;
}sLogInfo, *psLogInfo;

typedef struct task_queue
{
	myproxy_task_t *head; 
	myproxy_task_t **tail;	
	unsigned int maxtasknum; 
	unsigned int curtasknum; 
}myproxy_task_queue_t;

typedef struct threadpool
{
    TAILQ_HEAD(,_sLocalPswCacheInfo) LocalPswCacheQueue;
    TAILQ_HEAD(,_sLocalPswCacheInfo) UpdatePswDatFileQueue;
    TAILQ_HEAD(,_sLogInfo)           LogCacheQueue;

	pthread_mutex_t    mutex;  
	pthread_mutex_t    ThreadFdCountMutex;  
    pthread_mutex_t    OnceUpdateMutex;
	pthread_mutex_t    LocalPswCacheQueueMutex;  
    pthread_mutex_t    UpdatePswDatFileQueueMutex;  
    pthread_mutex_t    LogCacheQueueMutex;  
	pthread_mutex_t    FirstCheckIsUpdateMutex;  

	pthread_cond_t     cond;	
	pthread_cond_t     OnceUpdateCond;	

    sem_t              UpdatePswDatFileQueueSem;
    sem_t              LogCacheQueueSem;
    sem_t              TasksQueueSem;

	myproxy_task_queue_t  tasks;

	unsigned int       threadnum; 
	unsigned int       thread_stack_size; 
    unsigned int       ThreadFdCount;
    unsigned int       NetworkState;

    bool               bFirstCheckIsUpdate;
    bool               bOnceUpdate;

    POOL_UPDATE_FUN    UpdateLocalPswCache;

    sPthreadFdInfo     pfds[8];

}myproxy_threadpool_t;

typedef struct threadpool_conf
{
	unsigned int threadnum;    
	unsigned int thread_stack_size;
	unsigned int maxtasknum;
}myproxy_threadpool_conf_t;

void Log(const char* format, ... );  

int SetNonBlocking(int fd);
bool SelectListen(int sockfd);
int z_conf_check(myproxy_threadpool_conf_t *conf);
inline void z_task_queue_init(myproxy_task_queue_t* task_queue);
int z_thread_mutex_create(pthread_mutex_t *mutex);
inline void z_thread_mutex_destroy(pthread_mutex_t *mutex);
inline int z_thread_cond_create(pthread_cond_t *cond);
inline void z_thread_cond_destroy(pthread_cond_t *cond);
inline int z_thread_sem_create(sem_t *sem);
inline void z_thread_sem_destroy(sem_t *sem);
int z_threadpool_create(myproxy_threadpool_t *pool);
void *z_threadpool_cycle(void* argv);
void *z_threadpool_save(void* argv);
void *z_threadpool_log(void* argv);
void *z_threadpool_exit_cb(void* argv);
inline int z_thread_add(myproxy_threadpool_t *pool);
inline void z_change_maxtask_num(myproxy_threadpool_t *pool, unsigned int num);
inline int z_thread_key_create();
inline void z_thread_key_destroy();

myproxy_threadpool_t* myproxy_threadpool_init(myproxy_threadpool_conf_t *conf);
int myproxy_threadpool_add_task(myproxy_threadpool_t *pool, CB_FUN handler, void* argv);
void myproxy_threadpool_destroy(myproxy_threadpool_t *pool);
int myproxy_thread_add(myproxy_threadpool_t *pool);
int myproxy_set_max_tasknum(myproxy_threadpool_t *pool,unsigned int num);

bool GetPvaFromLocal(myproxy_threadpool_t *pool, char *appID, char *valueID, char *pswOut);
bool CheckIsNeedUpdate(myproxy_threadpool_t *pool);
bool UpdateLocalPswCache(void *arg);
bool LoadRawPswCacheFromBinFile(myproxy_threadpool_t *pool);
bool LoadPswCachedFromDatFile(myproxy_threadpool_t *pool, char *pszErrorInfo);
void SavePswToLocalCacheDatFile(sLocalPswCacheInfo *pswNew);
int EnCodeSendInfo(char* pszInSendData, int nInSendDataLen, char* pszOutEncodeData, int nEncodeType);
bool SendDataToServer(int* pnSocket, char* pszSendData, int nSendLen);
//bool SendRequestToUpstream(long appID, char *valueID, int *sockfd, char *szSeqNumber);
bool SendRequestToUpstream(long appID, char *valueID, int *sockfd);
bool GetOnePswFromLocalCache(myproxy_threadpool_t *pool, long appID, char *pswOut);
bool ProcessPswInfoFromUpstream(myproxy_threadpool_t *pool, myproxy_task_t *ptask);
bool GetDataFromServer(int pSockClient, char* pszRecvData, int* pRecvDataLen, char* pszErrorInfo);
bool SendDataToServer2(int pnSocket, char* pszSendData, int nSendLen, char* pszRecvData, int* pRecvDataLen, char* pszErrorInfo);
//bool ParseUpstreamXmlInfo(char *appID, char *valueID, char *pszXmlBuffer, int nBufferLen, char *pswOut, char *SeqNumber);
bool ParseUpstreamXmlInfo(char *appID, char *valueID, char *pszXmlBuffer, int nBufferLen, char *pswOut, long lAppID);
bool ParseLoginReqXmlData(char* pszSeqNumber, char* pszXmlBuffer, int nBufferLen);
bool VerifyLogin(int sockfd, char *localIP);
bool LoginPvaServer(int *sockfd);
void ChangeVariableNetworkState(myproxy_threadpool_t *pool, pthread_t pfd, bool isOnline);
bool NotifyUpdateCache(myproxy_threadpool_t *pool);
bool ReplaceLocalPswCache(char *appID, char *valueID, char *pswInfo, myproxy_threadpool_t *pool);
void ParseDownstreamInfo(char *appID, char *valueID, char *pszDecodeData, int nBufferLen);
bool ParseReActiveUpdateXmlInfo(char *appID, char *valueID, char *pszXmlBuffer, int nBufferLen, char *pswOut);
bool ParseRecvInfo(char *appID, char *valueID, char *pswReturn, char *pswIn, int type, char *seqNumber, long lAppID);
bool ActiveUpgradeLocalPswCache(char *buf, void *arg, myproxy_threadpool_t *pool);
void ReActiveUpdateLocalCache(char *buf, myproxy_threadpool_t* pool);
void SendDataToDownstream(char *pswSendData, myproxy_task_t *ptask);
void ProcessNewPswFromUpstream(char *buf, myproxy_threadpool_t *pool, myproxy_task_t *ptask);
bool ReadPvaPoll(struct pollfd *pfd, int *needrelogin, myproxy_threadpool_t *pool, void *arg, int sendready);
bool Req_ReceiveRequest(void *task, void *p);
bool Req_ProcessRequest(void *task, void *p);

#endif
