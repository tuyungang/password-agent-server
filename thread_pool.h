/* *******************************************************
 * Call Center On Demand Product Series
 * Copyright (C) 2017 HonDa(Guangzhou.) Technology Ltd., Co.
 * All right reserved
 *
 * @file thread_pool.h
 * @brief 
 * @author tuyungang
 * @version v1.0
 * @date 2017-12-01
 * 
 * TODO: 线程池 
 * 
 * *******************************************************/
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

//static 	pthread_key_t  key;
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

/* --------------------------------------------------------------------------*/
/**
 * @brief struct task
 * @description 任务结构定义
 */
/* ----------------------------------------------------------------------------*/
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
}agent_task_t;

typedef struct _sLogInfo
{
    TAILQ_ENTRY(_sLogInfo) next;
    char                  logBuffer[256];
    CB_FUN                handler;
    unsigned int          lock;
}sLogInfo, *psLogInfo;

typedef struct task_queue
{
	agent_task_t *head; 
	agent_task_t **tail;	
	unsigned int maxtasknum; 
	unsigned int curtasknum; 
}agent_task_queue_t;

/* --------------------------------------------------------------------------*/
/**
 * @brief struct threadpool
 * @description 线程池结构定义
 */
/* ----------------------------------------------------------------------------*/
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

	agent_task_queue_t  tasks;

	unsigned int       threadnum; 
	unsigned int       thread_stack_size; 
    unsigned int       ThreadFdCount;
    unsigned int       NetworkState;

    bool               bFirstCheckIsUpdate;
    bool               bOnceUpdate;

    POOL_UPDATE_FUN    UpdateLocalPswCache;

    sPthreadFdInfo     pfds[8];

}agent_threadpool_t;

typedef struct threadpool_conf
{
	unsigned int threadnum;    
	unsigned int thread_stack_size;
	unsigned int maxtasknum;
}agent_threadpool_conf_t;

void Log(const char* format, ... );  

int SetNonBlocking(int fd);
bool SelectListen(int sockfd);
int z_conf_check(agent_threadpool_conf_t *conf);
inline void z_task_queue_init(agent_task_queue_t* task_queue);
int z_thread_mutex_create(pthread_mutex_t *mutex);
inline void z_thread_mutex_destroy(pthread_mutex_t *mutex);
inline int z_thread_cond_create(pthread_cond_t *cond);
inline void z_thread_cond_destroy(pthread_cond_t *cond);
inline int z_thread_sem_create(sem_t *sem);
inline void z_thread_sem_destroy(sem_t *sem);
int z_threadpool_create(agent_threadpool_t *pool);

/* --------------------------------------------------------------------------*/
/**
 * @brief z_threadpool_cycle 
 * @decription 工作线程，等待获取任务请求和接收server端主动更新
 * @param argv
 *
 * @returns  
 */
/* ----------------------------------------------------------------------------*/
void *z_threadpool_cycle(void* argv);

/* --------------------------------------------------------------------------*/
/**
 * @brief z_threadpool_save 
 * @description 缓存本地密码文件线程，等待获取缓存密码任务并写入.dat文件保存
 * @param argv 
 *
 * @returns  
 */
/* ----------------------------------------------------------------------------*/
void *z_threadpool_save(void* argv);

/* --------------------------------------------------------------------------*/
/**
 * @brief z_threadpool_log 
 * @description 缓存日志文件线程，等待获取日志任务并写入log文件保存
 * @param argv
 *
 * @returns  
 */
/* ----------------------------------------------------------------------------*/
void *z_threadpool_log(void* argv);
void *z_threadpool_exit_cb(void* argv);
inline int z_thread_add(agent_threadpool_t *pool);
inline void z_change_maxtask_num(agent_threadpool_t *pool, unsigned int num);
inline int z_thread_key_create();
inline void z_thread_key_destroy();

/* --------------------------------------------------------------------------*/
/**
 * @brief agent_threadpool_init 
 * @description 线程池初始化，拉起线程池
 * @param conf
 *
 * @returns  
 */
/* ----------------------------------------------------------------------------*/
agent_threadpool_t* agent_threadpool_init(agent_threadpool_conf_t *conf);
/* --------------------------------------------------------------------------*/
/**
 * @brief agent_threadpool_add_task 
 * @description 添加任务至线程池任务队列函数接口
 * @param pool
 * @param handler
 * @param argv
 *
 * @returns  
 */
/* ----------------------------------------------------------------------------*/
int agent_threadpool_add_task(agent_threadpool_t *pool, CB_FUN handler, void* argv);
void agent_threadpool_destroy(agent_threadpool_t *pool);
int agent_thread_add(agent_threadpool_t *pool);
int agent_set_max_tasknum(agent_threadpool_t *pool,unsigned int num);

bool GetPvaFromLocal(agent_threadpool_t *pool, char *appID, char *valueID, char *pswOut);
/* --------------------------------------------------------------------------*/
/**
 * @brief CheckIsNeedUpdate 
 * @description 检测是否需要更新本地缓存密码函数
 *
 * @param pool
 *
 * @returns  
 */
/* ----------------------------------------------------------------------------*/
bool CheckIsNeedUpdate(agent_threadpool_t *pool);
bool UpdateLocalPswCache(void *arg);
/* --------------------------------------------------------------------------*/
/**
 * @brief LoadRawPswCacheFromBinFile 
 * @description 加载本地原始密码.bin文件至临时缓存函数
 *
 * @param pool
 *
 * @returns  
 */
/* ----------------------------------------------------------------------------*/
bool LoadRawPswCacheFromBinFile(agent_threadpool_t *pool);
/* --------------------------------------------------------------------------*/
/**
 * @brief LoadPswCachedFromDatFile 
 * @description 加载本地密码.dat文件至临时缓存函数
 *
 * @param pool
 * @param pszErrorInfo
 *
 * @returns  
 */
/* ----------------------------------------------------------------------------*/
bool LoadPswCachedFromDatFile(agent_threadpool_t *pool, char *pszErrorInfo);
/* --------------------------------------------------------------------------*/
/**
 * @brief SavePswToLocalCacheDatFile 
 * @description 保存密码至本地.dat文件中
 *
 * @param pswNew
 */
/* ----------------------------------------------------------------------------*/
void SavePswToLocalCacheDatFile(sLocalPswCacheInfo *pswNew);
int EnCodeSendInfo(char* pszInSendData, int nInSendDataLen, char* pszOutEncodeData, int nEncodeType);
bool SendDataToServer(int* pnSocket, char* pszSendData, int nSendLen);
//bool SendRequestToUpstream(long appID, char *valueID, int *sockfd, char *szSeqNumber);
/* --------------------------------------------------------------------------*/
/**
 * @brief SendRequestToUpstream 
 * @description  发送加密的xml格式的请求至server端，封装的xml格式大致如下：
 *                <?xml version="1.0" encoding="utf-8"?>
 *                <req type="pva" obj="t_password_info" seq="c653d10a91ba4b5288428c11b35842f3">
 *                <vaultid>2478cbd7fe8f4f22810664407e01f437</vaultid>
 *                <appid>194505417</appid>
 *                </req>
 *                
 * @param appID
 * @param valueID
 * @param sockfd
 *
 * @returns  
 */
/* ----------------------------------------------------------------------------*/
bool SendRequestToUpstream(long appID, char *valueID, int *sockfd);
bool GetOnePswFromLocalCache(agent_threadpool_t *pool, long appID, char *pswOut);
bool ProcessPswInfoFromUpstream(agent_threadpool_t *pool, agent_task_t *ptask);
bool GetDataFromServer(int pSockClient, char* pszRecvData, int* pRecvDataLen, char* pszErrorInfo);
bool SendDataToServer2(int pnSocket, char* pszSendData, int nSendLen, char* pszRecvData, int* pRecvDataLen, char* pszErrorInfo);
//bool ParseUpstreamXmlInfo(char *appID, char *valueID, char *pszXmlBuffer, int nBufferLen, char *pswOut, char *SeqNumber);

/* --------------------------------------------------------------------------*/
/**
 * @brief ParseUpstreamXmlInfo 
 * @description 解析接收到的服务器返回信息，xml中code字段表示获取密码是否成功标志
 *              根据返回的xml中code字段值:
 *              code值等于0时表示获取成功
 *              code值等于非0时表示获取失败
 *
 * @param appID
 * @param valueID
 * @param pszXmlBuffer
 * @param nBufferLen
 * @param pswOut
 * @param lAppID
 *
 * @returns  
 */
/* ----------------------------------------------------------------------------*/
bool ParseUpstreamXmlInfo(char *appID, char *valueID, char *pszXmlBuffer, int nBufferLen, char *pswOut, long lAppID);

/* --------------------------------------------------------------------------*/
/**
 * @brief ParseLoginReqXmlData 
 * @description 解析接收到的登陆请求返回信息，登陆是否成功
 *              根据返回的xml中code字段值:
 *              code值等于0时表示登陆成功
 *              code值等于非0时表示登陆失败
 *
 * @param pszSeqNumber
 * @param pszXmlBuffer
 * @param nBufferLen
 *
 * @returns  
 */
/* ----------------------------------------------------------------------------*/
bool ParseLoginReqXmlData(char* pszSeqNumber, char* pszXmlBuffer, int nBufferLen);

/* --------------------------------------------------------------------------*/
/**
 * @brief VerifyLogin 
 * @description 验证登陆函数，登陆xml格式：
 *              <?xml version="1.0" encoding="utf-8"?>
 *              <req type="auth" user="aimuser" pass="7da43a4dc548515c5616d928e968ddfbc9b20d96" role="huawei@aim" ip="192.168.2.117" md5="null" seq="200">
 *              </req>
 *
 * @param sockfd
 * @param localIP
 *
 * @returns  
 */
/* ----------------------------------------------------------------------------*/
bool VerifyLogin(int sockfd, char *localIP);

/* --------------------------------------------------------------------------*/
/**
 * @brief LoginPvaServer 
 * @description 登陆服务器函数
 *
 * @param sockfd
 *
 * @returns  
 */
/* ----------------------------------------------------------------------------*/
bool LoginPvaServer(int *sockfd);

/* --------------------------------------------------------------------------*/
/**
 * @brief ChangeVariableNetworkState 
 * @description 更改工作线程的网络连接状态
 *
 * @param pool
 * @param pfd
 * @param isOnline
 */
/* ----------------------------------------------------------------------------*/
void ChangeVariableNetworkState(agent_threadpool_t *pool, pthread_t pfd, bool isOnline);

/* --------------------------------------------------------------------------*/
/**
 * @brief NotifyUpdateCache 
 * @description 通知主线程开启主动更新本地缓存
 *
 * @param pool
 *
 * @returns  
 */
/* ----------------------------------------------------------------------------*/
bool NotifyUpdateCache(agent_threadpool_t *pool);

/* --------------------------------------------------------------------------*/
/**
 * @brief ReplaceLocalPswCache 
 * @description 更新替换临时密码缓存列表
 *
 * @param appID
 * @param valueID
 * @param pswInfo
 * @param pool
 *
 * @returns  
 */
/* ----------------------------------------------------------------------------*/
bool ReplaceLocalPswCache(char *appID, char *valueID, char *pswInfo, agent_threadpool_t *pool);

/* --------------------------------------------------------------------------*/
/**
 * @brief ParseDownstreamInfo 
 * @description 解析处理client请求，报文格式如下(无解密)：
 *              604505738=2478cbd7fe8f4f22810664407e01f437
 *
 * @param appID
 * @param valueID
 * @param pszDecodeData
 * @param nBufferLen
 */
/* ----------------------------------------------------------------------------*/
void ParseDownstreamInfo(char *appID, char *valueID, char *pszDecodeData, int nBufferLen);

/* --------------------------------------------------------------------------*/
/**
 * @brief ParseReActiveUpdateXmlInfo 
 * @description 处理server端主动密码更新请求，解析密码更新xml,xml的格式如下:
 *              <?xml version="1.0" encoding="utf-8"?>
 *              <resp type="pva" seq="pva_10000" code="0">
 *              <appid>值</appid>
 *              <pass>值</pass>
 *              </resp>
 *
 * @param appID
 * @param valueID
 * @param pszXmlBuffer
 * @param nBufferLen
 * @param pswOut
 *
 * @returns  
 */
/* ----------------------------------------------------------------------------*/
bool ParseReActiveUpdateXmlInfo(char *appID, char *valueID, char *pszXmlBuffer, int nBufferLen, char *pswOut);

/* --------------------------------------------------------------------------*/
/**
 * @brief ParseRecvInfo 
 * @description 处理client和server端消息的统一接口
 *
 * @param appID
 * @param valueID
 * @param pswReturn
 * @param pswIn
 * @param type
 * @param seqNumber
 * @param lAppID
 *
 * @returns  
 */
/* ----------------------------------------------------------------------------*/
bool ParseRecvInfo(char *appID, char *valueID, char *pswReturn, char *pswIn, int type, char *seqNumber, long lAppID);

/* --------------------------------------------------------------------------*/
/**
 * @brief ActiveUpgradeLocalPswCache 
 * @description 专门接收处理代理主动更新时，server端过来的反馈消息
 *
 * @param buf
 * @param arg
 * @param pool
 *
 * @returns  
 */
/* ----------------------------------------------------------------------------*/
bool ActiveUpgradeLocalPswCache(char *buf, void *arg, agent_threadpool_t *pool);

/* --------------------------------------------------------------------------*/
/**
 * @brief ReActiveUpdateLocalCache 
 * @description 专门处理server端主动密码更新消息
 *
 * @param buf
 * @param pool
 */
/* ----------------------------------------------------------------------------*/
void ReActiveUpdateLocalCache(char *buf, agent_threadpool_t* pool);

void SendDataToDownstream(char *pswSendData, agent_task_t *ptask);

/* --------------------------------------------------------------------------*/
/**
 * @brief ProcessNewPswFromUpstream 
 * @description 专门处理server端的消息，包括密码请求反馈和主动更新
 *
 * @param buf
 * @param pool
 * @param ptask
 */
/* ----------------------------------------------------------------------------*/
void ProcessNewPswFromUpstream(char *buf, agent_threadpool_t *pool, agent_task_t *ptask);

/* --------------------------------------------------------------------------*/
/**
 * @brief ReadPvaPoll 
 * @description 监听server端函数 
 *
 * @param pfd
 * @param needrelogin
 * @param pool
 * @param arg
 * @param sendready
 *
 * @returns  
 */
/* ----------------------------------------------------------------------------*/
bool ReadPvaPoll(struct pollfd *pfd, int *needrelogin, agent_threadpool_t *pool, void *arg, int sendready);

/* --------------------------------------------------------------------------*/
/**
 * @brief Req_ReceiveRequest 
 * @description 任务请求接收函数接口，与任务绑定，主线程调用此接口
 *
 * @param task
 * @param p
 *
 * @returns  
 */
/* ----------------------------------------------------------------------------*/
bool Req_ReceiveRequest(void *task, void *p);

/* --------------------------------------------------------------------------*/
/**
 * @brief Req_ProcessRequest 
 * @description 任务请求处理函数接口，与任务绑定,工作线程获取到任务调用此接口
 *
 * @param task
 * @param p
 *
 * @returns  
 */
/* ----------------------------------------------------------------------------*/
bool Req_ProcessRequest(void *task, void *p);

#endif
