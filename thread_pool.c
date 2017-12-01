/* *******************************************************
 * Call Center On Demand Product Series
 * Copyright (C) 2017 HonDa(Guangzhou.) Technology Ltd., Co.
 * All right reserved
 *
 * @file thread_pool.c
 * @brief 
 * @author tuyungang
 * @version v1.0
 * @date 2017-12-01
 * 
 * TODO: 线程池 
 * 
 * *******************************************************/
#include "thread_pool.h"
#include "ini_config.h"

char m_DownStream_Buffer[128];
static agent_threadpool_t * POOL = NULL;
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

static 	pthread_key_t  key;

int SetNonBlocking(int fd)
{
    int old_option = fcntl( fd, F_GETFL, 0 );
    //int new_option = old_option | O_NONBLOCK;
    //fcntl( fd, F_SETFL, new_option | O_NONBLOCK );
    fcntl( fd, F_SETFL, old_option | O_NONBLOCK );
    return old_option;
}

bool GetPvaFromLocal(agent_threadpool_t *pool, char *appID, char *valueID, char *pswOut)
{
    if (appID == NULL)
        return false;
    pthread_mutex_lock(&pool->LocalPswCacheQueueMutex);
    if (TAILQ_EMPTY(&pool->LocalPswCacheQueue)) {
        pthread_mutex_unlock(&pool->LocalPswCacheQueueMutex);
        return false;
    }
    sLocalPswCacheInfo *it = NULL;
    TAILQ_FOREACH(it, &pool->LocalPswCacheQueue, next) {
        if (it->lAppID == atol(appID)) {
            memcpy(pswOut, it->szPassword, strlen(it->szPassword));
            break;
        }
    }
    if (it == TAILQ_END(&pool->LocalPswCacheQueue)) {
        pthread_mutex_unlock(&pool->LocalPswCacheQueueMutex);
        return false;
    }
    pthread_mutex_unlock(&pool->LocalPswCacheQueueMutex);
    return true;
}

bool CheckIsNeedUpdate(agent_threadpool_t *pool)
{
    int n = 0;
    char appID[50] = {0};
    time_t tmCurrent = time(0);

    sLocalPswCacheInfo *it = NULL;
    pthread_mutex_lock(&pool->LocalPswCacheQueueMutex);
    TAILQ_FOREACH(it, &pool->LocalPswCacheQueue, next) {
        if (it->tmChange != (time_t)0 && it->tmChange + 120 < tmCurrent) {
            agent_task_t task;
            //task.DownStreamPfd = NULL;
            task.argv = NULL;
            task.handler = NULL;
            task.ReceiveRequest = NULL;
            task.ProcessRequest = NULL;
            task.next = NULL;
            task.sockfd = -1;
            task.UpstreamSockfd = -1;
            task.lAppID = it->lAppID;
            task.GetFormFlag = 0;
            memset(task.szVaultID, '\0', 128);
            memcpy(task.szVaultID, g_SafeBoxID, strlen(g_SafeBoxID));
            //memcpy(task.szVaultID, "2478cbd7fe8f4f22810664407e01f437", strlen("2478cbd7fe8f4f22810664407e01f437"));
            memset(task.DownStreamBuffer, '\0', 256);
            //memset(task->SeqNumber, '\0', 32);
            memset(task.UpStreamBuffer, '\0', 1024);
            task.bIsActiveUpdate = true;
            agent_threadpool_add_task(pool, NULL, (void*)&task);
            n++;
        }
    }
    pthread_mutex_unlock(&pool->LocalPswCacheQueueMutex);
    int ret = pthread_mutex_trylock(&pool->FirstCheckIsUpdateMutex);  
    if (ret == 0) {
        pool->bFirstCheckIsUpdate = true;
        pthread_mutex_unlock(&pool->FirstCheckIsUpdateMutex);  
    }
    if (n == 0) {
        return false;
    }
    return true;
}

bool UpdateLocalPswCache(void *arg)
{ 
    agent_threadpool_t * pool = (agent_threadpool_t*)arg;
    pthread_mutex_lock(&pool->LocalPswCacheQueueMutex);
    if (TAILQ_EMPTY(&pool->LocalPswCacheQueue)) {
        pthread_mutex_unlock(&pool->LocalPswCacheQueueMutex);
        return false;
    }
    pthread_mutex_unlock(&pool->LocalPswCacheQueueMutex);

	int ret = pthread_mutex_trylock(&pool->FirstCheckIsUpdateMutex);  
    if (ret == 0) {
        bool bFirstCheckIsUpdateFlag = pool->bFirstCheckIsUpdate;
        pthread_mutex_unlock(&pool->FirstCheckIsUpdateMutex);  
        if (!bFirstCheckIsUpdateFlag) {
            bool bRet = CheckIsNeedUpdate(pool);
            if (!bRet) {
                return false;
            }
        }
    }

    return true;
}

bool LoadRawPswCacheFromBinFile(agent_threadpool_t *pool)
{
    char* pszPvaFile = "pvabuffer.bin";
    FILE* pFile = NULL;
    pFile = fopen(pszPvaFile, "rb");
    if (pFile == NULL)
    {
        Log("open password file failed");
		return false;
    }
	
    fseek(pFile, 0, SEEK_END);
    long lFileSize = ftell(pFile);
    if (lFileSize == 0)
    {
        Log("get password file size failed");
		fclose(pFile);
		remove(pszPvaFile);
        return false;
    }
    rewind(pFile);
	
    long nFileType = 0;
    fread(&nFileType, sizeof(long), 1, pFile);
    if (ntohl(nFileType) != 0x1100) //file type identify
    {
        Log("get password file head type failed");
		fclose(pFile);
		return false;
    }

    lFileSize -= sizeof(long);
    char* pszDataBuffer= (char*)malloc(lFileSize + 1);
    if (pszDataBuffer == NULL)
    {
        Log("malloc save file buffer failed");
		fclose(pFile);
		return false;
    }
	
    memset(pszDataBuffer, 0, lFileSize + 1);
    long nDataLen = 0;
    while (nDataLen < lFileSize)
    {
       char szBuffer[40960] = {0};
       int nReadLen = fread(szBuffer, sizeof(char), 40960, pFile);
       if (nReadLen > 0)
       {
	   		memcpy(pszDataBuffer, szBuffer, nReadLen);
	   		nDataLen += nReadLen;
       }
       else
	   		break;
    }
	fclose(pFile);
	
	if (nDataLen < lFileSize)
	{
        Log("read password file buffer failed");
		free(pszDataBuffer);
		return false;
	}
	
	char* pszDecodeData = (char*)malloc(lFileSize * 2);
	if (pszDecodeData == NULL)
	{
        Log("malloc decode buffer failed");
		free(pszDataBuffer);
		return false;
	}
	memset(pszDecodeData, 0, lFileSize * 2);
	
	unsigned char szEncodeKey[16] = {0};
	unsigned char szEndData[16] = { 0xe1, 0x02, 0xa3, 0x04, 0x15, 0xb6, 0x07, 0x08, 0xc9, 0x0a, 0xab, 0x0c, 0x6d, 0x0e, 0x2f, 0x01 };
	int nIndex = 0;
    for (nIndex = 0; nIndex < 16; nIndex++)
	{
		if (nIndex % 3 == 0)
		{
		   szEncodeKey[nIndex] = (0x0f) & (szEndData[nIndex] >> 2);
		}
		else if (nIndex % 3 == 1)
		{
		   szEncodeKey[nIndex] = (0x1f) & (szEndData[nIndex] >> 3);
		}
		else
		{
		   szEncodeKey[nIndex] = (0x3f) & (szEndData[nIndex] >> 4);
		}
	}
	int nDecodeLen = 0;
	AES_DecryptDataEVP((unsigned char*)pszDataBuffer, lFileSize, szEncodeKey, pszDecodeData, &nDecodeLen);
	if (nDecodeLen == 0)
	{
        Log("decode file buffer failed");
		free(pszDataBuffer);
		free(pszDecodeData);
		return false;
	}
	free(pszDataBuffer);
	
	char szPassword[64];
	nDataLen = 0;
	long lAppID = 0;
	int nBufferLen = 0;
	while (nDataLen < nDecodeLen)
	{
		memcpy(&lAppID, pszDecodeData + nDataLen, sizeof(long));
		nDataLen += sizeof(long);
		
		memcpy(&nBufferLen, pszDecodeData + nDataLen, sizeof(int));
		nDataLen += sizeof(int);
		
		memset(szPassword, 0, sizeof(szPassword));
		if (nBufferLen > 63)	//password buffer size is 64;
			break;
		
		memcpy(szPassword, pszDecodeData + nDataLen, nBufferLen);
		nDataLen += nBufferLen;

		sLocalPswCacheInfo *ps = (sLocalPswCacheInfo *)malloc(sizeof(sLocalPswCacheInfo));
        //ps = NULL;
        ps->lAppID = lAppID;
        memset(ps->szVaultID, 0, 128);
        memcpy(ps->szVaultID, g_SafeBoxID, strlen(g_SafeBoxID));
        //memcpy(ps->szVaultID, "2478cbd7fe8f4f22810664407e01f437", strlen("2478cbd7fe8f4f22810664407e01f437"));
        memset(ps->szPassword, 0, 64);
        memcpy(ps->szPassword, szPassword, nBufferLen);
        ps->tmChange = (time_t)0;
        //ps->next = NULL;
        ps->handler = NULL;
        ps->lock = 0;
        pthread_mutex_lock(&pool->LocalPswCacheQueueMutex);
        TAILQ_INSERT_TAIL(&pool->LocalPswCacheQueue, ps, next);
        pthread_mutex_unlock(&pool->LocalPswCacheQueueMutex);
	}

	free(pszDecodeData);
    return true;
}

bool LoadPswCachedFromDatFile(agent_threadpool_t *pool, char *pszErrorInfo)
{
    DIR *dirp;
    struct dirent *direntp;
    //char g_CurAbsolutePath[256];
    //char g_CacheFileAbsolutePath[256];

    //memset(g_CurAbsolutePath, '\0', 256);
    //memset(g_CacheFileAbsolutePath, '\0', 256);
    /*
    if (NULL == getcwd(g_CurAbsolutePath, 256)) {
    }
    */
    sprintf(g_CacheFileAbsolutePath, "%s/%s",g_CurAbsolutePath, "pswcache");

    if ((dirp = opendir(g_CacheFileAbsolutePath)) == NULL) {
        Log("get password cache dat file failed");
        return false;
    }

    char tempDatPath[256] = {0};
    while ((direntp = readdir(dirp)) != NULL) {
        if (strstr(direntp->d_name, ".dat") != NULL) {
            memset(tempDatPath, '\0', 256);
            sprintf(tempDatPath, "%s/%s", g_CacheFileAbsolutePath, direntp->d_name);
            FILE* pFile = NULL;
            pFile = fopen(tempDatPath, "rb");
            if (pFile == NULL)
            { 
                Log("open password file failed");
                return false;
            }
            
            fseek(pFile, 0, SEEK_END);
            long lFileSize = ftell(pFile);
            if (lFileSize == 0)
            {
                Log("get password %s size failed", direntp->d_name);
                fclose(pFile);
                remove(direntp->d_name);
                closedir(dirp);
                return false;
            }
            rewind(pFile);
            
            long nFileType = 0;
            fread(&nFileType, sizeof(long), 1, pFile);
            if (ntohl(nFileType) != 0x1100) //file type identify
            {
                Log("get password %s head type failed", direntp->d_name);
                fclose(pFile);
                return false;
            }

            lFileSize -= sizeof(long);
            char* pszDataBuffer= (char*)malloc(lFileSize + 1);
            if (pszDataBuffer == NULL)
            {
                Log("malloc save file buffer failed");
                fclose(pFile);
                return false;
            }
            
            memset(pszDataBuffer, 0, lFileSize + 1);
            long nDataLen = 0;
            while (nDataLen < lFileSize)
            {
                char szBuffer[1024] = {0};
                int nReadLen = fread(szBuffer, sizeof(char), 40960, pFile);
                if (nReadLen > 0)
                {
                        memcpy(pszDataBuffer, szBuffer, nReadLen);
                        nDataLen += nReadLen;
                }
                else
                    break;
            }
            fclose(pFile);
            
            if (nDataLen < lFileSize)
            {
                Log("read password file buffer failed");
                free(pszDataBuffer);
                return false;
            }
            
            char* pszDecodeData = (char*)malloc(lFileSize * 2);
            if (pszDecodeData == NULL)
            {
                Log("malloc decode buffer failed");
                free(pszDataBuffer);
                return false;
            }
            memset(pszDecodeData, 0, lFileSize * 2);
            
            unsigned char szEncodeKey[16] = {0};
            unsigned char szEndData[16] = { 0xe1, 0x02, 0xa3, 0x04, 0x15, 0xb6, 0x07, 0x08, 0xc9, 0x0a, 0xab, 0x0c, 0x6d, 0x0e, 0x2f, 0x01 };
            int nIndex = 0;
            for (nIndex = 0; nIndex < 16; nIndex++)
            {
                if (nIndex % 3 == 0)
                {
                szEncodeKey[nIndex] = (0x0f) & (szEndData[nIndex] >> 2);
                }
                else if (nIndex % 3 == 1)
                {
                szEncodeKey[nIndex] = (0x1f) & (szEndData[nIndex] >> 3);
                }
                else
                {
                szEncodeKey[nIndex] = (0x3f) & (szEndData[nIndex] >> 4);
                }
            }
            int nDecodeLen = 0;
            AES_DecryptDataEVP((unsigned char*)pszDataBuffer, lFileSize, szEncodeKey, pszDecodeData, &nDecodeLen);
            if (nDecodeLen == 0)
            {
                Log("decode file buffer failed");
                free(pszDataBuffer);
                free(pszDecodeData);
                return false;
            }
            free(pszDataBuffer);
            
            char szPassword[64];
            nDataLen = 0;
            long lAppID = 0;
            int nBufferLen = 0;
            time_t tmTimeChange = 0;
            while (nDataLen < nDecodeLen)
            {
                memcpy(&lAppID, pszDecodeData + nDataLen, sizeof(long));
                nDataLen += sizeof(long);
                
                memcpy(&nBufferLen, pszDecodeData + nDataLen, sizeof(int));
                nDataLen += sizeof(int);
                
                memset(szPassword, 0, sizeof(szPassword));
                if (nBufferLen > 63)	//password buffer size is 64;
                    break;
                
                memcpy(szPassword, pszDecodeData + nDataLen, nBufferLen);
                nDataLen += nBufferLen;
                memcpy(&tmTimeChange, pszDecodeData + nDataLen, sizeof(time_t));
                nDataLen += sizeof(time_t);

                sLocalPswCacheInfo *ps = (sLocalPswCacheInfo *)malloc(sizeof(sLocalPswCacheInfo));
                //ps = NULL;
                ps->lAppID = lAppID;
                memset(ps->szVaultID, 0, 128);
                //memcpy(ps->szVaultID, "2478cbd7fe8f4f22810664407e01f437", strlen("2478cbd7fe8f4f22810664407e01f437"));
                memcpy(ps->szVaultID, g_SafeBoxID, strlen(g_SafeBoxID));
                memset(ps->szPassword, 0, 64);
                memcpy(ps->szPassword, szPassword, nBufferLen);
                ps->tmChange = tmTimeChange;
                ps->handler = NULL;
                ps->lock = 0;
                //ps->next = NULL;
                pthread_mutex_lock(&pool->LocalPswCacheQueueMutex);
                if (TAILQ_EMPTY(&pool->LocalPswCacheQueue)) {
                    TAILQ_INSERT_TAIL(&pool->LocalPswCacheQueue, ps, next);
                } else {
                    sLocalPswCacheInfo *it = NULL;
                    TAILQ_FOREACH(it, &pool->LocalPswCacheQueue, next) {
                        if (it->lAppID == lAppID) {
                            if (strcmp(it->szPassword, szPassword) == 0) {
                                it->tmChange = tmTimeChange;
                                break;
                            } else {
                                memset(it->szPassword, 0, sizeof(it->szPassword));
                                memcpy(it->szPassword, szPassword, strlen(szPassword));
                                it->tmChange = tmTimeChange;
                                break;
                            }
                        }
                    }
                    if (it == TAILQ_END(&pool->LocalPswCacheQueue)) {
                        TAILQ_INSERT_TAIL(&pool->LocalPswCacheQueue, ps, next);
                    }
                }
                pthread_mutex_unlock(&pool->LocalPswCacheQueueMutex);
            }
            free(pszDecodeData);
        }
    }
    sLocalPswCacheInfo *ps = NULL;
    if (direntp == NULL) {
        if (TAILQ_EMPTY(&pool->LocalPswCacheQueue)) {
            goto END;
        }
    }

END:
    /*
    TAILQ_FOREACH(ps, &pool->LocalPswCacheQueue, next) {
        printf("%s %ld %s %ld\n", __func__, ps->lAppID, ps->szPassword, ps->tmChange);
    }
    */
    closedir(dirp);
    return true;
}

agent_threadpool_t* agent_threadpool_init(agent_threadpool_conf_t *conf)
{
	agent_threadpool_t *pool = NULL;
	//int error_flag_mutex = 0;
	//int error_flag_cond = 0;
	//pthread_attr_t attr;
	do{
		if (z_conf_check(conf) == -1){ 
			break;
		}

		pool = (agent_threadpool_t *)malloc(sizeof(agent_threadpool_t));
		if (pool == NULL){
			break;
		}
        //pool = NULL;

		pool->threadnum = conf->threadnum;
		pool->thread_stack_size = conf->thread_stack_size;
		pool->tasks.maxtasknum = conf->maxtasknum;
		pool->tasks.curtasknum = 0;

        TAILQ_INIT(&pool->LocalPswCacheQueue);
        TAILQ_INIT(&pool->UpdatePswDatFileQueue);
        TAILQ_INIT(&pool->LogCacheQueue);
		z_task_queue_init(&pool->tasks);
        memset(pool->pfds, 0, sizeof(sPthreadFdInfo)*8);
	
        pool->NetworkState = 0;
        pool->bFirstCheckIsUpdate = false;
        pool->bOnceUpdate = false;
        pool->UpdateLocalPswCache = UpdateLocalPswCache;

		if (z_thread_key_create() != 0) {
			free(pool);
            pool = NULL;
			break;
		}

		if (z_thread_mutex_create(&pool->mutex) != 0) { 
			z_thread_key_destroy();
			free(pool);
            pool = NULL;
			break;
		}
		if (z_thread_mutex_create(&pool->ThreadFdCountMutex) != 0) { 
			z_thread_key_destroy();
			free(pool);
            pool = NULL;
			break;
		}
		if (z_thread_mutex_create(&pool->OnceUpdateMutex) != 0) { 
			z_thread_key_destroy();
			free(pool);
            pool = NULL;
			break;
		}
		if (z_thread_mutex_create(&pool->LocalPswCacheQueueMutex) != 0) { 
			z_thread_key_destroy();
			free(pool);
            pool = NULL;
			break;
		}
		if (z_thread_mutex_create(&pool->FirstCheckIsUpdateMutex) != 0) { 
			z_thread_key_destroy();
			free(pool);
            pool = NULL;
			break;
		}
        if (z_thread_mutex_create(&pool->LogCacheQueueMutex) != 0) { 
			z_thread_key_destroy();
			free(pool);
            pool = NULL;
			break;
		}
        if (z_thread_sem_create(&pool->TasksQueueSem)) {
			z_thread_key_destroy();
			free(pool);
            pool = NULL;
			break;
        }
        if (z_thread_sem_create(&pool->UpdatePswDatFileQueueSem)) {
			z_thread_key_destroy();
			free(pool);
            pool = NULL;
			break;
        }
        if (z_thread_sem_create(&pool->LogCacheQueueSem)) {
			z_thread_key_destroy();
			free(pool);
            pool = NULL;
			break;
        }
		if (z_thread_cond_create(&pool->cond) != 0) { 
			z_thread_key_destroy();
			z_thread_mutex_destroy(&pool->ThreadFdCountMutex);
			z_thread_mutex_destroy(&pool->OnceUpdateMutex);
			z_thread_mutex_destroy(&pool->LocalPswCacheQueueMutex);
			z_thread_mutex_destroy(&pool->FirstCheckIsUpdateMutex);
			z_thread_mutex_destroy(&pool->LogCacheQueueMutex);
			z_thread_mutex_destroy(&pool->mutex);
            z_thread_sem_destroy(&pool->UpdatePswDatFileQueueSem);
            z_thread_sem_destroy(&pool->LogCacheQueueSem);
            z_thread_sem_destroy(&pool->TasksQueueSem);
			free(pool);
            pool = NULL;
			break;
		}
		if (z_thread_cond_create(&pool->OnceUpdateCond) != 0) { 
			z_thread_key_destroy();
			z_thread_mutex_destroy(&pool->ThreadFdCountMutex);
			z_thread_mutex_destroy(&pool->OnceUpdateMutex);
			z_thread_mutex_destroy(&pool->LocalPswCacheQueueMutex);
			z_thread_mutex_destroy(&pool->FirstCheckIsUpdateMutex);
			z_thread_mutex_destroy(&pool->LogCacheQueueMutex);
			z_thread_mutex_destroy(&pool->mutex);
            z_thread_sem_destroy(&pool->UpdatePswDatFileQueueSem);
            z_thread_sem_destroy(&pool->LogCacheQueueSem);
            z_thread_sem_destroy(&pool->TasksQueueSem);
			free(pool);
            pool = NULL;
			break;
		}
        POOL = pool;

        bool bRet;
        static unsigned int nReLoadCount = 0;
        char *sError = NULL;
    RELOADFROMBIN:
            bRet = LoadRawPswCacheFromBinFile(pool);
        if (!bRet) {
            Log("load bin file fail try num: %u", nReLoadCount + 1);
            nReLoadCount++;
            if (nReLoadCount >= 2){
                nReLoadCount = 0;
                goto RELOADFROMDAT;
            }
            goto RELOADFROMBIN;
        }

    RELOADFROMDAT:
        bRet =  LoadPswCachedFromDatFile(pool, sError);
        if (!bRet) {
            Log("load dat file fail");
        }

		if (z_threadpool_create(pool) != 0){
			z_thread_key_destroy();
			z_thread_mutex_destroy(&pool->mutex);
			z_thread_mutex_destroy(&pool->ThreadFdCountMutex);
			z_thread_mutex_destroy(&pool->OnceUpdateMutex);
			z_thread_mutex_destroy(&pool->LocalPswCacheQueueMutex);
			z_thread_mutex_destroy(&pool->FirstCheckIsUpdateMutex);
			z_thread_mutex_destroy(&pool->LogCacheQueueMutex);
            z_thread_sem_destroy(&pool->UpdatePswDatFileQueueSem);
            z_thread_sem_destroy(&pool->LogCacheQueueSem);
			z_thread_cond_destroy(&pool->cond);
			z_thread_cond_destroy(&pool->OnceUpdateCond);
            z_thread_sem_destroy(&pool->TasksQueueSem);
			free(pool);
            pool = NULL;
			break;
		}
	}while(0);

    /*
    bool bRet;
    static unsigned int nReLoadCount = 0;
    char *sError = NULL;
RELOADFROMBIN:
        bRet = LoadRawPswCacheFromBinFile(pool);
    if (!bRet) {
        //Log("(%s %d) load bin file fail try num: %u", __func__, __LINE__, nReLoadCount + 1);
        nReLoadCount++;
        if (nReLoadCount >= 2){
            nReLoadCount = 0;
            goto RELOADFROMDAT;
        }
        goto RELOADFROMBIN;
    }

RELOADFROMDAT:
    bRet =  LoadPswCachedFromDatFile(pool, sError);
    if (!bRet) {
        //Log("(%s %d) %s", __func__, __LINE__, "load dat file fail");
    }
    */
    POOL = pool;
    return pool;
}

bool Req_ReceiveRequest(void *task, void *p)
{
    agent_task_t *ptask = (agent_task_t*)task;
    agent_threadpool_t *pool = (agent_threadpool_t *)p;
    //bool m_downstream_flag = false;
    bool m_error_flag = false;
    int m_downstream_idx = 0;
    memset(ptask->DownStreamBuffer, 0, 256);
    while (1) 
    {
        int ret = recv( ptask->sockfd, ptask->DownStreamBuffer + m_downstream_idx, 256, 0 );
        if (ret < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                //m_downstream_flag = true;
                break;
            } else {
                m_error_flag = true;
                close(ptask->sockfd);
                break;
            }
        } else if (ret == 0) {
            m_error_flag = true;
            close(ptask->sockfd);
            ptask->sockfd = -1;
            break;
        } else if (ret > 0) {
            m_downstream_idx += ret;
            //m_read_upstream_len = m_read_upstream_idx;
            break;
        }
    }
    /*
    if (!m_downstream_flag) {
        printf("%s %d\n", __func__, __LINE__);
        return false;
    }
    */
    if (m_error_flag) {
        return false;
    }

    char appID[80] = {0}; 
    char valueID[128] = {0}; 
    char pswOut[256] = {0};
    bool bRet;

    unsigned int state;
    pthread_mutex_lock(&pool->ThreadFdCountMutex);
    state = pool->NetworkState;
    pthread_mutex_unlock(&pool->ThreadFdCountMutex);
    printf("network count: %u\n", state);

    if (state == 0){
        goto NETWORK_OUTLINE;
    }

NETWORK_ONLINE:
    printf("%s %d %s\n", __func__, __LINE__, "online");
    bRet = ParseRecvInfo(appID, valueID, pswOut, ptask->DownStreamBuffer, 0, NULL, 0);
    if (!bRet) {
        SendDataToDownstream("client send data error: 401", ptask);
        memset(ptask->DownStreamBuffer, 0, 256);
        return false;
    }
    bRet = GetOnePswFromLocalCache(pool, atol(appID), pswOut);
    if (bRet) {
        if (pswOut != NULL) {
            SendDataToDownstream(pswOut, ptask);
            memset(ptask->DownStreamBuffer, 0, 256);
            return false;
        }
    }
    ptask->lAppID = atol(appID);
    memset(ptask->szVaultID, 0, 128);
    memcpy(ptask->szVaultID, valueID, strlen(valueID));
    memset(ptask->DownStreamBuffer, 0, 256);
    return true;

NETWORK_OUTLINE:
    printf("%s %d %s\n", __func__, __LINE__, "online");
    bRet = ParseRecvInfo(appID, valueID, pswOut, ptask->DownStreamBuffer, 0, NULL, 0);
    bRet = GetPvaFromLocal(pool, appID, valueID, pswOut);
    if (bRet)
        SendDataToDownstream(pswOut, ptask);
    else
        SendDataToDownstream("Internal server error: 501", ptask);
    memset(ptask->DownStreamBuffer, 0, 256);
    return false;
}

bool Req_ProcessRequest(void *task, void *p)
{
    agent_task_t *ptask = (agent_task_t *)task;
    agent_threadpool_t *pool = (agent_threadpool_t *)p;
    //bool bRet = SendRequestToUpstream(ptask->lAppID, ptask->szVaultID, &ptask->UpstreamSockfd, ptask->SeqNumber);
    bool bRet = SendRequestToUpstream(ptask->lAppID, ptask->szVaultID, &ptask->UpstreamSockfd);
    if (!bRet) {
        if (ptask->bIsActiveUpdate) {
            free(ptask);
            ptask = NULL;
            return false;
        } else {
            char pswOut[128] = {0}, appID[80] = {0};
            sprintf(appID, "%ld", ptask->lAppID);
            bRet = GetPvaFromLocal(pool, appID, ptask->szVaultID, pswOut);
            if (bRet)
                SendDataToDownstream(pswOut, ptask);
            else
                SendDataToDownstream("Internal server error: 501", ptask);
        }
        return false;
    }
    /*
    if (ptask->bIsActiveUpdate) {
        printf("%s %d\n", __func__, __LINE__);
        bRet = SendRequestToUpstream(ptask->lAppID, ptask->szVaultID, &ptask->UpstreamSockfd);
        if (!bRet) {
            free(task);
            task = NULL;
            return false;
        }
    } 
    else {
        printf("%s %d\n", __func__, __LINE__);
        bRet = ProcessPswInfoFromUpstream(pool, ptask);
        if (!bRet) {
            free(task);
            task = NULL;
            return false;
        }
    }
    */
    //free(task);
    return true;
}

int agent_threadpool_add_task(agent_threadpool_t *pool, CB_FUN handler, void* argv)
{
	agent_task_t *task = NULL; 
    task = (agent_task_t *)malloc(sizeof(agent_task_t));
	if (task == NULL){
		return -1;
	}
    if (handler != NULL) {
        task->handler = handler;
        task->argv = argv;
        task->next = NULL;
    } else {
        //task = (agent_task_t*)argv;
        //task->DownStreamPfd = ((agent_task_t*)argv)->DownStreamPfd;
        task->argv = NULL;
        task->handler = NULL;
        task->ReceiveRequest = Req_ReceiveRequest;
        task->ProcessRequest = Req_ProcessRequest;
        task->sockfd = ((agent_task_t*)argv)->sockfd;
        task->UpstreamSockfd = -1;
        task->lAppID = ((agent_task_t*)argv)->lAppID;
        memset(task->szVaultID, '\0', 128);
        memcpy(task->szVaultID, ((agent_task_t*)argv)->szVaultID, strlen(((agent_task_t*)argv)->szVaultID));
        //memset(task->SeqNumber, '\0', 32);
        memset(task->DownStreamBuffer, '\0', 256);
        memset(task->UpStreamBuffer, '\0', 1024);
        //task->UpStreamBuffer = ((agent_task_t*)argv)->UpStreamBuffer;
        //task->DownStreamBuffer = ((agent_task_t*)argv)->DownStreamBuffer;
        task->bIsActiveUpdate = ((agent_task_t*)argv)->bIsActiveUpdate;
        task->GetFormFlag = ((agent_task_t*)argv)->GetFormFlag;
        task->next = NULL;
    }

	if (pthread_mutex_lock(&pool->mutex) != 0){ 
		free(task);
		return -1;
	}
	do{
		if (pool->tasks.curtasknum >= pool->tasks.maxtasknum) {
			break;
		}

		*(pool->tasks.tail) = task;
		pool->tasks.tail = &task->next;
		pool->tasks.curtasknum++;

        /*
		if (pthread_cond_signal(&pool->cond) != 0){
			break;
		}
        */

		pthread_mutex_unlock(&pool->mutex);
        sem_post(&pool->TasksQueueSem);
		return 0;

	}while(0);
    printf("%s %d\n", __func__, __LINE__);
	pthread_mutex_unlock(&pool->mutex);
	free(task);
	return -1;

}

void agent_threadpool_destroy(agent_threadpool_t *pool)
{
	unsigned int n = 0;
	volatile unsigned int  lock;

	for (; n < pool->threadnum; n++){
		lock = 1;
		if (agent_threadpool_add_task(pool, z_threadpool_exit_cb, (void*)&lock) != 0){
			return;
		}
		while (lock){
			usleep(1);
		}
	}

    sLocalPswCacheInfo *ps = (sLocalPswCacheInfo *)malloc(sizeof(sLocalPswCacheInfo));
    //ps = NULL;
    ps->lock = 1;
    ps->handler = z_threadpool_exit_cb;
    pthread_mutex_lock(&pool->UpdatePswDatFileQueueMutex);
    TAILQ_INSERT_HEAD(&pool->UpdatePswDatFileQueue, ps, next);
    pthread_mutex_unlock(&pool->UpdatePswDatFileQueueMutex);
    sem_post(&pool->UpdatePswDatFileQueueSem);
    while (ps->lock){
        usleep(1);
    }

    sLogInfo *log = (sLogInfo*)malloc(sizeof(sLogInfo));
    //log = NULL;
    log->lock = 1; 
    log->handler = z_threadpool_exit_cb;
    pthread_mutex_lock(&pool->LogCacheQueueMutex);
    TAILQ_INSERT_HEAD(&pool->LogCacheQueue, log, next);
    pthread_mutex_unlock(&pool->LogCacheQueueMutex);
    sem_post(&pool->UpdatePswDatFileQueueSem);
    while (log->lock){
        usleep(1);
    }

    z_thread_mutex_destroy(&pool->mutex);
    z_thread_mutex_destroy(&pool->ThreadFdCountMutex);
    z_thread_mutex_destroy(&pool->OnceUpdateMutex);
    z_thread_mutex_destroy(&pool->LocalPswCacheQueueMutex);
    z_thread_mutex_destroy(&pool->FirstCheckIsUpdateMutex);
    z_thread_mutex_destroy(&pool->LogCacheQueueMutex);
    z_thread_sem_destroy(&pool->UpdatePswDatFileQueueSem);
    z_thread_sem_destroy(&pool->LogCacheQueueSem);
    z_thread_cond_destroy(&pool->cond);
    z_thread_cond_destroy(&pool->OnceUpdateCond);
    z_thread_sem_destroy(&pool->TasksQueueSem);

	z_thread_key_destroy();
	free(pool);
}

int agent_thread_add(agent_threadpool_t *pool)
{
	int ret = 0;
	if (pthread_mutex_lock(&pool->mutex) != 0) {
		return -1;
	}
	ret = z_thread_add(pool);
	pthread_mutex_unlock(&pool->mutex);
	return ret;
}

int agent_set_max_tasknum(agent_threadpool_t *pool,unsigned int num)
{
	if (pthread_mutex_lock(&pool->mutex) != 0) {
		return -1;
	}
	z_change_maxtask_num(pool, num); 
	pthread_mutex_unlock(&pool->mutex);
    return 0;
}

int z_conf_check(agent_threadpool_conf_t *conf)
{
	if (conf == NULL){
		return -1;
	}

	if (conf->threadnum < 1){
		return -1;
	}

	if (conf->maxtasknum < 1){
		conf->maxtasknum = MAX_TASK_SIZE;
	}
	return 0;
}

inline void  z_task_queue_init(agent_task_queue_t* task_queue)
{
	task_queue->head = NULL;
	task_queue->tail = &task_queue->head;
}

inline int z_thread_sem_create(sem_t *sem)
{
    if(sem_init(sem , 0, 0) != 0) {
        return -1;
    }
    return 0;
}

int z_thread_mutex_create(pthread_mutex_t *mutex)
{
	int ret = 0;
	pthread_mutexattr_t attr;

	if (pthread_mutexattr_init(&attr) != 0){
		return -1;
	}

	if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK) != 0){
		pthread_mutexattr_destroy(&attr);
		return -1;
	}

	ret = pthread_mutex_init(mutex,&attr);

	pthread_mutexattr_destroy(&attr);

	return ret;
}

inline void z_thread_sem_destroy(sem_t *sem)
{
    sem_destroy(sem);
}

inline void z_thread_mutex_destroy(pthread_mutex_t *mutex)
{
	pthread_mutex_destroy(mutex);
}

inline int z_thread_cond_create(pthread_cond_t *cond)
{
	return pthread_cond_init(cond, NULL);
}

inline void z_thread_cond_destroy(pthread_cond_t *cond)
{
	pthread_cond_destroy(cond);
}

void SavePswToLocalCacheDatFile(sLocalPswCacheInfo *pswNew)
{
    if (!pswNew)
        return;

    //char g_CurAbsolutePath[256];
    //char g_CacheFileAbsolutePath[256];

    //memset(g_CurAbsolutePath, '\0', 256);
    //memset(g_CacheFileAbsolutePath, '\0', 256);
    /*
    if (NULL == getcwd(g_CurAbsolutePath, 256)) {
    }
    */
    sprintf(g_CacheFileAbsolutePath, "%s/%s/%ld.dat",g_CurAbsolutePath, "pswcache", pswNew->lAppID);
    if (access(g_CacheFileAbsolutePath, F_OK) == 0)
        remove(g_CacheFileAbsolutePath);

    FILE* pFile = NULL;
    pFile = fopen(g_CacheFileAbsolutePath, "wb");
    if (pFile == NULL)
        return;

    long lFileType = htonl(0x1100);
    fwrite(&lFileType, sizeof(long), 1, pFile);

    unsigned char szEncodeKey[16] = {0};
    unsigned char szEndData[16] = { 0xe1, 0x02, 0xa3, 0x04, 0x15, 0xb6, 0x07, 0x08, 0xc9, 0x0a, 0xab, 0x0c, 0x6d, 0x0e, 0x2f, 0x01 };
    int nIndex = 0;
    for (nIndex = 0; nIndex < 16; nIndex++)
    {
        if (nIndex % 3 == 0)
        {
            szEncodeKey[nIndex] = (0x0f) & (szEndData[nIndex] >> 2);
        }
        else if (nIndex % 3 == 1)
        {
            szEncodeKey[nIndex] = (0x1f) & (szEndData[nIndex] >> 3);
        }
        else
        {
            szEncodeKey[nIndex] = (0x3f) & (szEndData[nIndex] >> 4);
        }
    }

    int  nBufferIndex = 0, nPasswordLen = 0;
    char szBuffer[2048] = {0};
    int i = 0;

    memcpy(szBuffer + nBufferIndex, &(pswNew->lAppID), sizeof(long));
    nBufferIndex += sizeof(long);
    nPasswordLen = strlen(pswNew->szPassword);
    memcpy(szBuffer + nBufferIndex, &nPasswordLen, sizeof(int));
    nBufferIndex += sizeof(int);
    memcpy(szBuffer + nBufferIndex, pswNew->szPassword, nPasswordLen);
    nBufferIndex += nPasswordLen;
    time_t tmTimeChange = time(0);
    memcpy(szBuffer + nBufferIndex, &tmTimeChange, sizeof(time_t));
    nBufferIndex += sizeof(time_t);

    char uszEncodeData[4096] = {0};
    int nEncodeLen = 0;
    AES_CryptDataEVP((unsigned char*)szBuffer, nBufferIndex, szEncodeKey, (unsigned char*)uszEncodeData, &nEncodeLen);

    int nDataLen = 0;
    while (nEncodeLen > 0)
    {
        int nWriteLen = fwrite(uszEncodeData + nDataLen, sizeof(char), nEncodeLen, pFile);
        if (nWriteLen <= 0)
            break;
        nEncodeLen -= nWriteLen;
        nDataLen += nWriteLen;
    }

    fclose(pFile);
}

void *z_threadpool_save(void* argv)
{
	unsigned int exit_flag = 0;
	pthread_setspecific(key,(void*)&exit_flag);

    agent_threadpool_t * pool = (agent_threadpool_t *)argv;
    while (!exit_flag) 
    {
        if (sem_trywait(&pool->UpdatePswDatFileQueueSem) != 0)
            continue;
        pthread_mutex_lock(&pool->UpdatePswDatFileQueueMutex);
        if (TAILQ_EMPTY(&pool->UpdatePswDatFileQueue)) {
            pthread_mutex_unlock(&pool->UpdatePswDatFileQueueMutex);
            continue;
        }
        sLocalPswCacheInfo *it = NULL;
        it = TAILQ_FIRST(&pool->UpdatePswDatFileQueue);
        if (it == NULL) {
            pthread_mutex_unlock(&pool->UpdatePswDatFileQueueMutex);
            continue;
        }
        if (it->handler != NULL) {
            it->handler((void*)&(it->lock));
            pthread_mutex_unlock(&pool->UpdatePswDatFileQueueMutex);
            continue;
        } 

        SavePswToLocalCacheDatFile(it);

        TAILQ_REMOVE(&pool->UpdatePswDatFileQueue, it, next);
        free(it);
        it = NULL;

        pthread_mutex_unlock(&pool->UpdatePswDatFileQueueMutex);
    }
    //return pool;
	pthread_exit(0);
}

void Log(const char* format, ... )  
{
    char wzLog[1024] = {0};
    char szBuffer[1024] = {0};
    va_list args;
    va_start(args, format);
    vsprintf(wzLog, format, args);
    va_end(args);

    time_t now;
    time(&now);
    struct tm *local;
    local = localtime(&now);
    sprintf(szBuffer,"%04d-%02d-%02d %02d:%02d:%02d  %s\n", local->tm_year+1900, local->tm_mon,local->tm_mday, local->tm_hour, local->tm_min, local->tm_sec, wzLog);
    int nLen = strlen(szBuffer);
    printf("%s", szBuffer);

    sLogInfo *log = (sLogInfo*)malloc(sizeof(sLogInfo));
    //log = NULL;
    log->lock = 0;
    log->handler = NULL;
    memset(log->logBuffer, '\0', 256);
    memcpy(log->logBuffer, szBuffer, nLen);
    pthread_mutex_lock(&POOL->LogCacheQueueMutex);
    /*
    if ( m_worklogqueue.size() > m_max_log )
    {
        m_loglocker.unlock();
        return ;
    }
    */

    TAILQ_INSERT_HEAD(&POOL->LogCacheQueue, log, next);
    pthread_mutex_unlock(&POOL->LogCacheQueueMutex);

    sem_post(&POOL->LogCacheQueueSem);

    return ;
}

void *z_threadpool_log(void* argv)
{
    agent_threadpool_t * pool = (agent_threadpool_t *)argv;
	unsigned int exit_flag = 0;
	pthread_setspecific(key,(void*)&exit_flag); 

    //char g_CurAbsolutePath[256];
    //char g_LogAbsolutePath[256];
    //memset(g_CurAbsolutePath, '\0', 256);
    //memset(g_LogAbsolutePath, '\0', 256);
    /*
    if (NULL == getcwd(g_CurAbsolutePath, 256)) {
    }
    */
    sprintf(g_LogAbsolutePath, "%s/%s",g_CurAbsolutePath, "log/pvadll.log");

    FILE* pFile = NULL;
REOPEN:
    pFile = fopen(g_LogAbsolutePath, "a+");
    while (!exit_flag) 
    {
        if (sem_wait(&pool->LogCacheQueueSem) != 0)
            continue;

        pthread_mutex_lock(&pool->LogCacheQueueMutex);
        if (TAILQ_EMPTY(&pool->LogCacheQueue)) {
            pthread_mutex_unlock(&pool->LogCacheQueueMutex);
            continue;
        }
        sLogInfo *it = TAILQ_FIRST(&pool->LogCacheQueue);
        if (it == NULL) {
            pthread_mutex_unlock(&pool->LogCacheQueueMutex);
            continue;
        }

        if (it->handler != NULL) {
            it->handler((void*)&it->lock);
            pthread_mutex_unlock(&pool->LogCacheQueueMutex);
            continue;
        }
REWRITE:
        if (pFile == NULL)
            goto REOPEN;
        int nInfoLen = strlen(it->logBuffer);
        int nRetCode = fwrite(it->logBuffer, sizeof(char), nInfoLen, pFile);
        if (nRetCode != nInfoLen)
            goto REWRITE;
        else
        {
            fflush(pFile);
        }

        TAILQ_REMOVE(&pool->LogCacheQueue, it, next);
        free(it);
        it = NULL;
        pthread_mutex_unlock(&pool->LogCacheQueueMutex);
    }
	pthread_exit(0);
}

int z_threadpool_create(agent_threadpool_t *pool)
{
	unsigned int i = 0;
	pthread_t  pid, save_pid, log_pid;
	pthread_attr_t attr;

	if (pthread_attr_init(&attr) != 0){
		return -1;
	}

	if (pool->thread_stack_size != 0)
	{
		if (pthread_attr_setstacksize(&attr, pool->thread_stack_size) != 0){
			pthread_attr_destroy(&attr);
			return -1;
		}
	}

    if (pthread_create(&save_pid, NULL, z_threadpool_save, pool) != 0) {
        pthread_attr_destroy(&attr);
        return -1;
    }

    if (pthread_create(&log_pid, NULL, z_threadpool_log, pool) != 0) {
        pthread_attr_destroy(&attr);
        return -1;
    }

	for (; i < pool->threadnum; ++i)
	{
		if (pthread_create(&pid, &attr, z_threadpool_cycle, pool) != 0) {
            pthread_attr_destroy(&attr);
            return -1;
        }
        printf("start worker thread:%d\n", i);
	}	
	pthread_attr_destroy(&attr);
	return 0;
}

int z_thread_add(agent_threadpool_t *pool)
{
	pthread_t  pid;
	pthread_attr_t attr;
	int ret = 0;
	if (pthread_attr_init(&attr) != 0){
		return -1;
	}
	if (pool->thread_stack_size != 0)
	{
		if (pthread_attr_setstacksize(&attr, pool->thread_stack_size) != 0){
			pthread_attr_destroy(&attr);
			return -1;
		}
	}
	ret = pthread_create(&pid, &attr, z_threadpool_cycle,pool);
	if (ret == 0)
	{
		pool->threadnum++;
	}
	pthread_attr_destroy(&attr);
	return ret;
}

int EnCodeSendInfo(char* pszInSendData, int nInSendDataLen, char* pszOutEncodeData, int nEncodeType)
{
    if (nEncodeType == 0) 
    {
        memcpy(pszOutEncodeData, pszInSendData, nInSendDataLen);
        return nInSendDataLen;
    }
    else if (nEncodeType == 1) 
    {
        int nRetCode = 0, nRandValue = 0;
        srand((unsigned int)time(0));
        unsigned char uszKey[16] = { 0 };
        int nIndex = 0;
        for (nIndex = 0; nIndex < 16; nIndex++) 
        {
            nRandValue = rand();
            nRetCode = nRandValue % 3;
            if (nRetCode == 0)
            {
                uszKey[nIndex] = (0x0f) & (nRandValue >> 2);
            }
            else if (nRetCode == 1)
            {
                uszKey[nIndex] = (0x1f) & (nRandValue >> 3);
            }
            else
            {
                uszKey[nIndex] = (0x3f) & (nRandValue >> 4);
            }
        }

        int nEncodeLen = 0;
        unsigned char uszEncodeData[10240] = { 0 };
        bool bRetCode = AES_CryptDataEVP((unsigned char*)pszInSendData, nInSendDataLen, uszKey, (unsigned char*)uszEncodeData, &nEncodeLen);

        memcpy(pszOutEncodeData, uszEncodeData, nEncodeLen);
        pszOutEncodeData += nEncodeLen;

        unsigned char szSingleKey[8] = { 0 }, szDoubleKey[8] = { 0 };
        for (nIndex = 0; nIndex < 8; nIndex++)
        {
            szSingleKey[nIndex] = uszKey[nIndex * 2];
            szDoubleKey[nIndex] = uszKey[nIndex * 2 + 1];
        }

        unsigned char szEndData[16] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x01 };
        int nRandRemaind = rand() % 8;

        memcpy(pszOutEncodeData, szSingleKey, 8);
        pszOutEncodeData += 8;

        memcpy(pszOutEncodeData, &(szEndData[nRandRemaind]), 8);
        pszOutEncodeData += 8;

        memcpy(pszOutEncodeData, szDoubleKey, 8);
        pszOutEncodeData += 8;

        int t = 0;
        for (t = 0; t < nRandRemaind; t++)
        {
            *pszOutEncodeData = szEndData[t];
            pszOutEncodeData++;
        }

        int k = 0;
        for (k = nRandRemaind + 8; k < 16; k++)
        {
            *pszOutEncodeData = szEndData[k];
            pszOutEncodeData++;
        }

        int nXmlLen = nEncodeLen + 32;
        return nXmlLen;
    }
    else if (nEncodeType == 2)
    {
        int nLen = nInSendDataLen;
        int nRemainder = nLen % 2;
        int nSingleLen = 0, nDoubleLen = 0;
        if (nRemainder > 0)
            nSingleLen = (nLen - 1) / 2 + 1;
        else
            nSingleLen = nLen / 2;

        nDoubleLen = nLen - nSingleLen;

        int nIndex = 0;
        for (nIndex = 0; nIndex < nSingleLen; nIndex++)
        {
            *pszOutEncodeData = pszInSendData[nIndex * 2];
            pszOutEncodeData++;
        }

        int k = 0;
        for (k = 0; k < nDoubleLen; k++)
        {
            *pszOutEncodeData = pszInSendData[k * 2 + 1];
            pszOutEncodeData++;
        }
        return nLen;
    }
    else
    {
        memcpy(pszOutEncodeData, pszInSendData, nInSendDataLen);
        return nInSendDataLen;
    }
    return 0;
}

bool SendDataToServer(int* pnSocket, char* pszSendData, int nSendLen)
{
    while (nSendLen > 0)
    {
        int nRealSend = send(*pnSocket, pszSendData, nSendLen, 0);
        if (nRealSend == -1)
        {
            if (*pnSocket != -1)
            {
                printf("%s %d\n", __func__, __LINE__);
                close(*pnSocket);
                *pnSocket = -1;
            }
            Log("send req data info failed!");
            return false;
        }
        nSendLen -= nRealSend;
    }
    printf("%s %d\n", __func__, __LINE__);
    return true;
}

//bool SendRequestToUpstream(long appID, char *valueID, int *sockfd, char *szSeqNumber)
bool SendRequestToUpstream(long appID, char *valueID, int *sockfd)
{
    time_t tmCurrent = time(0);
    char szSeqNumber[32] = {0};
    sprintf(szSeqNumber, "%ld%ld", tmCurrent, rand() % RAND_MAX + 1);
    //memcpy(m_SeqNumber, szSeqNumber, strlen(szSeqNumber));
    char szSendXml[4096] = {0};
    int nXmlLen = strlen("<?xml version=\"1.0\" encoding=\"utf-8\"?><req type=\"pva\" obj=\"t_password_info\" seq=\"");
    memcpy(szSendXml, "<?xml version=\"1.0\" encoding=\"utf-8\"?><req type=\"pva\" obj=\"t_password_info\" seq=\"", nXmlLen);
    memcpy(szSendXml + nXmlLen, szSeqNumber, strlen(szSeqNumber));
    nXmlLen += strlen(szSeqNumber);
    memcpy(szSendXml + nXmlLen, "\"><vaultid>", strlen("\"><vaultid>"));
    nXmlLen += strlen("\"><vaultid>");
    if (valueID != NULL && valueID != '\0') {
        memcpy(szSendXml + nXmlLen, valueID, strlen(valueID));
        nXmlLen += strlen(valueID);
    }
    else {
        memcpy(szSendXml + nXmlLen, g_SafeBoxID, strlen(g_SafeBoxID));
        //memcpy(szSendXml + nXmlLen, "2478cbd7fe8f4f22810664407e01f437", strlen("2478cbd7fe8f4f22810664407e01f437"));
        nXmlLen += strlen(g_SafeBoxID);
        //nXmlLen += strlen("2478cbd7fe8f4f22810664407e01f437");
    }
    memcpy(szSendXml + nXmlLen, "</vaultid><appid>", strlen("</vaultid><appid>"));
    nXmlLen += strlen("</vaultid><appid>");
    char m_lAppID[30] = {0};
    sprintf(m_lAppID, "%ld", appID);
    memcpy(szSendXml + nXmlLen, m_lAppID, strlen(m_lAppID));
    nXmlLen += strlen(m_lAppID);
    memcpy(szSendXml + nXmlLen, "</appid></req>", strlen("</appid></req>"));
    nXmlLen += strlen("</appid></req>");

    char szEncodeXml[8192] = {0};
    int* pHeader = (int*)szEncodeXml;
    *pHeader = htonl(0x1100);
    pHeader += 1;

    int nEncodeLen = 0;
    nEncodeLen = EnCodeSendInfo(szSendXml, nXmlLen, szEncodeXml + sizeof(int) * 2, 1);
    nEncodeLen += sizeof(int) * 2;
    *pHeader = htonl(nEncodeLen);

    printf("send upstream xml:%s\n", szSendXml);
    char szRecvData[8192] = {0};
    int  nRecvDataLen = 0;
    bool bRetCode = SendDataToServer(sockfd, szEncodeXml, nEncodeLen);
    if (!bRetCode) 
    {
        //Log("");
        return false;
    }

    /*
    char szDecodeData[8192] = {0};
    int  nDecodeData = 0;
    bRetCode = DecodeRecvData(szRecvData, szDecodeData, &nDecodeData, pszErrorInfo);
    if (!bRetCode)
        return false;

    char szPAPassword[256] = {0};
    bRetCode = ParseXmlData(pszSeqNumber, szDecodeData, nDecodeData, szPAPassword, pnErrorCode, pszErrorInfo);
    if (!bRetCode)
        return false;

    int nPswLen = strlen(szPAPassword);
    if (nPswLen > 32)
        memcpy(pszReturnPsw, szPAPassword, 32);
    else
        memcpy(pszReturnPsw, szPAPassword, nPswLen);
    */

    return true;
}

bool GetOnePswFromLocalCache(agent_threadpool_t *pool, long appID, char *pswOut)
{
    pthread_mutex_lock(&pool->LocalPswCacheQueueMutex);
    if (TAILQ_EMPTY(&pool->LocalPswCacheQueue)) {
        pthread_mutex_unlock(&pool->LocalPswCacheQueueMutex);
        pswOut = NULL;
        return false;
    }
    sLocalPswCacheInfo *it = NULL;
    time_t tmTimeChange = time(0);
    TAILQ_FOREACH(it, &pool->LocalPswCacheQueue, next) {
        if (it->lAppID == appID && it->tmChange + 60 > tmTimeChange) {
            memcpy(pswOut, it->szPassword, strlen(it->szPassword));
            break;
        }
    }
    if (it == TAILQ_END(&pool->LocalPswCacheQueue)) {
        pthread_mutex_unlock(&pool->LocalPswCacheQueueMutex);
        pswOut = NULL;
        return false;
    }
    pthread_mutex_unlock(&pool->LocalPswCacheQueueMutex);
    return true;
}

bool ProcessPswInfoFromUpstream(agent_threadpool_t *pool, agent_task_t *ptask)
{
    bool bRet;
    char pswSendData[128] = {0};
    bRet = GetOnePswFromLocalCache(pool, ptask->lAppID, pswSendData);
    if (!bRet) {
        goto TOUPSTREAM;
    }
    else {
        if (pswSendData == NULL)
            goto TOUPSTREAM;
    }
    ptask->GetFormFlag = 1;
    SendDataToDownstream(pswSendData, ptask);
    return true;

TOUPSTREAM:
    /*
    bRet = SendRequestToUpstream(ptask->lAppID, ptask->szVaultID, &ptask->UpstreamSockfd);
    if (!bRet)
        return false;
        */
    return true;
}

bool GetDataFromServer(int pSockClient, char* pszRecvData, int* pRecvDataLen, char* pszErrorInfo)
{ 
    char szRecvBuffer[4096] = {0};
    int nRecvLen = recv(pSockClient, szRecvBuffer, 4096, 0);
    if (nRecvLen == -1 || nRecvLen == 0)
    {
        close(pSockClient);
        //pSockClient = -1;

        //Log("recv data from remote server failed!");
        return false;
    }

    memcpy(pszRecvData, szRecvBuffer, nRecvLen);
    *pRecvDataLen = nRecvLen;
    return true;
}

bool SendDataToServer2(int pnSocket, char* pszSendData, int nSendLen, char* pszRecvData, int* pRecvDataLen, char* pszErrorInfo)
{
    while (nSendLen > 0)
    {
        int nRealSend = send(pnSocket, pszSendData, nSendLen, 0);
        if (nRealSend == -1)
        {
            if (pnSocket != -1)
            {
                close(pnSocket);
                //pnSocket = -1;
            }
            Log("send req data info failed!");
            return false;
        }
        nSendLen -= nRealSend;
    }

    return GetDataFromServer(pnSocket, pszRecvData, pRecvDataLen, pszErrorInfo);
}

//bool ParseUpstreamXmlInfo(char *appID, char *valueID, char *pszXmlBuffer, int nBufferLen, char *pswOut, char *SeqNumber)
bool ParseUpstreamXmlInfo(char *appID, char *valueID, char *pszXmlBuffer, int nBufferLen, char *pswOut, long lAppID)
{
    printf("%s %d :%s\n", __func__, __LINE__, pszXmlBuffer);
    xmlDocPtr doc;
    doc = xmlParseMemory(pszXmlBuffer, nBufferLen);
    if (doc == NULL)
    {
        Log("parse xml from buffer is wrong!");
        return false;
    }

    xmlNodePtr xmlRoot;
    xmlRoot = xmlDocGetRootElement(doc);
    if (xmlRoot == NULL)
    {
        Log("get root element from xml is wrong");
        xmlFreeDoc(doc);
        return false;
    }

    xmlChar* pXmlSeq = NULL, *pXmlCode = NULL;
    pXmlSeq = xmlGetProp(xmlRoot, BAD_CAST("seq"));
    if (pXmlSeq == NULL)
    {
        Log("get seq element from xml is wrong");
        xmlFreeDoc(doc);
        return false;
    }

    bool bUpdateXml = false;
    char szSeqNumber[256] = {0};
    char szCode[100] = {0};
    char* pszXmlName = (char*)pXmlSeq;
    memcpy(szSeqNumber, pszXmlName, strlen(pszXmlName));
    xmlFree(pXmlSeq);  

    if (memcmp(szSeqNumber, "pva_10000", strlen("pva_10000")) != 0) {
        //char szCode[100] = {0};
        pXmlCode = xmlGetProp(xmlRoot, BAD_CAST("code"));
        if (pXmlCode == NULL)
        {
            Log("get code element from xml is wrong");
            xmlFreeDoc(doc);
            return false;
        }

        pszXmlName = (char*)pXmlCode;
        memcpy(szCode, pszXmlName, strlen(pszXmlName));
        xmlFree(pXmlCode);

        xmlNodePtr nodeChild;
        nodeChild = xmlRoot->children;
        if (nodeChild == NULL)
        {
            Log("get child element from xml is wrong");
            xmlFreeDoc(doc);
            return false;
        }

        xmlChar* pXmlPassword = NULL;   
        pXmlPassword = xmlNodeGetContent(nodeChild);
        if (pXmlPassword == NULL)
        {
            Log("get password element from xml is wrong");
            xmlFreeDoc(doc);
            return false;
        }

        char* pszPassword = (char*)pXmlPassword;
        int nPswInfoLen = strlen(pszPassword);
        if (nPswInfoLen > 200)
            memcpy(pswOut, pszPassword, 200);
        else
            memcpy(pswOut, pszPassword, nPswInfoLen);

        xmlFree(pXmlPassword);
        xmlFreeDoc(doc); 

        appID = NULL;
        valueID = NULL;
    } else {
        //char szCode[100] = {0};
        pXmlCode = xmlGetProp(xmlRoot, BAD_CAST("code"));
        if (pXmlCode == NULL)
        {
            Log("get code element from xml is wrong");
            xmlFreeDoc(doc);
            return false;
        }

        pszXmlName = (char*)pXmlCode;
        memcpy(szCode, pszXmlName, strlen(pszXmlName));
        xmlFree(pXmlCode);


        xmlNodePtr pChildElement = xmlRoot->children; 
        if (pChildElement == NULL) 
        { 
            Log("Get xml name element failed");
            xmlFreeDoc(doc); 
            return false; 
        } 

        if(xmlStrcmp(pChildElement->name, (const xmlChar*)"appid") != 0) 
        { 
            Log("Get xml appid element failed");
            xmlFreeDoc(doc); 
            return false; 
        } 

        xmlChar* pXmlAppID = NULL; 
        pXmlAppID = xmlNodeGetContent(pChildElement); 
        if (pXmlAppID == NULL) 
        { 
            Log("Get xml appid value failed");
            xmlFreeDoc(doc); 
            return false; 
        } 

        char szAppID[64] = {0}; 
        char* pXmlAppIDInfo = (char*)pXmlAppID ; 
        int nAppIDLen = strlen(pXmlAppIDInfo); 
        if (nAppIDLen >= 64) 
            memcpy(szAppID, pXmlAppIDInfo, 63); 
        else 
            memcpy(szAppID, pXmlAppIDInfo, nAppIDLen); 
        xmlFree(pXmlAppID); 

        xmlNodePtr pPasswordElement = xmlRoot->children->next; 
        if (pPasswordElement == NULL) 
        { 
            Log("Get xml password element failed");
            xmlFreeDoc(doc); 
            return false; 
        } 
        if(xmlStrcmp(pPasswordElement->name, (const xmlChar*)"pass") != 0) 
        { 
            Log("Get xml pass element failed");
            xmlFreeDoc(doc); 
            return false; 
        } 

        xmlChar* pXmlPassword = NULL; 
        pXmlPassword = xmlNodeGetContent(pPasswordElement); 
        if (pXmlPassword == NULL) 
        { 
            Log("Get xml password value failed");
            xmlFreeDoc(doc); 
            return false; 
        } 

        char szPassword[64] = {0}; 
        char* pXmlPasswordInfo = (char*)pXmlPassword ; 
        int nPswLen = strlen(pXmlPasswordInfo); 
        if (nPswLen >= 64) 
            memcpy(szPassword, pXmlPasswordInfo, 63); 
        else 
            memcpy(szPassword, pXmlPasswordInfo, nPswLen); 

        xmlFree(pXmlPassword); 
        xmlFreeDoc(doc); 

        memcpy(appID, szAppID, strlen(szAppID)); 
        memcpy(pswOut, szPassword, strlen(szPassword)); 
        valueID = NULL;
        if (lAppID != atol(appID)) {
            bUpdateXml = true;
        }
    }

    /*
    bool bSeqNumberValid = false;
    if (memcmp(SeqNumber, szSeqNumber, strlen(szSeqNumber)) == 0 &&
    memcmp(szSeqNumber, SeqNumber, strlen(SeqNumber)) == 0)
        bSeqNumberValid = true;

    if (!bSeqNumberValid)
    {
        Log("get seq number is not same to send seq number");
        return false;
    }
    */

    int nCode = atol(szCode);
    if (nCode > 0)
    {
        Log("get password error,please check the send data");       
        return false;
    }

    if (bUpdateXml) {
        ReplaceLocalPswCache(appID, NULL, pswOut, POOL);
        return false;
    }
    return true;
}

bool ParseLoginReqXmlData(char* pszSeqNumber, char* pszXmlBuffer, int nBufferLen)
{
    xmlDocPtr doc;
    doc = xmlParseMemory(pszXmlBuffer, nBufferLen);
    if (doc == NULL)
    {
        Log("parse xml from buffer is wrong!");
        return false;
    }

    xmlNodePtr xmlRoot;
    xmlRoot = xmlDocGetRootElement(doc);
    if (xmlRoot == NULL)
    {
        Log("get root element from xml is wrong");
        xmlFreeDoc(doc);
        return false;
    }

    xmlChar* pXmlSeq = NULL, *pXmlCode = NULL;
    pXmlSeq = xmlGetProp(xmlRoot, BAD_CAST("seq"));
    if (pXmlSeq == NULL)
    {
        Log("get seq element from xml is wrong");
        xmlFreeDoc(doc);
        return false;
    }

    char szSeqNumber[256] = {0};
    char* pszXmlName = (char*)pXmlSeq;
    memcpy(szSeqNumber, pszXmlName, strlen(pszXmlName));
    xmlFree(pXmlSeq);  

    char szCode[100] = {0};
    pXmlCode = xmlGetProp(xmlRoot, BAD_CAST("code"));
    if (pXmlCode == NULL)
    {
        Log("get code element from xml is wrong");
        xmlFreeDoc(doc);
        return false;
    }

    pszXmlName = (char*)pXmlCode;
    memcpy(szCode, pszXmlName, strlen(pszXmlName));
    xmlFree(pXmlCode);
    xmlFreeDoc(doc); 

    /*
    bool bSeqNumberValid = false;
    if (memcmp(pszSeqNumber, szSeqNumber, strlen(szSeqNumber)) == 0 &&
    memcmp(szSeqNumber, pszSeqNumber, strlen(pszSeqNumber)) == 0)
    bSeqNumberValid = true;

    if (!bSeqNumberValid)
    {
        Log("get seq number is not same to send seq number");
        return false;
    }
    */

    int nCode = atol(szCode);
    if (nCode > 0)
    {
        Log("get password error,please check the send data");     
        return false;
    }
    return true;
}

bool VerifyLogin(int sockfd, char *localIP)
{
    char szSendData[8192] = { 0 };
    int nDataLen = 0;
    nDataLen = strlen("<?xml version=\"1.0\" encoding=\"utf-8\"?><req type=\"auth\" user=\"");
    memcpy(szSendData, "<?xml version=\"1.0\" encoding=\"utf-8\"?><req type=\"auth\" user=\"", nDataLen);
    memcpy(szSendData + nDataLen, g_LoginName, strlen(g_LoginName));
    //memcpy(szSendData + nDataLen, "aimuser", strlen("aimuser"));
    nDataLen += strlen(g_LoginName);
    //nDataLen += strlen("aimuser");
    memcpy(szSendData + nDataLen, "\" pass=\"", strlen("\" pass=\""));
    nDataLen += strlen("\" pass=\"");
    memcpy(szSendData + nDataLen, g_LoginPassword, strlen(g_LoginPassword));
    //memcpy(szSendData + nDataLen, "7da43a4dc548515c5616d928e968ddfbc9b20d96", strlen("7da43a4dc548515c5616d928e968ddfbc9b20d96")/*g_szPassword, strlen(g_szPassword)*/);
    nDataLen += strlen(g_LoginPassword);
    //nDataLen += strlen("7da43a4dc548515c5616d928e968ddfbc9b20d96"/*g_szPassword*/);
    memcpy(szSendData + nDataLen, "\" role=\"", strlen("\" role=\""));
    nDataLen += strlen("\" role=\"");
    memcpy(szSendData + nDataLen, g_SystemName, strlen(g_SystemName));
    //memcpy(szSendData + nDataLen, "huawei@aim", strlen("huawei@aim"));
    //nDataLen += strlen("huawei@aim");
    memcpy(szSendData + nDataLen, "\" ip=\"", strlen("\" ip=\""));
    nDataLen += strlen("\" ip=\"");
    if (strlen(localIP) > 0)
    {
        memcpy(szSendData + nDataLen, localIP, strlen(localIP));
        nDataLen += strlen(localIP);
    }
    else
    {
        memcpy(szSendData + nDataLen, "127.0.0.1", strlen("127.0.0.1"));
        nDataLen += strlen("127.0.0.1");
        //memcpy(szSendData + nDataLen, g_szIPAddress, strlen(g_szIPAddress));
        //nDataLen += strlen(g_szIPAddress);
    }

    memcpy(szSendData + nDataLen, "\" md5=\"", strlen("\" md5=\""));
    nDataLen += strlen("\" md5=\"");
    memcpy(szSendData + nDataLen, "null", strlen("null")/*g_szExeKey, strlen(g_szExeKey)*/);
    nDataLen += strlen("null"/*g_szExeKey*/);
    memcpy(szSendData + nDataLen, "\" seq=\"", strlen("\" seq=\""));
    nDataLen += strlen("\" seq=\"");

    time_t tmCurrent = time(0);
    char szSeqNumber[32] = { 0 };
    snprintf(szSeqNumber, 32, "%ld", tmCurrent);
    memcpy(szSendData + nDataLen, szSeqNumber, strlen(szSeqNumber));
    nDataLen += strlen(szSeqNumber);
    memcpy(szSendData + nDataLen, "\"></req>", strlen("\"></req>"));
    nDataLen += strlen("\"></req>");

    char szEncodeXml[8192] = { 0 };
    int* pHeader = (int*)szEncodeXml;
    *pHeader = htonl(0x1100);
    pHeader += 1;

    int nEncodeLen = 0;
    nEncodeLen = EnCodeSendInfo(szSendData, nDataLen, szEncodeXml + sizeof(int) * 2, 1);
    nEncodeLen += sizeof(int) * 2;
    *pHeader = htonl(nEncodeLen);

    int nRecvDataLen = 0;
    char szRecvData[8192] = {0};
    char pszErrorInfo[1024] = {0};
    bool bRetCode = SendDataToServer2(sockfd, szEncodeXml, nEncodeLen, szRecvData, &nRecvDataLen, pszErrorInfo);
    if (!bRetCode) {
        //Log("");
        return false;
    }

    char szDecodeData[8192] = {0};
    int  nDecodeData = 0;
    char *appID = NULL, *valueID = NULL, *pswReturn = NULL /**pswIn = NULL*/;
    bRetCode =  ParseRecvInfo(appID, valueID, pswReturn, szRecvData, 1, szSeqNumber, 0);
    if (!bRetCode)
    {
        if (sockfd != -1)
        {
            close(sockfd);
        }
        return false;
    }

    return true;
}

bool SelectListen(int sockfd)
{
    struct timeval tm;
    int len, err = -1;
    tm.tv_sec = 3;  
    tm.tv_usec = 0;  
    fd_set wset;
    FD_ZERO(&wset);  
    FD_SET(sockfd, &wset);  
    int retval = select(sockfd + 1, NULL, &wset, NULL, &tm);  
    switch(retval)  
    {  
        case -1:  
        {
            perror("select");  
            return false;  
        }
        case 0:  
        {
            printf("connect timeout\n");  
            return false;  
        }
        case 1:
        {
            if(FD_ISSET(sockfd, &wset))  
            {  
                printf("build connect successfully!\n");
            }
            break;
        }
        default:  
        {
            if(FD_ISSET(sockfd, &wset))  
            {  
                if(getsockopt(sockfd,SOL_SOCKET,SO_ERROR, &err, (socklen_t *)&len) < 0)  
                {  
                    return false;  
                }  
                if(err != 0)  
                {  
                    return false;
                }  
            }
            break;  
        }
    }
    return true;
}

bool LoginPvaServer(int *sockfd)
{
    struct sockaddr_in address;
    int reuse, on, n = 0, err, sndbuf;
    int m_tryconnect_count = 0;
    int m_sockfd;
    bool bRet;
    char m_LocalIP[128];

RETRYMAIN:
    { /*connect remote main ip*/
        //bzero( &address, sizeof( address ) );
        memset( &address, 0, sizeof( address ) );
        address.sin_family = AF_INET;
        printf("%s %s\n", __func__, g_MasterIP);
        inet_pton( AF_INET, g_MasterIP, &address.sin_addr );
        address.sin_port = htons( atoi(g_Port) );
        m_sockfd = -1;
        m_sockfd = socket( PF_INET, SOCK_STREAM, 0 );
        printf( "connectting main password server\n" );
        if( m_sockfd < 0 )
        {
            Log("main socket() error");
            close(m_sockfd);
            goto RETRYMAIN;
        }

        reuse = 1, on = 1, sndbuf = 0;
        setsockopt(m_sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
        setsockopt(m_sockfd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on));
        //setsockopt(m_sockfd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
        struct timeval timeout;
        timeout.tv_sec = 3;
        timeout.tv_usec = 0;
        socklen_t len = sizeof(timeout);
        setsockopt(m_sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, len);
        SetNonBlocking(m_sockfd);

        if ((err = connect( m_sockfd, ( struct sockaddr* )&address, sizeof( address ))) == 0  )
        {
            printf( "build main connection successfully\n");
            goto SUCCESS;
        }
        else if (err < 0)
        {
            if (errno == EINPROGRESS) {
                bRet = SelectListen(m_sockfd);
                if (bRet)
                    goto SUCCESS;
            }
        }

        Log("connect main IP failed");
        fcntl(m_sockfd, F_SETFL, fcntl( m_sockfd, F_GETFL, 0 ) & ~O_NONBLOCK);
        close(m_sockfd);
    }

RETRYSTANDBY:
    { /*connect remote standby ip*/
        //bzero( &address, sizeof( address ) );
        memset( &address, 0, sizeof( address ) );
        address.sin_family = AF_INET;
        printf("%s %s\n", __func__, g_StandbyIP);
        inet_pton( AF_INET, g_StandbyIP, &address.sin_addr );
        address.sin_port = htons( atoi(g_Port) );
        m_sockfd = -1;
        m_sockfd = socket( PF_INET, SOCK_STREAM, 0 );
        printf( "connectting standby password server\n" );
        if( m_sockfd < 0 )
        {
            Log("standby socket() error");
            close(m_sockfd);
            goto RETRYSTANDBY;
        }

        reuse = 1, on = 1, sndbuf = 0;
        setsockopt(m_sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
        setsockopt(m_sockfd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on));
        //setsockopt(m_sockfd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
        struct timeval timeout;
        timeout.tv_sec = 3;
        timeout.tv_usec = 0;
        socklen_t len = sizeof(timeout);
        setsockopt(m_sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, len);
        SetNonBlocking(m_sockfd);

        if ((err = connect( m_sockfd, ( struct sockaddr* )&address, sizeof( address ))) == 0  )
        {
            printf( "build minor connection successfully\n");
            goto SUCCESS;
        }
        else if (err < 0)
        {
            if (errno == EINPROGRESS) {
                bRet = SelectListen(m_sockfd);
                if (bRet)
                    goto SUCCESS;
            }
        }
        Log("connect standby IP failed");
        fcntl(m_sockfd, F_SETFL, fcntl( m_sockfd, F_GETFL, 0 ) & ~O_NONBLOCK);
        close(m_sockfd);
    }
    m_tryconnect_count += 1;
    n += 1000;
    if (m_tryconnect_count != RETRY_CONNECT_MAX_COUNT) {
        usleep(n * m_tryconnect_count);
        goto RETRYMAIN;
    }
    return false;

SUCCESS:
    memset(m_LocalIP, 0, 128);
    char szHostName[256] = {0};
    gethostname(szHostName, 256);
    struct hostent* pHostent = (struct hostent*)gethostbyname(szHostName);
    if (pHostent != NULL)
    {
        char* pszHostAddress = inet_ntoa(*((struct in_addr *)pHostent->h_addr));
        if (pszHostAddress)
        {
            memcpy(m_LocalIP, pszHostAddress, strlen(pszHostAddress));
        }
    }
    fcntl(m_sockfd, F_SETFL, fcntl( m_sockfd, F_GETFL, 0 ) & ~O_NONBLOCK);
    *sockfd = m_sockfd;
    int m = 0;

VERIFICATION:
    //bRet = VerifyLogin(m_sockfd, "192.168.2.100" /*m_LocalIP*/);
    bRet = VerifyLogin(m_sockfd, m_LocalIP);
    if (!bRet) {
        if (m >= 2)  {
            close(m_sockfd);
            Log("verifylogin failed");
            return false;
        }
        m++;
        goto VERIFICATION;
    }
    printf("verifylogin successfully\n");
    return true;

}

void ChangeVariableNetworkState(agent_threadpool_t *pool, pthread_t pfd, bool isOnline)
{
    int i;
    pthread_mutex_lock(&pool->ThreadFdCountMutex);
    for (i = 0; i < pool->ThreadFdCount; i++) {
        if (pool->pfds[i].fd == pfd && pool->pfds[i].isOnline == 1) {
            if (!isOnline) {
                pool->NetworkState--;
                printf("%s %d networkstate:%d\n", __func__, __LINE__, pool->NetworkState);
                pool->pfds[i].isOnline = 0;
            }
            break;
        }
        else if (pool->pfds[i].fd == pfd && pool->pfds[i].isOnline == -1) {
            if (isOnline) {
                pool->NetworkState++;
                printf("%s %d networkstate:%d\n", __func__, __LINE__, pool->NetworkState);
                pool->pfds[i].isOnline= 1;
            }
            break;
        }
        else if (pool->pfds[i].fd == pfd && pool->pfds[i].isOnline == 0) {
            if (isOnline) {
                pool->NetworkState++;
                printf("%s %d networkstate:%d\n", __func__, __LINE__, pool->NetworkState);
                pool->pfds[i].isOnline = 1;
            }
            break;
        }
    }
    pthread_mutex_unlock(&pool->ThreadFdCountMutex);
}

inline void z_change_maxtask_num(agent_threadpool_t *pool, unsigned int num)
{
	pool->tasks.maxtasknum = num;
	if (pool->tasks.maxtasknum < 1)
	{
		pool->tasks.maxtasknum = MAX_TASK_SIZE;
	}
}

bool NotifyUpdateCache(agent_threadpool_t *pool)
{
    int ret = pthread_mutex_trylock(&pool->OnceUpdateMutex);
    if (ret == 0) {
        if (!pool->bOnceUpdate) {
            pool->bOnceUpdate = true;
            pthread_cond_signal(&pool->OnceUpdateCond);
        }
        pthread_mutex_unlock(&pool->OnceUpdateMutex);
    }
    return true;
}

bool ReplaceLocalPswCache(char *appID, char *valueID, char *pswInfo, agent_threadpool_t *pool)
{
    long lAppID = atol(appID);

    sLocalPswCacheInfo *ps = (sLocalPswCacheInfo *)malloc(sizeof(sLocalPswCacheInfo));
    //ps = NULL;
    ps->lock = 0;
    ps->handler = NULL;
    ps->lAppID = lAppID;
    if (valueID != NULL && valueID == '\0') {
        memset(ps->szVaultID, '\0', 64);
        memcpy(ps->szVaultID, valueID, strlen(valueID));
    }
    else {
        memset(ps->szVaultID, '\0', 64);
        memcpy(ps->szVaultID, g_SafeBoxID, strlen(g_SafeBoxID));
        //memcpy(ps->szVaultID, "2478cbd7fe8f4f22810664407e01f437", strlen("2478cbd7fe8f4f22810664407e01f437"));
    }
    memset(ps->szPassword, '\0', 64);
    memcpy(ps->szPassword, pswInfo, strlen(pswInfo));
    ps->tmChange = time(0);
    //ps->next = NULL;

    pthread_mutex_lock(&pool->LocalPswCacheQueueMutex);
    if (!TAILQ_EMPTY(&pool->LocalPswCacheQueue)) {
        sLocalPswCacheInfo *it = NULL;
        TAILQ_FOREACH(it, &pool->LocalPswCacheQueue, next) {
            if (it->lAppID == lAppID) {
                //TODO
                //TAILQ_REPLACE(&pool->LocalPswCacheQueue, it , ps, next);
                it->tmChange = time(0);
                memset(it->szPassword, '\0', 64);
                memcpy(it->szPassword, pswInfo, strlen(pswInfo));
                break;
            }
        }
        if (it == TAILQ_END(&pool->LocalPswCacheQueue)) {
            TAILQ_INSERT_TAIL(&pool->LocalPswCacheQueue, ps, next);
        } 
    } else {
        TAILQ_INSERT_TAIL(&pool->LocalPswCacheQueue, ps, next);
    }

    pthread_mutex_unlock(&pool->LocalPswCacheQueueMutex);

    pthread_mutex_lock(&pool->UpdatePswDatFileQueueMutex);
    TAILQ_INSERT_HEAD(&pool->UpdatePswDatFileQueue, ps, next);
    pthread_mutex_unlock(&pool->UpdatePswDatFileQueueMutex);

    sem_post(&pool->UpdatePswDatFileQueueSem);
}

void ParseDownstreamInfo(char *appID, char *valueID, char *pszDecodeData, int nBufferLen)
{
    char temp[256];
    memset(temp, '\0', 256);
    memcpy(temp, pszDecodeData, strlen(pszDecodeData));
    char *m_vID = NULL;
    m_vID = strpbrk(temp,"=");
    if (!m_vID) {
        Log("ParseDownstreamInfo failed");
        return;
    }
    *m_vID++ = '\0';
    memcpy(valueID, m_vID, strlen(m_vID));
    memcpy(appID, temp, strlen(temp));
    return;
}

bool ParseReActiveUpdateXmlInfo(char *appID, char *valueID,char *pszXmlBuffer, int nBufferLen, char *pswOut)
{
    xmlDocPtr doc; 
    doc = xmlParseMemory(pszXmlBuffer, nBufferLen); 
    if (doc == NULL) 
    { 
        Log("parse xml from buffer is wrong!");
        return false; 
    } 

    xmlNodePtr xmlRoot; 
    xmlRoot = xmlDocGetRootElement(doc); 
    if (xmlRoot == NULL) 
    { 
        Log("get root element from xml is wrong");
        xmlFreeDoc(doc); 
        return false; 
    } 

    xmlChar* pXmlSeq = NULL; 
    pXmlSeq = xmlGetProp(xmlRoot, BAD_CAST("seq")); 
    if (pXmlSeq == NULL) 
    { 
        Log("get seq element from xml is wrong");
        xmlFreeDoc(doc); 
        return false; 
    } 

    char szSeqNumber[256] = {0}; 
    char* pszXmlName = (char*)pXmlSeq; 
    memcpy(szSeqNumber, pszXmlName, strlen(pszXmlName)); 
    xmlFree(pXmlSeq); 

    if (memcmp(szSeqNumber, "pva_10000", strlen("pva_10000")) != 0) 
    { 
        Log("get pva_10000 element from xml is wrong");
        xmlFreeDoc(doc); 
        return false; 
    } 

    xmlNodePtr pChildElement = xmlRoot->children; 
    if (pChildElement == NULL) 
    { 
        Log("Get xml name element failed");
        xmlFreeDoc(doc); 
        return false; 
    } 

    if(xmlStrcmp(pChildElement->name, (const xmlChar*)"appid") != 0) 
    { 
        Log("Get xml appid element failed");
        xmlFreeDoc(doc); 
        return false; 
    } 

    xmlChar* pXmlAppID = NULL; 
    pXmlAppID = xmlNodeGetContent(pChildElement); 
    if (pXmlAppID == NULL) 
    { 
        Log("Get xml appid value failed");
        xmlFreeDoc(doc); 
        return false; 
    } 

    char szAppID[64] = {0}; 
    char* pXmlAppIDInfo = (char*)pXmlAppID ; 
    int nAppIDLen = strlen(pXmlAppIDInfo); 
    if (nAppIDLen >= 64) 
        memcpy(szAppID, pXmlAppIDInfo, 63); 
    else 
        memcpy(szAppID, pXmlAppIDInfo, nAppIDLen); 
    xmlFree(pXmlAppID); 

    xmlNodePtr pPasswordElement = xmlRoot->children->next; 
    if (pPasswordElement == NULL) 
    { 
        Log("Get xml password element failed");
        xmlFreeDoc(doc); 
        return false; 
    } 
    if(xmlStrcmp(pPasswordElement->name, (const xmlChar*)"pass") != 0) 
    { 
        Log("Get xml pass element failed");
        xmlFreeDoc(doc); 
        return false; 
    } 

    xmlChar* pXmlPassword = NULL; 
    pXmlPassword = xmlNodeGetContent(pPasswordElement); 
    if (pXmlPassword == NULL) 
    { 
        Log("Get xml password value failed");
        xmlFreeDoc(doc); 
        return false; 
    } 

    char szPassword[64] = {0}; 
    char* pXmlPasswordInfo = (char*)pXmlPassword ; 
    int nPswLen = strlen(pXmlPasswordInfo); 
    if (nPswLen >= 64) 
        memcpy(szPassword, pXmlPasswordInfo, 63); 
    else 
        memcpy(szPassword, pXmlPasswordInfo, nPswLen); 

    xmlFree(pXmlPassword); 
    xmlFreeDoc(doc); 

    memcpy(appID, szAppID, strlen(szAppID)); 
    memcpy(pswOut, szPassword, strlen(szPassword)); 
    valueID = NULL;
    return true;
}

bool ParseRecvInfo(char *appID, char *valueID, char *pswReturn,char *pswIn, int type, char *seqNumber, long lAppID)
{
    int* pIdentifer = (int*)pswIn;
    long lIdentifer = *pIdentifer;
    lIdentifer = ntohl(lIdentifer);

    if (lIdentifer != 0x2000 && lIdentifer != 0x1100 && lIdentifer != 0x1110)
    {
        Log("recv data head identifer is wrong!");
        return false;
    }

    int nIdentiferType = 0;
    if (lIdentifer == 0x1000)
    nIdentiferType = 0;
    else if (lIdentifer == 0x1100)
    nIdentiferType = 1;
    else
    nIdentiferType = 2;

    int* pPacketLen = (int*)(pswIn + 4);
    int nPacketLen = ntohl(*pPacketLen);
    if (nPacketLen < 8)
    {
        Log("recv data len is wrong!");
        return false;
    }

    char szEnCodeData[4096] = { 0 };
    char pszDecodeData[8192] = {0};
    int nPacketDataLen = nPacketLen - 8;
    if (nPacketDataLen > 4096)
    {
        Log("recv data is too big!");
        return false;
    }

    //if (lIdentifer == 0x1000)
    if (lIdentifer == 0x2000)
    {   
        memcpy(szEnCodeData, pswIn + 8, nPacketDataLen);
        memcpy(pszDecodeData, szEnCodeData, nPacketDataLen);
        //*pDecodeDataLen = nPacketDataLen;
        ParseDownstreamInfo(appID, valueID, pszDecodeData, strlen(pszDecodeData));
    }
    else if (lIdentifer == 0x1100)
    {
        nPacketDataLen = nPacketLen - 40;//header + nLen = 8, encode key = 16, random = 16

        unsigned char uszTailData[32] = { 0 };
        memcpy(uszTailData, pswIn + nPacketDataLen + 8, 32);
        unsigned char uszKey[16] = { 0 }, uszSingle[8] = { 0 }, uszDouble[8] = { 0 };
        int nIndex = 0;
        for ( nIndex = 0; nIndex < 8; nIndex++)
        {
            uszSingle[nIndex] = uszTailData[nIndex];
        }

        int i = 0;
        for (i = 0; i < 8; i++)
        {
            uszDouble[i] = uszTailData[i + 16];
        }

        int nKeyIndex = 0, k = 0;
        for (k = 0; k < 8; k++)
        {
            uszKey[nKeyIndex++] = uszSingle[k];
            uszKey[nKeyIndex++] = uszDouble[k];
        }

        int nDecodeLen = 0;
        unsigned char szDeCodeBuffer[5120] = { 0 };
        AES_DecryptDataEVP((unsigned char*)(pswIn + 8), nPacketDataLen, uszKey, szDeCodeBuffer, &nDecodeLen);
        if (nDecodeLen == 0)
        {
            return false;
        }
        memcpy(szEnCodeData, szDeCodeBuffer, nDecodeLen);  
        memcpy(pszDecodeData, szEnCodeData, nDecodeLen);
        //*pDecodeDataLen = nDecodeLen;

        bool bRet = false;
        if (type == 0) 
            //bRet = ParseUpstreamXmlInfo(appID, valueID, pszDecodeData, nDecodeLen, pswReturn, seqNumber);
            bRet = ParseUpstreamXmlInfo(appID, valueID, pszDecodeData, nDecodeLen, pswReturn, lAppID);
        else if (type == 1)
            bRet = ParseLoginReqXmlData(seqNumber, pszDecodeData, nDecodeLen);
        else 
            bRet = ParseReActiveUpdateXmlInfo(appID, valueID,pszDecodeData, nDecodeLen, pswReturn);

        return bRet;
    }
    else if (lIdentifer == 0x1110)
    {
        char szSingleData[5120] = { 0 }, szDoubleData[5120] = { 0 };
        int nRemaider = nPacketDataLen % 2;
        int nSingleLen = 0, nDoubleLen = 0;
        if (nRemaider > 0)
            nSingleLen = (nPacketDataLen - 1) / 2 + 1;
        else
            nSingleLen = nPacketDataLen / 2;
        nDoubleLen = nPacketDataLen - nSingleLen;

        memcpy(szSingleData, pswIn + 8, nSingleLen);
        memcpy(szDoubleData, pswIn + 8 + nSingleLen, nDoubleLen);

        int nEncodeLenIndex = 0, nIndex = 0;
        for (nIndex = 0; nIndex < nDoubleLen; nIndex++)
        {
            szEnCodeData[nEncodeLenIndex++] = szSingleData[nIndex];
            szEnCodeData[nEncodeLenIndex++] = szDoubleData[nIndex];
        }

        if (nRemaider > 0)
        {
            szEnCodeData[nEncodeLenIndex++] = szSingleData[nSingleLen - 1];
        }

        memcpy(pszDecodeData, szEnCodeData, nPacketDataLen);
        //*pDecodeDataLen = nPacketDataLen;
    }
    return true;
}

bool ActiveUpgradeLocalPswCache(char *buf, void *arg, agent_threadpool_t *pool)
{
    char appID[80] = {0}, valueID[128] = {0}, pswSendData[256] = {0};
	agent_task_t *ptask = (agent_task_t *)arg;
    bool bRet = ParseRecvInfo(appID, valueID, pswSendData, buf, 0, NULL, 0);
    //bool bRet = ParseRecvInfo(appID, valueID, pswSendData, buf, 0, ptask->SeqNumber);
    if (bRet) {
        memset(appID, '\0', 80);
        sprintf(appID, "%ld", ptask->lAppID);
        ReplaceLocalPswCache(appID, ptask->szVaultID, pswSendData, pool);
    }
    return true;
}

void ReActiveUpdateLocalCache(char *buf, agent_threadpool_t* pool)
{
    char appID[80] = {0}, valueID[128] = {0}, pswSendData[256] = {0};
    bool bRet = ParseRecvInfo(appID, valueID, pswSendData, buf, 2, NULL, 0);
    if (bRet) {
        ReplaceLocalPswCache(appID, valueID, pswSendData, pool);
    }
}

void SendDataToDownstream(char *pswSendData, agent_task_t *ptask)
{
    /*
    if (ptask->DownStreamPfd == NULL) {
        printf("%s %d\n", __func__, __LINE__);
        return ;
    }
    ptask->DownStreamPfd->events |= ~POLLIN; 
    ptask->DownStreamPfd->events |= POLLOUT; 
    memset(m_DownStream_Buffer, '\0', 128);
    memcpy(m_DownStream_Buffer, pswSendData, strlen(pswSendData));
    */

    //memcpy(m_DownStream_Buffer, pswSendData, strlen(pswSendData));
    int nSendLen = strlen(pswSendData);
    while (nSendLen > 0)
    {
        int nRealSend = send(ptask->sockfd, pswSendData, nSendLen, 0);
        if (nRealSend == -1)
        {
            if (ptask->sockfd != -1)
            {
                close(ptask->sockfd);
                ptask->sockfd = -1;
            }
            Log("send req data info failed!");
            return ;
        }
        nSendLen -= nRealSend;
    }
    return ;
}

void ProcessNewPswFromUpstream(char *buf, agent_threadpool_t *pool, agent_task_t *ptask)
{
    char appID[80] = {0}, valueID[128] = {0}, pswSendData[256] = {0};
    POOL = pool;
    bool bRet = ParseRecvInfo(appID, valueID, pswSendData, buf, 0, NULL, 0);
    //bool bRet = ParseRecvInfo(appID, valueID, pswSendData, buf, 0, ptask->SeqNumber);
    if (bRet) {
        SendDataToDownstream(pswSendData, ptask);
        memset(appID, '\0', 80);
        sprintf(appID, "%ld", ptask->lAppID);
        ReplaceLocalPswCache(appID, valueID, pswSendData, pool);
    } else {
        memset(appID, '\0', 80);
        sprintf(appID, "%ld", ptask->lAppID);
        memset(pswSendData, '\0', 256);
        bRet =GetPvaFromLocal(pool, appID, valueID, pswSendData);
        if (bRet)
            SendDataToDownstream(pswSendData, ptask);
        else
            SendDataToDownstream("password server error: 501", ptask);
    }
}

bool ReadPvaPoll(struct pollfd *pfd, int *needrelogin, agent_threadpool_t *pool, void *arg, int sendready)
{
	agent_task_t *ptask = (agent_task_t *)arg;
    int selectfd = pfd->fd;
    struct timeval tmWait;
    fd_set rset;
    char m_upstream_buffer[4096] = {0};
    int ret = poll(pfd, 1, 6000);
    if (ret < 0) {
        Log("poll failure");
    } else if (ret == 0){
        if(sendready == 1) {
            *needrelogin = 1;
            ChangeVariableNetworkState(pool, pthread_self(), false);
            close(selectfd);
            return false;
        }
        goto SELECTLISTEN_NETWORK_STATE;
    }
    int i;
    for (i = 0; i < ret; ++i)
    {
        int sockfd = pfd->fd;
        if (pfd->revents & POLLERR) {
            printf("get an error from %d\n", pfd->fd);
            char errors[100];
            memset(errors, '\0', 100);
            socklen_t length = sizeof(errors);
            if (getsockopt(pfd->fd, SOL_SOCKET, SO_ERROR, &errors, &length) < 0) {
                Log("get socket option failed");
            }
            *needrelogin = 1;
            ChangeVariableNetworkState(pool, pthread_self(), false);
            continue;
        }
        else if (pfd->revents & POLLPRI) {
            printf("%s %d\n", __func__, __LINE__);
        }
        else if (pfd->revents & POLLSYNC) {
            printf("%s %d\n", __func__, __LINE__);
        }
        else if (pfd->revents & POLLMSG) {
            printf("%s %d\n", __func__, __LINE__);
        }
        else if (pfd->revents & POLLHUP) {
            printf("%s %d\n", __func__, __LINE__);
            *needrelogin = 1;
            ChangeVariableNetworkState(pool, pthread_self(), false);
            close(sockfd);
            break;
        }
        else if (pfd->revents & POLLIN) {
            //bool m_read_upstream_flag = false;
            int m_read_upstream_idx = 0;
            //memset(ptask->UpStreamBuffer, '\0', 1024);
            while (1) {
                int ret = recv( sockfd, m_upstream_buffer + m_read_upstream_idx, 4096, 0 );
                if (ret < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        //m_read_upstream_flag = true;
                        break;
                    } else {
                        Log("worker thread %ld recv() error, errno :%d", errno);
                        ChangeVariableNetworkState(pool, pthread_self(), false);
                        *needrelogin = 1;
                        close(sockfd);
                        break;
                    }
                } else if (ret == 0) {
                    ChangeVariableNetworkState(pool, pthread_self(), false);
                    *needrelogin = 1;
                    close(sockfd);
                    break;
                } else if (ret > 0) {
                    m_read_upstream_idx += ret;
                    //m_read_upstream_len = m_read_upstream_idx;
                    if (ptask == NULL) {
                        ReActiveUpdateLocalCache(m_upstream_buffer, pool);
                    }
                    else {
                        if (ptask->bIsActiveUpdate) {
                            ActiveUpgradeLocalPswCache(m_upstream_buffer, (void*)ptask, pool);
                        }
                        else {
                            ProcessNewPswFromUpstream(m_upstream_buffer, pool, (void*)ptask);
                        }
                    }
                    free(ptask);
                    ptask = NULL;
                    break;
                }
            }
            /*
            if (m_read_upstream_flag) {
                m_read_upstream_flag = false;
                if (ptask == NULL) {
                    ReActiveUpdateLocalCache(m_upstream_buffer, pool);
                }
                else {
                    if (ptask->bIsActiveUpdate)
                        ActiveUpgradeLocalPswCache(m_upstream_buffer, (void*)ptask, pool);
                    else {
                        ProcessNewPswFromUpstream(m_upstream_buffer, pool, (void*)ptask);
                    }
                }
            }
            */
        }
        else if (pfd->revents & POLLOUT) {
            printf("%s %d\n", __func__, __LINE__);

        }
    }
    memset(m_upstream_buffer, 0, 4096);
    return true;

SELECTLISTEN_NETWORK_STATE:
    //struct timeval tmWait;
    tmWait.tv_sec = 1;
    tmWait.tv_usec = 0;
    //fd_set rset;
    FD_ZERO(&rset);
    FD_SET(selectfd, &rset);
    int nRetCode = select(selectfd + 1, &rset, NULL, NULL, &tmWait);
    if (nRetCode > 0)
    {  
        printf("%s %d\n", __func__, __LINE__);
        if (FD_ISSET(selectfd, &rset) > 0)
        {
            //char szBuffer[8912] = {0};
            int nRecvLen = recv(selectfd, m_upstream_buffer, 4096, 0);
            if (nRecvLen <= 0)        
            {
                printf("%s %d\n", __func__, __LINE__);
                ChangeVariableNetworkState(pool, pthread_self(), false);
                *needrelogin = 1;

                if (selectfd != -1)        
                {
                    close(selectfd);           
                    //nSocket = -1;             
                }
            }
        }
    }
    else if (nRetCode < 0)
    {
        printf("%s %d\n", __func__, __LINE__);
        ChangeVariableNetworkState(pool, pthread_self(), false);
        *needrelogin = 1;

        if (selectfd != -1)
        {
            close(selectfd);
            //nSocket = -1;
        }
    }
    memset(m_upstream_buffer, 0, 4096);
    return true;
}

void *z_threadpool_cycle(void* argv)
{
    pthread_t pid = pthread_self();
    int err = pthread_detach( pid );
	unsigned int exit_flag = 0;
	sigset_t set;
	agent_task_t *ptask = NULL;
	agent_threadpool_t *pool = (agent_threadpool_t*)argv;

    //ChangeThreadFdCount();
    pthread_mutex_lock(&pool->ThreadFdCountMutex);
    pool->pfds[pool->ThreadFdCount].fd = pid;
    pool->pfds[pool->ThreadFdCount].isOnline = -1;
    pool->ThreadFdCount++;
    pthread_mutex_unlock(&pool->ThreadFdCountMutex);

	sigfillset(&set);
	sigdelset(&set, SIGILL);
	sigdelset(&set, SIGFPE);
	sigdelset(&set, SIGSEGV);
	sigdelset(&set, SIGBUS);
	
RETRY:
	if (pthread_setspecific(key,(void*)&exit_flag) != 0) {
        goto RETRY;
		//return NULL;
	}

	if (pthread_sigmask(SIG_BLOCK, &set, NULL) != 0) {
        goto RETRY;
		//return NULL;
	}

    int sockfd;
    bool ret = false;

RELOGIN:
    ret = LoginPvaServer(&sockfd);
    if (!ret) {
        ChangeVariableNetworkState(pool, pthread_self(), false);
        goto RELOGIN;
    }
    ChangeVariableNetworkState(pool, pthread_self(), true);
    NotifyUpdateCache(pool);

    struct pollfd pfd;
    pfd.fd = sockfd;
    pfd.events = POLLIN | POLLERR | POLLHUP | POLLSYNC | POLLMSG | POLLPRI;
    pfd.revents = 0;

    int SendReady;
    bool bRet;
    int m_NeedRetryConnect = 0;
	while(!exit_flag){        
        if (m_NeedRetryConnect) {
            bool err = LoginPvaServer(&sockfd);
            if (!err) {
                //Log("");
                continue;
            }
            ChangeVariableNetworkState(pool, pthread_self(), true);
            //addfd(pfd, sockfd);
            pfd.fd = sockfd;
            pfd.events = POLLIN | POLLERR | POLLHUP;
            pfd.revents = 0;
            m_NeedRetryConnect = 0;
        }

        SendReady = -1;
        if (sem_trywait(&pool->TasksQueueSem) != 0) {
            ptask = NULL;
            goto NOREQUEST;
        }

        pthread_mutex_lock(&pool->mutex);
        if (pool->tasks.head == NULL) {
            pthread_mutex_unlock(&pool->mutex);
            ptask = NULL;
            goto NOREQUEST;
        }

        /*
        struct timespec ts;
        struct timeval  tp;
        gettimeofday(&tp, NULL);
        ts.tv_sec = tp.tv_sec + 3;
        ts.tv_nsec = tp.tv_usec * 1000;

        if (pthread_mutex_trylock(&pool->mutex) != 0) {
            printf("%u %s %d\n", pthread_self(), __func__, __LINE__);
            //goto NOREQUEST;
        }

        if (pthread_cond_timedwait(&pool->cond, &pool->mutex,&ts) != 0) {
            printf("%u %s %d\n", pthread_self(), __func__, __LINE__);
            pthread_mutex_unlock(&pool->mutex);
            goto NOREQUEST;
        }

        if (pool->tasks.head == NULL) {
            pthread_mutex_unlock(&pool->mutex);
            goto NOREQUEST;
        }
        */
        /*
		if (pthread_mutex_lock(&pool->mutex) != 0){  
			return NULL;
		}

		while(pool->tasks.head == NULL){
			if (pthread_cond_wait(&pool->cond, &pool->mutex) != 0){
				pthread_mutex_unlock(&pool->mutex);
				return NULL;
			}
		}
        */

        printf("%u :get task\n", pthread_self());
		
		ptask = pool->tasks.head;     
		pool->tasks.head = ptask->next;
		pool->tasks.curtasknum--;   

		if (pool->tasks.head == NULL){
			pool->tasks.tail = &pool->tasks.head;
		}

		if (pthread_mutex_unlock(&pool->mutex) != 0) {
            free(ptask);
            ptask = NULL;
            continue;
			//return NULL;
		}
        if (ptask->handler != NULL) {
            ptask->handler(ptask->argv);  
            free(ptask);
            ptask = NULL;
            continue;
        }
        ptask->UpstreamSockfd = sockfd;
        if (ptask->ProcessRequest != NULL) {
            bRet = ptask->ProcessRequest(ptask, pool); 
            if (!bRet) {
                m_NeedRetryConnect = 1;
                ChangeVariableNetworkState(pool, pthread_self(), false);
                continue;
            }
            /*
            if (ptask->GetFormFlag == 1) {
                free(ptask);
                ptask = NULL;
                printf("%s %d\n", __func__, __LINE__);
                //continue;
            }
            */
        }
        SendReady = 1;

NOREQUEST:
        ret = ReadPvaPoll(&pfd, &m_NeedRetryConnect, pool, ptask, SendReady);
        if (!ret) {
            char pswOut[128] = {0}, appID[80] = {0};
            sprintf(appID, "%ld", ptask->lAppID);
            ret = GetPvaFromLocal(pool, appID, ptask->szVaultID, pswOut);
            if (ret)
                SendDataToDownstream(pswOut, ptask);
            else
                SendDataToDownstream("Internal server error: 501", ptask);
            free(ptask);
            ptask = NULL;
        }
	}
	pthread_exit(0);
}

void *z_threadpool_exit_cb(void* argv)
{
	unsigned int *lock = argv;
	unsigned int *pexit_flag = NULL;
	pexit_flag = (unsigned int *)pthread_getspecific(key);
	*pexit_flag = 1;   
	pthread_setspecific(key, (void*)pexit_flag);
	*lock = 0;
    return pexit_flag;
}

inline int z_thread_key_create()
{
	return pthread_key_create(&key, NULL);
}

inline void z_thread_key_destroy()
{
	pthread_key_delete(key);
}

