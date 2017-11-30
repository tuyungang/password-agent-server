#ifndef _INI_CONFIG_H
#define _INI_CONFIG_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "thread_pool.h"

/*
typedef struct
{
    char LoginName[10];
    char LoginPassword[128];
    char MasterIP[32];
    char StandbyIP[32];
    char SystemName[10];
    char SafeBoxID[128];
}sAgentConfigInfo, *psAgentConfigInfo;
*/


bool InitIniConfig();
void trim(char *str);
void GetIniKeyString(const char *section, const char *key, char *vaule);
void GetIniKeyInt(const char *section, const char *key, int vaule);
void GetIniKeyLong(const char *section, const char *key, long vaule);

#endif
