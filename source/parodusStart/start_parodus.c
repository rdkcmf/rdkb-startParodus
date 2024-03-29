/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2019 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/
/**
 * @file start_parodus.c
 *
 * @description This is a C application to start parodus process.
 *
 */
 
#include <stdio.h>
#include <string.h>
#include <sys/sysinfo.h>
#include <time.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <ccsp/platform_hal.h>
#include <ccsp/cm_hal.h>
#include <sysevent/sysevent.h>
#include <sys/wait.h>
#include <syscfg/syscfg.h>
#include <limits.h>
#if !(_COSA_BCM_MIPS_ || _COSA_DRG_TPG_ || CONFIG_CISCO)
#include <autoconf.h>
#endif
#include "cJSON.h"
#include "safec_lib_common.h"

#if defined(_PLATFORM_RASPBERRYPI_) || defined(_PLATFORM_TURRIS_)
#include "ccsp_vendor.h"
#endif

#if defined(_COSA_BCM_MIPS_)
#include <ccsp/dpoe_hal.h>
#endif

#define PARODUS_UPSTREAM              "tcp://127.0.0.1:6666"
#define DEVICE_PROPS_FILE             "/etc/device.properties"
#define MODULE 			      "PARODUS"
#define MAX_BUF_SIZE 		      1024
#define MAX_VALUE_SIZE 		      64
#define MAX_SERVER_URL_SIZE           64
#define LOG_ERROR                     0
#define LOG_INFO                      1
#define LogInfo(...)                  _START_LOG(LOG_INFO, __VA_ARGS__)
#define LogError(...)                 _START_LOG(LOG_ERROR, __VA_ARGS__)
#define WEBPA_CFG_FILE		      "/nvram/webpa_cfg.json"
#define WEBPA_CFG_FIRMWARE_VER	      "oldFirmwareVersion"
#define WEBPA_CFG_MAX_PING_WAIT       "MaxPingWaitTimeInSec"
#define SSL_CERT_BUNDLE               "/etc/ssl/certs/ca-certificates.crt"
#define WEBPA_CFG_SERVER_URL          "ServerIP"
#define WEBPA_CFG_SERVER_PORT         "ServerPort"
#define PSM_COMPONENT_NAME	      "com.cisco.spvtg.ccsp.psm"
#define JWT_KEY                       "/etc/ssl/certs/webpa-rs256.pem"
#define ACQUIRE_JWT		      1
#define WEBPA_CFG_ACQUIRE_JWT	      "acquire-jwt"
#define MAX_PROCESS_LEN				  16
#define MAX_BUILD_LEN                 16
#define CRUD_CONFIG_FILE             "/nvram/parodus_cfg.json"
#define CURL_FILE_RESPONSE 	     "/tmp/adzvfchig-res.mch"
#define PARCONNHEALTH_FILE	     "/tmp/parconnhealth.txt"
#define GETCONF_FILE 		     "/usr/bin/GetConfigFile"
#define MAX_PARTNERID_LEN              64

#ifdef CONFIG_CISCO
#define CONFIG_VENDOR_NAME  "Cisco"
#endif

#if (_COSA_BCM_MIPS_ || _COSA_DRG_TPG_)
#define CONFIG_VENDOR_NAME "ARRIS Group, Inc."
#endif

#ifdef INCLUDE_BREAKPAD
#include "breakpad_wrapper.h"
#endif
/*----------------------------------------------------------------------------*/
/*                             Function Prototypes                            */
/*----------------------------------------------------------------------------*/
static void get_url(char *parodus_url, char *seshat_url, char *build_type);
static void getPartnerId(char *partner_id);
static int addParodusCmdToFile(char *command);
static void _START_LOG(int level, const char *msg, ...);
static void getValueFromCfgJson( char *key, char **value, cJSON **out);
static int  writeToJson(char *data);
static void getValuesFromPsmDb(char *names[], char **values,int count);
static void getWebpaValuesFromPsmDb(char *names[], char **values,int count);
static void getValuesFromSysCfgDb(char *names[], char **values,int count);
static int setValuesToPsmDb(char *names[], char **values,int count);
static void waitForPSMHealth(char *compName);
static int syncXpcParamsOnUpgrade(char *lastRebootReason, char *firmwareVersion);
static void free_sync_db_items(int paramCount,char *psmValues[],char *sysCfgValues[]);
static void get_parodusStart_logFile(char *parodusStart_Log);
static void checkAndUpdateServerUrlFromDevCfg(char **serverUrl);
#if !defined(_COSA_BCM_MIPS_)
int s_sysevent_connect (token_t *out_se_token);
#endif
static char *pathPrefix  = "eRT.com.cisco.spvtg.ccsp.webpa.";
static char *WEBPA_SERVER_URL = "";
static char *TOKEN_SERVER_URL = "";
static char *DNS_TEXT_URL = "";
static int executeConfigFile();
FILE* g_fArmConsoleLog = NULL;
/*----------------------------------------------------------------------------*/
/*                             External Functions                             */
/*----------------------------------------------------------------------------*/

int main(int argc, char *argv[])
{
	#ifdef INCLUDE_BREAKPAD
	breakpad_ExceptionHandler();
	#endif
	char parodusStart_Log[MAX_BUF_SIZE] = {'\0'};
	char output[MAX_PROCESS_LEN] = {'\0'};
	FILE *cmd = NULL;
	const char *pid_cmd = "pidof parodus";
        errno_t rc = -1;
        int ind = -1;
		int Wan_Status_Started = 0;
	
        get_parodusStart_logFile(parodusStart_Log);

	g_fArmConsoleLog = freopen(parodusStart_Log, "a+", stderr);
	if (NULL == g_fArmConsoleLog) 
	{
		LogError("Error while opening Log file:%s\n", parodusStart_Log);
	}
	else
	{
		LogInfo("Successful in opening parodusStart_Log file:%s\n", parodusStart_Log);
	}
	
        if((argc > 1) && (NULL != argv[1]))
        {
                rc = strcmp_s("wan-status",strlen("wan-status"),argv[1],&ind);
                ERR_CHK(rc);
                if((!ind) && (rc == EOK))
		{
		    if(NULL != argv[2]) 
		    {
		        LogInfo("wan-status event received with state %s\n", argv[2]);
			rc = strcmp_s("started",strlen("started"),argv[2],&ind);
                        ERR_CHK(rc);
                        if((!ind) && (rc == EOK))
                        {
				Wan_Status_Started = 1;
			}
		     }
		     if (Wan_Status_Started)
		     {
                        
			LogInfo("wan-status is ready. Proceed with parodus start up\n");	
			if ((cmd = popen(pid_cmd, "r")) == NULL)
			{
				LogError("Error in getting parodus pid \n");
				return 0;
			}

			if(fgets(output,MAX_PROCESS_LEN,cmd) == NULL)
                               LogError("fgets() error\n");
			pid_t pid = strtoul(output,NULL,10);// base 10 (decimal)
			LogInfo("Check parodus pid %d\n",pid);
			pclose(cmd);
			if(pid)
			{
				LogError("wan-status is ready, but Pardous process is already started/running \n");
				return 0;
			}

		      }
		      else
		      {
			  LogInfo("wan-status is not ready , waiting to start parodus..\n");
			  if (NULL != g_fArmConsoleLog)
			  fclose(g_fArmConsoleLog);
			  return 0;
		      }
                 }
	}
	
	/*Coverity Fix CID:78992,78513  */
	char modelName[256]={'\0'};
	char serialNumber[256]={'\0'};
	char firmwareVersion[64]={'\0'};
	char lastRebootReason[128]={'\0'};
	char deviceMac[64]={'\0'};
	char webpaInterface[64]={"erouter0"};
	char manufacturer[64]={'\0'};
#if defined(_COSA_BCM_MIPS_)
	dpoe_mac_address_t tDpoe_Mac;
#else
	CMMGMT_CM_DHCP_INFO dhcpinfo;
#endif
	char parodus_url[MAX_SERVER_URL_SIZE] = {'\0'};
        char seshat_url[MAX_SERVER_URL_SIZE] = {'\0'};
	char build_type[MAX_BUILD_LEN] = {'\0'};
	char partner_id[MAX_PARTNERID_LEN] = {'\0'};
	char tempStr[64] = {'\0'};
	char *webpaUrl = NULL;
	cJSON *out = NULL;
        char command[1024]={'\0'};
        unsigned int bootTime=0;
        struct sysinfo s_info;
        struct timeval currentTime;
       	int cmdUpdateStatus = -1;
        int upTime=0, syncStatus= -1;
	char *paramList[] = {"X_COMCAST-COM_CMC","X_COMCAST-COM_CID","X_COMCAST-COM_SyncProtocolVersion"};
        char *webpaParamList[] = {"Device.X_RDKCENTRAL-COM_Webpa.Server.URL","Device.X_RDKCENTRAL-COM_Webpa.TokenServer.URL","Device.X_RDKCENTRAL-COM_Webpa.DNSText.URL"};
	int paramCount = 0, i = 0, wait_time = 0;
	char *psmValues[MAX_VALUE_SIZE] = {'\0'};
	char *acquireJwt = NULL;
	int jwtFlag;
	char final_lastRebootReason[128] = {'\0'};
    	char rebootCounter[8] = {'\0'};
	char client_cert_path[128]={'\0'};
	int decodeStatus = -1;

#if defined (START_PARODUS) && defined (UPDATE_CONFIG_FILE)
	LogInfo("Proceeding to unregister wan-status event\n");

	system("/etc/utopia/registration.d/02_parodus stop");
#endif
        LogInfo("startParodus is enabled\n");
        if ( platform_hal_PandMDBInit() == 0)
        {
                LogInfo("PandMDB initiated successfully\n");
        }
        else
        {
                LogError("Failed to initiate DB\n");
        }
        
        if ( cm_hal_InitDB() == 0)
        {
                LogInfo("cm_hal DB initiated successfully\n");
        }
        else
        {
                LogError("Failed to initiate cm_hal DB\n");
        }

	if ( platform_hal_GetModelName(modelName) == 0)
	{
		LogInfo("modelName returned from hal:%s\n", modelName);
	}
        else 
        {
        	LogError("Unable to get ModelName\n");
        	
    	}

	if ( platform_hal_GetSerialNumber(serialNumber) == 0)
	{
		LogInfo("serialNumber returned from hal:%s\n", serialNumber);
	}
        else 
        {
        	LogError("Unable to get SerialNumber\n");
    	}
    	
    	if ( platform_hal_GetFirmwareName(firmwareVersion, 64) == 0)
	{
		LogInfo("firmwareVersion returned from hal:%s\n", firmwareVersion);
	}
        else 
        {
        	LogError("Unable to get FirmwareName\n");
    	}
    	

        rc = strcpy_s(manufacturer, sizeof(manufacturer), CONFIG_VENDOR_NAME);
        if(rc != EOK)
        {
            ERR_CHK(rc);
            LogError("Failed to get manufacturer name\n");
        }
        LogInfo("Manufacturer Name is %s\n", manufacturer);    	
    	
    	if (syscfg_init() != 0)
        {
        	LogError("syscfg init failure\n");
                rc = strcpy_s(final_lastRebootReason, sizeof(final_lastRebootReason), "unknown");
                if(rc != EOK)
                {
                    ERR_CHK(rc);
                    LogError("Failed to copy final_lastRebootReason\n");
                }
        }
        else
        {
		syscfg_get( NULL, "X_RDKCENTRAL-COM_LastRebootCounter", rebootCounter, sizeof(rebootCounter));

		/* /var/tmp/lastrebootreason file is created in PAM during bootup. When parodus starts early before PAM, /var/tmp/lastrebootreason file does not exists and if reboot counter is 0, reason is updated as unknown */

		if(access( "/var/tmp/lastrebootreason" , F_OK ) != 0 && ( strlen(rebootCounter)>0 && atoi(rebootCounter) ==0 ))
		{
			LogInfo("/var/tmp/lastrebootreason file doesn't exist and rebootCounter is %s\n", rebootCounter);
                        rc = strcpy_s(final_lastRebootReason, sizeof(final_lastRebootReason), "unknown");
                        if(rc != EOK)
                        {
                            ERR_CHK(rc);
                            LogError("Failed to copy final_lastRebootReason as unknown\n");
                        }
		}
		else
		{
			syscfg_get( NULL, "X_RDKCENTRAL-COM_LastRebootReason", lastRebootReason, sizeof(lastRebootReason));
			LogInfo("lastRebootReason is %s\n", lastRebootReason);

			// Strip all spaces and parentheses from reboot reason to make it one word
			// This also prevents command line parsing issues due to value like '-s'
			unsigned int i=0, j=0;
			for(i=0; i < sizeof(lastRebootReason) && j < sizeof(final_lastRebootReason); i++) {
				if(lastRebootReason[i] != ' ') {
					if(lastRebootReason[i] != '(')
					{
						if(lastRebootReason[i] != ')')
						{
							final_lastRebootReason[j]=lastRebootReason[i];
							j++;
						}
					}
				}
			}
		}
		LogInfo("Modified lastRebootReason is %s\n", final_lastRebootReason);
	}
#if defined(_COSA_BCM_MIPS_)
	if( dpoe_getOnuId(&tDpoe_Mac) == 0)
	{
                rc = sprintf_s(deviceMac, sizeof(deviceMac), "%02x:%02x:%02x:%02x:%02x:%02x",tDpoe_Mac.macAddress[0], tDpoe_Mac.macAddress[1],
                tDpoe_Mac.macAddress[2], tDpoe_Mac.macAddress[3], tDpoe_Mac.macAddress[4],tDpoe_Mac.macAddress[5]);
		if(rc < EOK)
                {
                   ERR_CHK(rc);
                   LogError("Failed to copy deviceMac\n");
                }
		LogInfo("deviceMac is %s\n", deviceMac);
	}
#else
        char isEthEnabled[64]={'\0'};
        token_t  token;
        int fd = s_sysevent_connect(&token);
       
        /*Coverity Fix:CID 63390 CHECKED_RETURN */
        if(fd < 0 )
        {  
            LogError("s_sysevent_connect() is returned Error\n");
            return -1;
        }  
       
  
          
        char deviceMACValue[32] = { '\0' };
		int Eth_Enabled = 0;
		
		if(0 == syscfg_get( NULL, "eth_wan_enabled", isEthEnabled, sizeof(isEthEnabled)))
		{
		if (isEthEnabled[0] != '\0')
		{
		   rc = strcmp_s("true",strlen("true"),isEthEnabled,&ind);
           ERR_CHK(rc);
           if((!ind) && (rc == EOK))
		   {
			  Eth_Enabled = 1;
		   }		   
		}
		}
		
        if( Eth_Enabled && sysevent_get(fd, token, "eth_wan_mac", deviceMACValue, sizeof(deviceMACValue)) == 0 && deviceMACValue[0] != '\0')
        {
            rc = strcpy_s(deviceMac, sizeof(deviceMac), deviceMACValue);
            if(rc != EOK)
            {
                ERR_CHK(rc);
                LogError("Failed to Copy deviceMACValue to deviceMac\n");
            }
            LogInfo("deviceMac is %s\n", deviceMac);
        }
        else if (cm_hal_GetDHCPInfo(&dhcpinfo) == 0)
        {
            LogInfo("MACAddress = %s\n", dhcpinfo.MACAddress);
            rc = strcpy_s(deviceMac, sizeof(deviceMac), dhcpinfo.MACAddress);
            if(rc != EOK)
            {
                ERR_CHK(rc);
                LogError("Failed to Copy dhcpinfo.MACAddress to deviceMac\n");
            }
            LogInfo("deviceMac is %s\n", deviceMac);
        }
#endif
         else
         {
         	LogError("Unable to get MACAdress\n");
         }
         
         
        while(!bootTime)
        {
            if(sysinfo(&s_info))
            {
                LogError("Failure in sysinfo fetch.\n");
            }
            else
            {
                upTime = s_info.uptime;
                gettimeofday(&currentTime, NULL);
                bootTime = currentTime.tv_sec - upTime;
            }

            if(bootTime > 0 && bootTime < UINT_MAX)
            {
                LogInfo("bootTime is %u\n", bootTime);
            }
            else
            {
                if(wait_time >= 60)
                {
                    LogError("boot_time is %u. Unable to get valid bootTime even after wait of 60s. Hence setting bootTime value to 0.\n",bootTime);
                    bootTime = 0;
                    break;
                }
                else
                {
                    LogError("boot_time %u is not valid, retry ofter 10s\n",bootTime);
                    bootTime = 0;
                    sleep(10);
                    wait_time = wait_time + 10;
                }
            }
        }

         LogInfo("Fetch parodus url from device.properties file\n");
         get_url(parodus_url, seshat_url, build_type);
	 LogInfo("parodus_url returned is %s\n", parodus_url);
         LogInfo("seshat_url returned is %s\n", seshat_url);
	 LogInfo("build_type returned is %s\n", build_type);

	if(strncmp(build_type, "dev", strlen(build_type)+1) == 0)
	{
		getValueFromCfgJson( WEBPA_CFG_SERVER_URL, &webpaUrl, &out);
		LogInfo("webpaUrl fetched from webpa_cfg.json is %s\n", webpaUrl);
        checkAndUpdateServerUrlFromDevCfg(&webpaUrl);
		LogInfo("Framed webpa url is %s\n",webpaUrl);
		if(out != NULL)
		{
			cJSON_Delete(out);
		}
	}

        getPartnerId(partner_id);
        LogInfo("PartnerID fetched is %s\n", partner_id);
        int partnerid_invalid = 0;
        if(partner_id[0] == '\0')
        {
             partnerid_invalid = 1;
        }
        else
        {
            rc = strcmp_s("unknown",strlen("unknown"),partner_id,&ind);
            ERR_CHK(rc);
            if((ind == 0) && (rc == EOK))
            {
                partnerid_invalid = 1;
            }
        }

        if(partnerid_invalid)
        {
           partner_id[0] = '\0';
        }
        else
        {
                rc = strcpy_s(tempStr, sizeof(tempStr), partner_id);
                if(rc != EOK)
                {
                    ERR_CHK(rc);
                    goto RETURN_ERROR;
                }
                rc = sprintf_s(partner_id,sizeof(partner_id),"*,%s",tempStr);
                if(rc < EOK)
                {
                    ERR_CHK(rc);
                    goto RETURN_ERROR;
                }
        }
	LogInfo("PartnerID framed is %s\n", partner_id);

	paramCount = sizeof(webpaParamList)/sizeof(webpaParamList[0]);
        getWebpaValuesFromPsmDb(webpaParamList, psmValues, paramCount);
        LogInfo("DB details are %s = %s %s = %s %s = %s\n",webpaParamList[0],psmValues[0],webpaParamList[1],psmValues[1],webpaParamList[2],psmValues[2]);
        for(i=0;i<paramCount;i++)
        {
                if(psmValues[i])
                {    
	             if(i==0) 
                     {		
			WEBPA_SERVER_URL = strdup(psmValues[i]);
		     } 
		     else if(i==1) 
                     {
			     TOKEN_SERVER_URL = strdup(psmValues[i]);
		     }
		     else if(i==2) 
                     {
			     DNS_TEXT_URL = strdup(psmValues[i]);
		     }	     
		}   
        }
	for(i=0;i<paramCount;i++)
	{
		if(psmValues[i])
		{
			free(psmValues[i]);
		}
	}
	LogInfo("WEBPA_SERVER_URL = %s\n", WEBPA_SERVER_URL);
	LogInfo("TOKEN_SERVER_URL = %s\n", TOKEN_SERVER_URL);
	LogInfo("DNS_TEXT_URL = %s\n", DNS_TEXT_URL);

	if(webpaUrl == NULL)
	{
		LogInfo("Setting webpaUrl to default server IP\n");
		webpaUrl = strdup(WEBPA_SERVER_URL);
	}


	getValueFromCfgJson( WEBPA_CFG_ACQUIRE_JWT, &acquireJwt, &out);
	if(out != NULL && acquireJwt != NULL)
	{
		jwtFlag = atoi(acquireJwt);
		cJSON_Delete(out);
		free(acquireJwt);
		acquireJwt = NULL;
	}
	else
	{
		LogInfo("Setting default value to acquire-jwt\n");
		jwtFlag = ACQUIRE_JWT;
	}
	LogInfo("acquire-jwt is %d\n",jwtFlag);

	decodeStatus = executeConfigFile();
	if(decodeStatus == 0)
	{
                rc = strcpy_s(client_cert_path, sizeof(client_cert_path), CURL_FILE_RESPONSE);
                if(rc != EOK)
                {
                    ERR_CHK(rc);
                    LogError("Failed to get client_cert_path\n");
                }
                else
                    LogInfo("client_cert_path is %s\n", client_cert_path);
	}
	else
	{
		LogError("Failed to get client_cert_path\n");
	}
#if defined(WAN_FAILOVER_SUPPORTED) || defined(FEATURE_RDKB_CONFIGURABLE_WAN_INTERFACE)
	char interfaceValue[64] = { '\0' };
	if (sysevent_get(fd, token, "current_wan_ifname", interfaceValue, sizeof(interfaceValue)) == 0)
	{
	    rc = strcpy_s(webpaInterface, sizeof(webpaInterface), interfaceValue);
            if(rc != EOK)
            {
                ERR_CHK(rc);
                LogError("Failed to Copy interfaceValue to webpaInterface\n");
            }
            LogInfo("webpaInterface is %s\n", webpaInterface);
	}
        else
        {
          LogError("Failed to get interface value\n");
        }
#endif
	LogInfo("Framing command for parodus\n");
	//Enabling parodus by forcing to ipv4
#if defined (ENABLE_SESHAT) && defined (FEATURE_DNS_QUERY)
        rc = sprintf_s(command, sizeof(command),
	"/usr/bin/parodus --hw-model=\"%s\" --hw-serial-number=%s --hw-manufacturer=\"%s\" --hw-last-reboot-reason=\"%s\" --fw-name=%s --boot-time=%u --hw-mac=%s --webpa-ping-time=180 --webpa-interface-used=%s --webpa-url=%s --webpa-backoff-max=8 --parodus-local-url=%s --partner-id=%s --ssl-cert-path=%s --connection-health-file=%s --seshat-url=%s --client-cert-path=%s --token-server-url=%s --acquire-jwt=%d --dns-txt-url=%s --jwt-public-key-file=%s --jwt-algo=RS256 --crud-config-file=%s --boot-time-retry-wait=%d &", 
        modelName, serialNumber, manufacturer, final_lastRebootReason, firmwareVersion, bootTime, deviceMac, webpaInterface, webpaUrl, ((NULL != parodus_url) ? parodus_url : PARODUS_UPSTREAM), partner_id, SSL_CERT_BUNDLE, PARCONNHEALTH_FILE, seshat_url, client_cert_path, TOKEN_SERVER_URL, jwtFlag, DNS_TEXT_URL, JWT_KEY, CRUD_CONFIG_FILE, wait_time);
       if(rc < EOK)
       {
          ERR_CHK(rc);
          goto RETURN_ERROR;
       }
#elif defined ENABLE_SESHAT
       rc = sprintf_s(command, sizeof(command),
	"/usr/bin/parodus --hw-model=\"%s\" --hw-serial-number=%s --hw-manufacturer=\"%s\" --hw-last-reboot-reason=\"%s\" --fw-name=%s --boot-time=%u --hw-mac=%s --webpa-ping-time=180 --webpa-interface-used=%s --webpa-url=%s --webpa-backoff-max=8 --parodus-local-url=%s --partner-id=%s --ssl-cert-path=%s --connection-health-file=%s --seshat-url=%s --client-cert-path=%s --token-server-url=%s --crud-config-file=%s --boot-time-retry-wait=%d &", 
        modelName, serialNumber, manufacturer, final_lastRebootReason, firmwareVersion, bootTime, deviceMac, webpaInterface, webpaUrl, ((NULL != parodus_url) ? parodus_url : PARODUS_UPSTREAM), partner_id, SSL_CERT_BUNDLE, PARCONNHEALTH_FILE, seshat_url, client_cert_path, TOKEN_SERVER_URL, CRUD_CONFIG_FILE, wait_time);
     if(rc < EOK)
     {
        ERR_CHK(rc);
        goto RETURN_ERROR;
     }
#elif defined FEATURE_DNS_QUERY
     rc = sprintf_s(command, sizeof(command),
	"/usr/bin/parodus --hw-model=\"%s\" --hw-serial-number=%s --hw-manufacturer=\"%s\" --hw-last-reboot-reason=\"%s\" --fw-name=%s --boot-time=%u --hw-mac=%s --webpa-ping-time=180 --webpa-interface-used=%s --webpa-url=%s --webpa-backoff-max=8 --parodus-local-url=%s --partner-id=%s --ssl-cert-path=%s --connection-health-file=%s --client-cert-path=%s --token-server-url=%s --acquire-jwt=%d --dns-txt-url=%s --jwt-public-key-file=%s --jwt-algo=RS256 --crud-config-file=%s --boot-time-retry-wait=%d &", 
        modelName, serialNumber, manufacturer, final_lastRebootReason, firmwareVersion, bootTime, deviceMac, webpaInterface, webpaUrl, ((NULL != parodus_url) ? parodus_url : PARODUS_UPSTREAM), partner_id, SSL_CERT_BUNDLE, PARCONNHEALTH_FILE, client_cert_path, TOKEN_SERVER_URL, jwtFlag, DNS_TEXT_URL, JWT_KEY, CRUD_CONFIG_FILE, wait_time);
    if(rc < EOK)
    {
        ERR_CHK(rc);
        goto RETURN_ERROR;
    }
#else
    rc = sprintf_s(command, sizeof(command),
	"/usr/bin/parodus --hw-model=\"%s\" --hw-serial-number=%s --hw-manufacturer=\"%s\" --hw-last-reboot-reason=\"%s\" --fw-name=%s --boot-time=%u --hw-mac=%s --webpa-ping-time=180 --webpa-interface-used=%s --webpa-url=%s --webpa-backoff-max=8 --parodus-local-url=%s --partner-id=%s --ssl-cert-path=%s --connection-health-file=%s --client-cert-path=%s --token-server-url=%s --crud-config-file=%s --boot-time-retry-wait=%d &", 
        modelName, serialNumber, manufacturer, final_lastRebootReason, firmwareVersion, bootTime, deviceMac, webpaInterface, webpaUrl, ((NULL != parodus_url) ? parodus_url : PARODUS_UPSTREAM), partner_id, SSL_CERT_BUNDLE, PARCONNHEALTH_FILE, client_cert_path, TOKEN_SERVER_URL, CRUD_CONFIG_FILE, wait_time);
    if(rc < EOK)
    {
       ERR_CHK(rc);
       goto RETURN_ERROR;
    }
#endif   
 
#ifdef ENABLE_WEBCFGBIN
       #define MAX_QUEUE_SIZE 10
       char max_queue_size[24] = {'\0'};
       snprintf(max_queue_size,sizeof(max_queue_size),"--max-queue-size=%d &", MAX_QUEUE_SIZE);
       //To remove the '&' from command
       command[strlen(command)-1] = '\0';
       strcat(command,max_queue_size);
#endif

	LogInfo("parodus command formed is: %s\n", command);
	
	cmdUpdateStatus = addParodusCmdToFile(command);
	if(cmdUpdateStatus == 0)
	{
		LogInfo("Added parodus cmd to file\n");
	}
	else
	{
		LogError("Error in adding parodus cmd to file\n");
	}

	if(webpaUrl != NULL)
	{
		free(webpaUrl);
		webpaUrl = NULL;
	}
	/* Wait till PSM health is green before PSM DB sync */
       waitForPSMHealth(PSM_COMPONENT_NAME);
		
	syncStatus = syncXpcParamsOnUpgrade(lastRebootReason, firmwareVersion);
	if(syncStatus == 0)
	{
		LogInfo("DB synced successfully on firmware upgrade\n");
	}
	else if(syncStatus == -2)
	{
		LogInfo("PARODUS: Failed to sync DB during Firmware Upgrade\n");
	}
	else
	{
		LogInfo("DB sync is not required or failed to sync!!\n");
	}
	paramCount = sizeof(paramList)/sizeof(paramList[0]);
        getValuesFromPsmDb(paramList, psmValues, paramCount);
	LogInfo("DB details are %s = %s %s = %s %s = %s\n",paramList[0],psmValues[0],paramList[1],psmValues[1],paramList[2],psmValues[2]);
	for(i=0;i<paramCount;i++)
	{
		if(psmValues[i])
		{
			free(psmValues[i]);
		}
	}

#ifdef START_PARODUS
	LogInfo("Starting parodus process ..\n");
	system(command);
#endif
	
    	if (NULL != g_fArmConsoleLog)
		fclose(g_fArmConsoleLog);
	return 0;
	
RETURN_ERROR:
       if(webpaUrl != NULL)
       {
          free(webpaUrl);
          webpaUrl = NULL;
       }
       LogError("main function - RETURN_ERROR\n");
       return -1;
	
}

/*----------------------------------------------------------------------------*/
/*                             Internal functions                             */
/*----------------------------------------------------------------------------*/

static void get_url(char *parodus_url, char *seshat_url, char *build_type)
{

	FILE *fp = fopen(DEVICE_PROPS_FILE, "r");
        errno_t rc = -1;
	
	if (NULL != fp)
	{
		char str[255] = {'\0'};
		while(fscanf(fp,"%s", str) != EOF)
		{
		    char *value = NULL;
		    
		    if((value = strstr(str, "PARODUS_URL=")))
		    {
			value = value + strlen("PARODUS_URL=");
                    rc = strcpy_s(parodus_url, MAX_SERVER_URL_SIZE, value);
                    if(rc != EOK)
                    {
                        ERR_CHK(rc);
						fclose(fp);
                        return;
                    }
					
		    }
		    
            else if((value = strstr(str, "SESHAT_URL=")))
            {
                value = value + strlen("SESHAT_URL=");
                rc = strcpy_s(seshat_url, MAX_SERVER_URL_SIZE, value);
		        if(rc != EOK)
		        {
                    ERR_CHK(rc);
					fclose(fp);
                    return;
		        }
            }

		    else if((value = strstr(str, "BUILD_TYPE=")))
            {
                value = value + strlen("BUILD_TYPE=");
                rc = strcpy_s(build_type, MAX_BUILD_LEN, value);
		        if(rc != EOK)
		        {
                    ERR_CHK(rc);
		    		fclose(fp);
                    return;
                }
            }
		}
          /*Covrity Fix: CID 73480*/
                fclose(fp);  
	}
	else
	{
		LogError("Failed to open device.properties file:%s\n", DEVICE_PROPS_FILE);
              
	}
	
	
	if (0 == parodus_url[0])
	{
		LogError("parodus_url is not present in device.properties:%s\n", parodus_url);
	
	}
	
        if (0 == seshat_url[0])
        {
                LogError("seshat_url is not present in device.properties:%s\n", seshat_url);

        }

	 if (0 == build_type[0])
        {
                LogError("build_type is not present in device.properties:%s\n", build_type);

        }

	LogInfo("parodus_url formed is %s\n", parodus_url);	
        LogInfo("seshat_url formed is %s\n", seshat_url);
	LogInfo("build_type is %s\n", build_type);
}
 
static void getPartnerId(char *partner_id)
{
    FILE 	*file = NULL;

    if( 0 == syscfg_get(NULL, "PartnerID", partner_id, MAX_PARTNERID_LEN))
	{
	    if( *partner_id != '\0')
	    {
           return;
        }
    }
    
    file = popen("/lib/rdk/getpartnerid.sh GetPartnerID", "r");

	if(file)
	{
	   char *pos;
	   if( fgets ( partner_id, 64, file ) == NULL)
               LogError("fgets() error\n");
	   pclose ( file );
	   file = NULL;

	   if ( ( pos = strchr( partner_id, '\n' ) ) != NULL ) {
		   *pos = '\0';
	   }
	}
	else
	{
		LogError("Error in opening File to get partnerID\n");
	}
}

static int addParodusCmdToFile(char *command)
{
	FILE *fp;

	LogInfo("Opening parodusCmd file for writing the content\n");
	fp = fopen("/tmp/parodusCmd.cmd", "w");
	if (fp == NULL)
	{
		LogError("Cannot open %s in write mode\n", "/tmp/parodusCmd.cmd");
		return -1;
	}
	if (ferror(fp))
	{
		LogError("Error while writing parodusCmd.cmd file.\n");
		fclose(fp);
		return -1;
	}

	fprintf(fp, "%s", command);
	fclose(fp);
	return 0;
}
 
static void _START_LOG(int level, const char *msg, ...)
{
	static const char *_level[] = { "Error", "Info" };
	va_list arg_ptr;
	int nbytes;
	char buf[MAX_BUF_SIZE];
	char curtime[128];
   	time_t rawtime;
   	struct tm * timeinfo;
   	time ( &rawtime );
   	timeinfo = localtime ( &rawtime );
    	strftime(curtime, 128, "%y%m%d-%T", timeinfo);
    	
    	va_start(arg_ptr, msg);
    	nbytes = vsnprintf(buf, MAX_BUF_SIZE, msg, arg_ptr);
    	va_end(arg_ptr);
    	
    	if( nbytes >=  MAX_BUF_SIZE )	
	{
	    buf[ MAX_BUF_SIZE - 1 ] = '\0';
	}
	else
	{
	    buf[nbytes] = '\0';
	}
	if (NULL != g_fArmConsoleLog)
	{ 	
		fprintf(stderr, "%s : [mod=%s, lvl=%s] %s", curtime, MODULE, _level[level], buf);
	}	
	else
	{
		fprintf(stdout, "%s : [mod=%s, lvl=%s] %s", curtime, MODULE, _level[level], buf);
	}	
	
}

void getValueFromCfgJson( char *key, char **value, cJSON **out)
{
	char *data = NULL;
	cJSON *cfgValObj = NULL;
	cJSON *json = NULL;
	FILE *fileRead;
	int len = 0,n = 0;
        errno_t rc = -1;
	fileRead = fopen( WEBPA_CFG_FILE, "r+" );    
	if( fileRead == NULL ) 
	{
	    LogError( "Error opening file in read mode\n" );
	    return;
	}
	
	fseek( fileRead, 0, SEEK_END );
	len = ftell( fileRead );
        
        /*Coverity Fix CID 70708 */
        if(len < 0 )
        {
          
           LogError("ftell failed\n");
            fclose( fileRead );
            return;
        } 
        
	fseek( fileRead, 0, SEEK_SET );
	data = ( char* )malloc( sizeof(char) * (len + 1) );
         if (!data) {
            LogError("malloc() failed\n");
            fclose( fileRead );
            return;
        } 
          /* Coverity fix CID: 135424 STRING_SIZE NULL */
          n = fread( data, 1, len, fileRead );
             
             if (n <= 0) {
                LogInfo("webpa_cfg.json is empty\n");
                fclose( fileRead );
                return;
            }
             
  
                data[n] = '\0';
            
	fclose( fileRead );
        
        
	if( data != NULL && (strlen(data) > 0) )
	{
	    json = cJSON_Parse( data );
	    if( !json ) 
	    {
	        LogError( "json parse error: [%s]\n", cJSON_GetErrorPtr() );
	        char *ptr = NULL;
	        cJSON *tmpjson = NULL;
			char * newPtr = NULL;
			newPtr = (char *)realloc(data,len + 2);
                       
                        /* Coverity FIX  CID:66205 REVERSE_INULL */
                        if(newPtr == NULL)
		        {
                            LogError("Json parser failed due to newPtr is NULL\n");
                            return;
                        }
                       
               
                          	
			ptr = strstr(newPtr,WEBPA_CFG_MAX_PING_WAIT);
			if(ptr)
			{
				char *newLine = strchr(ptr,'\n');
				if(newLine)
				{
					//Get the length of current line and add comma at the end
					int nlen = strlen(ptr) - strlen(newLine);
					if(ptr[nlen-1] != ',')
					{
						ptr[nlen] = ',';
                                        	tmpjson = cJSON_Parse( newPtr );
						if(tmpjson)
						{
							char *output = cJSON_Print(tmpjson);
							writeToJson(output);
							if(output)
							{
								free(output);
							}
							if(tmpjson)
							{
								cJSON_Delete(tmpjson);
							}
						}
						else
						{
							LogError("Json parser failed even after recovery\n");
						}
					}
				}
			}
			
			free(newPtr);
			
	    } 
	    else 
	    {
	    	cfgValObj = cJSON_GetObjectItem( json, key );
	        if( cfgValObj != NULL)
	        {
                        if(cfgValObj->type == cJSON_String)
	                {
                                char *valFromJson = cJSON_GetObjectItem( json, key)->valuestring;
			        if (valFromJson != NULL && strlen(valFromJson) > 0)
			        {
				        *value = strdup(valFromJson);
			        }
			        else
			        {
				        *value = NULL;
			        }
			}
			else if(cfgValObj->type == cJSON_Number)
			{
			        int valFromJson = cJSON_GetObjectItem( json, key)->valueint;
	                        *value = (char *) malloc(sizeof(char) * MAX_VALUE_SIZE);
                            rc = sprintf_s(*value, MAX_VALUE_SIZE,"%d",valFromJson);
                            if(rc < EOK)
                            {
                               ERR_CHK(rc);
                               free(data);
		               return;
                             }
			}
			else
			{
			        *value = NULL;
			}
	       	 }
        	else
        	{
        		LogError("%s not available in webpa_cfg.json file\n", key);	
        	}
		
		*out = json;
		 free(data);
 		data = NULL;
	    }
	}
	else
	{
		LogInfo("webpa_cfg.json is empty\n");
                 if(data != NULL)
                     free(data);
		 return;
	}
}


static int writeToJson(char *data)
{
    FILE *fp;
    fp = fopen(WEBPA_CFG_FILE, "w");
    if (fp == NULL) 
    {
        LogError("Failed to open file %s\n", WEBPA_CFG_FILE);
        return -1;
    }
    
    fwrite(data, strlen(data), 1, fp);
    fclose(fp);
    return 0;
}

static void getWebpaValuesFromPsmDb(char *names[], char **values,int count)
{
    FILE* out = NULL;
    errno_t rc = -1;
    char command[MAX_BUF_SIZE]={'\0'};
    char buf[MAX_BUF_SIZE] = {'\0'};
    char tempBuf[MAX_BUF_SIZE] ={'\0'};
    int offset = 0, i=0, index=0;
    char temp[MAX_VALUE_SIZE] = {'\0'};

    for(i=0; i<count; i++)
    {
        rc = sprintf_s(tempBuf + offset, sizeof(tempBuf) - offset, " %dX %s", i, names[i]);
        if(rc < EOK)
        {
           ERR_CHK(rc);
           return;
        }
        offset += rc;
    }
    rc = sprintf_s(command, sizeof(command),"psmcli get -e%s", tempBuf);
    if(rc < EOK)
    {
        ERR_CHK(rc);
        return;
    }
    LogInfo("command : %s\n",command);

    out = popen(command, "r");
    if(out)
    {
        for(i=0; i<count; i++)
        {
            if(fgets(buf, sizeof(buf), out) == NULL)
                LogError("fgets() error\n");
            if(strlen(buf) > 0)
            {
                char *t = strrchr(buf, '"');
                if(t)
                    *t = '\0';
                if(sscanf(buf, "%dX=\"%s\n", &index, temp)  == 2 && index == i) {
                    values[i] = (char *) malloc(sizeof(char)* MAX_VALUE_SIZE);
                    rc = strcpy_s(values[i], MAX_VALUE_SIZE, temp);
                    if(rc != EOK)
                    {
                        ERR_CHK(rc);
						pclose(out);
                        return;
                    }
                }
            }
            if(feof(out))
            {
                LogInfo("End of file reached\n");
                break;
            }
        }
        pclose(out);
    }
    else
    {
        LogError("Failed to execute command\n");
    }
}

static void getValuesFromPsmDb(char *names[], char **values,int count)
{
    int i=0;
    char* prefixNames[count];
    char* buf = NULL;
    buf = (char*) malloc(MAX_BUF_SIZE);
    if(buf != NULL)
    {
        for(i=0; i<count; i++)
        {
            snprintf(buf, MAX_BUF_SIZE, "%s%s", pathPrefix, names[i]);
	    prefixNames[i] = strdup(buf);
        }
        free(buf);
        getWebpaValuesFromPsmDb( prefixNames, values, count );
    }
    else
    {
        LogError("getValuesFromPsmDb Failed\n");	    
    } 
}

static int setValuesToPsmDb(char *names[], char **values,int count)
{
    FILE* out = NULL;
    char command[MAX_BUF_SIZE]={'\0'};
    char buf[MAX_BUF_SIZE] = {0};
    int i = 0, ret=0;
    char tempBuf[MAX_BUF_SIZE] ={0};
    int offset = 0;
    errno_t rc = -1;

    for(i=0; i<count; i++)
    {
        rc = sprintf_s(tempBuf + offset, sizeof(tempBuf) - offset, " %s%s %s", pathPrefix,names[i], values[i]);
        if(rc < EOK)
        {
           ERR_CHK(rc);
           return -1;
        }
        offset += rc;
    }
    rc = sprintf_s(command, sizeof(command),"psmcli set%s", tempBuf);
    if(rc < EOK)
    {
        ERR_CHK(rc);
        return -1;
    }
    LogInfo("command : %s\n",command);
    out = popen(command, "r");
    if(out)
    {
        for(i=0; i<count; i++)
        {
            if(fgets(buf, sizeof(buf), out) == NULL)
                LogError("fgets() error\n");
            sscanf(buf, "%d\n", &ret);
            if(ret != 100)
            {
                LogError("Failed to setValuesToPsmDb\n");
                pclose(out);
                return -1;
            }
	    if(feof(out))
	    {
		LogInfo("End of file reached\n");
		break;
	    }
        }
        pclose(out);
    }
    else
    {
        LogError("Failed to execute command\n");
        return -1;
    }
    return 0;
}

static void getValuesFromSysCfgDb(char *names[], char **values,int count)
{
    int i = 0;
    errno_t rc = -1;
    for(i=0; i<count; i++)
    {
    	char temp[MAX_VALUE_SIZE] ={'\0'};
        if(syscfg_get( NULL, names[i], temp, MAX_VALUE_SIZE) == 0)
        {
	    	values[i] = (char *) malloc(sizeof(char)* MAX_VALUE_SIZE);
                rc = strcpy_s(values[i], MAX_VALUE_SIZE, temp);
                if(rc != EOK)
                {
                    ERR_CHK(rc);
                    return;
                }
        }
    }
}

static int syncXpcParamsOnUpgrade(char *lastRebootReason, char *firmwareVersion)
{
	int paramCount = 0, status = 0, i = 0;
	cJSON *out = NULL;
	char *cfgJson_firmware = NULL;
    char *paramList[] = {"X_COMCAST-COM_CMC","X_COMCAST-COM_CID","X_COMCAST-COM_SyncProtocolVersion"};
	char *psmValues[MAX_VALUE_SIZE] = {'\0'};
	char *sysCfgValues[MAX_VALUE_SIZE] = {'\0'};
	errno_t rc = -1;
        int ind = -1;
        int parodus_enable = 0;

	paramCount = sizeof(paramList)/sizeof(paramList[0]);
	getValueFromCfgJson( WEBPA_CFG_FIRMWARE_VER, &cfgJson_firmware, &out);
		
	LogInfo(" Returned json content is: %s\n", cJSON_Print(out));
	if(out != NULL)
	{
		LogInfo("cfgJson_firmware fetched from webpa_cfg.json is %s\n", cfgJson_firmware);
#ifdef UPDATE_CONFIG_FILE
		char *cJsonOut =NULL;
                int configUpdateStatus = -1;
                cJSON_ReplaceItemInObject(out, WEBPA_CFG_FIRMWARE_VER, cJSON_CreateString(firmwareVersion));
		
		cJsonOut = cJSON_Print(out);
		LogInfo("Updated json content is %s\n", cJsonOut);
		configUpdateStatus = writeToJson(cJsonOut);

		if(configUpdateStatus == 0)
		{
			LogInfo("Updated current Firmware version to config file\n");
		}
		else
		{
			LogError("Error in updating current Firmware version to config file\n");
		}
		if(cJsonOut != NULL)
		{
			free(cJsonOut);
			cJsonOut = NULL;
		}
#endif
		cJSON_Delete(out);
	}

	else
	{
		LogError("Error in fetching data from webpa_cfg.json file\n");
	}

        getValuesFromPsmDb(paramList, psmValues, paramCount);
	for(i = 0; i<paramCount; i++)
	{
	        if(psmValues[i] == NULL)
	        {
	        	LogInfo("PsmDb-> value is NULL for %s\n",paramList[i]);
	        	free_sync_db_items(paramCount, psmValues, sysCfgValues);
			/* Coverity Fix CID:53686 RESOURCE_LEAK  */
                          if( cfgJson_firmware != NULL)
                                free(cfgJson_firmware);
	        	return -1;
	        }
	        else
	        {
	        	LogInfo("PsmDb-> %s value is %s\n",paramList[i], psmValues[i]);
	        }
	}
	
	/* To check if it is an upgrade from release image to parodus ON */
        rc = strcmp_s("Software_upgrade",strlen("Software_upgrade"),lastRebootReason,&ind);
        ERR_CHK(rc);
        if((ind == 0) && (rc == EOK))
        {
            parodus_enable =1;
        }
        else if ((cfgJson_firmware != NULL) && (strlen(cfgJson_firmware)>0))
        {
             rc = strcmp_s(firmwareVersion,strlen(firmwareVersion),cfgJson_firmware,&ind);
             ERR_CHK(rc);
             if((ind != 0) && (rc == EOK))
             {
                 parodus_enable = 1;
             }
        }
		
    if( parodus_enable && ((psmValues[0] != NULL && atoi(psmValues[0]) ==0) && (psmValues[1] != NULL && atoi(psmValues[1]) ==0) && (psmValues[2] != NULL && atoi(psmValues[2]) ==0))) 
	{
		LogInfo("sync for bbhm and syscfg is required. Proceeding with DB sync..\n");
               getValuesFromSysCfgDb(paramList, sysCfgValues, paramCount);
		
		if(cfgJson_firmware != NULL)
		{
			free(cfgJson_firmware);
			cfgJson_firmware = NULL;
		}
		
		for(i=0; i<paramCount; i++)
		{
			if(sysCfgValues[i] == NULL)
	        	{
	        		LogInfo("SysCfgDb-> value is NULL for %s\n", paramList[i]);
	        		free_sync_db_items(paramCount, psmValues, sysCfgValues);
	        		return -2;
	        	}
	        	else
	        	{
	        		LogInfo("SysCfgDb-> %s value is %s\n", paramList[i], sysCfgValues[i]);
	        	}
		}
		
		status = setValuesToPsmDb(paramList, sysCfgValues, paramCount);
		if(status == 0)
		{
		        LogInfo("Successfully set values to PSM DB\n");
    		}
    		else
    		{
    			LogError("Failed to set values to PSM DB\n");
    			free_sync_db_items(paramCount, psmValues, sysCfgValues);
    			return -2;
    		}
    }
	else
	{
		LogInfo("Sync for bbhm and syscfg is not required\n");
		free_sync_db_items(paramCount, psmValues, sysCfgValues);
		if(cfgJson_firmware != NULL)
		{
			free(cfgJson_firmware);
			cfgJson_firmware = NULL;
		}
		return -1;
	}
		
	free_sync_db_items(paramCount, psmValues, sysCfgValues);
	return 0;
}

static void free_sync_db_items(int paramCount, char *psmValues[], char *sysCfgValues[])
{
	int i;
	for(i = 0; i<paramCount; i++)
	{
		if(psmValues[i] != NULL)
		{
	       		free(psmValues[i]);
	       		psmValues[i] = NULL;
	       	}
	       	
	       	if(sysCfgValues[i] != NULL)
		{
	       		free(sysCfgValues[i]);
	       		sysCfgValues[i] = NULL;
	       	}
	}

}


static void get_parodusStart_logFile(char *parodusStart_Log)
{

	FILE *fp = fopen(DEVICE_PROPS_FILE, "r");
        errno_t rc = -1;
	
	if (NULL != fp)
	{
		char str[255] = {'\0'};
		while(fscanf(fp,"%s", str) != EOF)
		{
		    char *value = NULL;
		    
		    if((value = strstr(str, "PARODUS_START_LOG_FILE=")))
		    {
			value = value + strlen("PARODUS_START_LOG_FILE=");
                        rc = strcpy_s(parodusStart_Log, MAX_BUF_SIZE, value);
                        if(rc != EOK)
                        {
                            ERR_CHK(rc);
                            fclose(fp);
                            return;
                        }
		    }
		    
		}
		fclose(fp);
	}
	else
	{
		LogError("Failed to open device.properties file:%s\n", DEVICE_PROPS_FILE);
	}
	
	if (0 == parodusStart_Log[0])
	{
		LogError("PARODUS_START_LOG_FILE is not present in device.properties \n");
	}	
	else
	{
		LogInfo("PARODUS_START_LOG_FILE is %s\n", parodusStart_Log);	
	}	
 }

/**
 * @brief To check format of server url
 * if url is matching the format <http/https>://<server_dns_name>:<port> returns success(1)
 *
 * @param[in] serverUrl server url from config json
 */
static int checkServerUrlFormat(char *serverUrl)
{
    int chCnt = 0;
    unsigned int i = 0;

    //looping to find count of ':'
    for (i = 0; i<strlen(serverUrl); i++)
    {
        if(serverUrl[i] == ':')
        {
            chCnt++;
        }
    }
    if(chCnt >= 2)
    {
        return 1;
    }
    return 0;
}

/**
 * @brief To check format of server url from config json and update server url
 * if url from config json matches the format <http/https>://<server_dns_name>:<port> update is not required
 * if url format is not matched, new server url will be framed  by getting port and dns_name from config json
 */
static void checkAndUpdateServerUrlFromDevCfg(char **serverUrl)
{
    char *tempUrl = NULL;
    cJSON *out = NULL;
    char *serverPort = NULL;
    errno_t rc = -1;
      
      if (*serverUrl == NULL ) {
             LogError(" **serverUrl is NULL \n");
          return;
      }


      tempUrl = strndup(*serverUrl, MAX_SERVER_URL_SIZE);
            if(checkServerUrlFormat(tempUrl) != 1 && strstr(tempUrl, "comcast") != NULL)
            {
                getValueFromCfgJson( "ServerPort", &serverPort, &out);
                if(out != NULL && serverPort != NULL && strlen(serverPort)>0)
                {
                    LogInfo("ServerPort fetched from webpa_cfg.json is %s\n", serverPort);
                    free(*serverUrl);
                    *serverUrl = (char *) malloc(sizeof(char) * MAX_SERVER_URL_SIZE);
                    if( *serverUrl == NULL)
                    {
                      LogError("Error in serverUrl malloc\n");
                       return;
                    }  
                    
                    rc = sprintf_s(*serverUrl, MAX_SERVER_URL_SIZE, "https://%s:%s",tempUrl,serverPort);
                    if(rc < EOK)
                    {
                       ERR_CHK(rc);
                       LogError("Error in updating server URL\n");
                    }
                    free(serverPort);
                    cJSON_Delete(out);
                }
                else
                {
                    LogError("Error in fetching data from webpa_cfg.json file\n");
                    *serverUrl = NULL;
                }
                      

            }
            free(tempUrl);
           
}
static void waitForPSMHealth(char *compName)
{
	int count = 0;
	char comp_status_cmd[128] = {0};
	char parameter_name[128]= {0};
	char comp_status[32]= {0};
        errno_t rc = -1;
		int ind = -1;
	
        rc = sprintf_s(parameter_name,sizeof(parameter_name),"%s.%s",compName,"Health");
        if(rc < EOK)
        {
           ERR_CHK(rc);
	       return;
        }
	
	while(1)
	{
        rc = sprintf_s(comp_status_cmd, sizeof(comp_status_cmd), "dmcli eRT getv com.cisco.spvtg.ccsp.psm.Health | grep value | awk '{print $5}'");
        if(rc < EOK)
        {
           ERR_CHK(rc);
           return;
        }
		
		FILE *f;
    		if ((f = popen(comp_status_cmd, "r")) == NULL) 
    		{
        		LogError("Error in getting status\n");
        		return;
        	}
                /* Coverity Fix CID:62204 CHECKED_RETURN */
		if( fscanf(f,"%s",comp_status) == EOF )      	
        		LogError("Error in fscanf() return\n");
    		pclose(f);

        rc = strcmp_s("Green",strlen("Green"),comp_status,&ind);
        ERR_CHK(rc);
        if((ind == 0) && (rc == EOK))
		{
			break;
		}
		else
		{
			if(count > 5 )
			{
				LogError("%s component has failed . Proceeding with Parodus start up\n",parameter_name);
				return;
			}
			else
			{
				LogError("%s component is not up, waiting\n",parameter_name);
				sleep(10);
				count++;
			}
		}
	} 
	LogInfo("%s component health is green, continue\n",parameter_name);
}

static int executeConfigFile()
{
	int rv = -1;
	FILE* out = NULL, *file = NULL;
	pid_t pid;
	int status;
	
	file = fopen(GETCONF_FILE, "r");
	if(file)
	{
		LogInfo("Proceeding with GetConfigFile\n");
		fclose(file);
	}
	else
	{
		LogError("Error: GetConfigFile Not Found\n");
		return rv;
	}

	if ((pid = fork()) == -1)
	{
		LogError("fork failed\n");
		return rv;
	}

	if(pid == 0)
	{

		pid = getpid();
		LogInfo("child process execution with pid:%d\n", pid);

		execl(GETCONF_FILE, "GetConfigFile", CURL_FILE_RESPONSE, (char *)0);

		exit(0);
	}
	else
	{
		pid_t cpid = waitpid(pid, &status, 0);

		LogInfo("cpid returned from waitpid %d status %d\n", cpid, status);

		if (WIFEXITED(status))
		{
			LogInfo("child %d terminated with status: %d\n", cpid, WEXITSTATUS(status));
		}
		else
		{
			LogInfo("child process pid running %d, killing it\n", pid);
			/*Coverity Fix CID:104370 CHECKED_RETURN */
                        if( kill(pid, SIGKILL) < 0 )
			   LogError("child process pid running %d, is not  killed successfully\n", pid);
				
		}
	}

	out = fopen(CURL_FILE_RESPONSE, "r");
	if(out)
	{
		LogInfo("CEDM decode file generated successfully\n");
		fclose(out);
		rv = 0;
	}
	else
	{
		LogError("Failure in CFG response\n");
		return rv;
	}
	return rv;

}
