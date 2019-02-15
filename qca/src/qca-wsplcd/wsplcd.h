/*
 * @File: wsplcd.h
 *
 * @Abstract: AP AutoConfig/wsplcd header file
 *
 * @Notes:  IEEE1905 AP Auto-Configuration Daemon
 *          AP Enrollee gets wifi configuration from AP Registrar via
 *          authenticated IEEE1905 Interfaces
 *
 * Copyright (c) 2011-2012,2018 Qualcomm Technologies, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 * 2011-2012 Qualcomm Atheros, Inc.
 * Qualcomm Atheros Confidential and Proprietary.
 * All rights reserved.
 *
 */


#ifndef _WSPLCD_H
#define _WSPLCD_H
#include "includes.h"
#include <signal.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <linux/if_packet.h>
#include <netinet/if_ether.h>
#include <linux/if_vlan.h>
#include "defs.h"
#include "common.h"
#include "priv_netlink.h"
#include "wireless_copy.h"
#include "wpa_common.h"
#include "eap_defs.h"
#include "l2_packet.h"
#include "wps_parser.h"
#include "legacy_ap.h"


#include "wps_config.h"
#include "apac_hyfi20_atf.h"

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

struct eap_session;
typedef struct l2_ethhdr L2_ETHHDR;
typedef struct ieee802_1x_hdr IEEE8021X_HDR;
typedef struct eap_hdr EAP_HDR;
typedef struct eap_format EAP_FORMAT;

#define EAPOL_MULTICAST_GROUP	{0x01,0x80,0xc2,0x00,0x00,0x03}


#define MODE_CLIENT 0x00
#define MODE_SERVER 0x01
#define MODE_NONE   0x02

// Default Push Button Ignore Duration (in seconds)
#define PUSH_BUTTON_IGNORE_DUR      10


#define WSPLC_NLMSG_IFNAME   "eth0"
#define WSPLC_EAPMSG_TXIFNAME "eth0"
#define WSPLC_EAPMSG_RXIFNAME "br0"

#define WSPLC_CLONE_TIMEOUT  180
#define WSPLC_WALK_TIMEOUT    120
#define WSPLC_REPEAT_TIMEOUT  1
#define WSPLC_INTERNAL_TIMEOUT 15
#define WSPLC_ONE_BUTTON     1
#define WSPLC_TWO_BUTTON    2

#define MAX_SSID_LEN        32
#define MAX_PASSPHRASE_LEN  63

#define MAX_RADIO_CONFIGURATION 3
#define MAX_WLAN_CONFIGURATION 16

typedef struct _wsplcd_config {
    u32     ssid_len;
    char    ssid[MAX_SSID_LEN];
    u16     auth;
    u16     encr;
    u32     passphraseLen;
    u8      passphrase[MAX_PASSPHRASE_LEN];
    u32    clone_timeout;
    u32    walk_timeout;
    u32    repeat_timeout;
    u32    internal_timeout;
    u32    button_mode;
    int     debug_level;

} WSPLCD_CONFIG;

typedef struct _wsplcd_data {
    int     mode;
    int     nlSkt;
    int     txSkt;
    int     rxSkt;
    int     txIfIndex;
    int     nlIfIndex;
    char   txIfName[IFNAMSIZ];
    char   rxIfName[IFNAMSIZ];
    char   nlIfName[IFNAMSIZ];
    u8     own_addr[ETH_ALEN];
    WSPLCD_CONFIG   wsplcConfig;

    int clone_running;
    struct eap_session* sess_list;
    struct wpa_sup* wpas;
} wsplcd_data_t;

/* stdio.h(gcc-5.2) brought dprintf() prototype which
 * is different from our existing dprintf() function
 * prototype, This causes compile time conflicts types
 * for dprintf().
 * Hence we will make our dpritf() prototype same as what
 * stdio.h is having.  */
int dprintf(int level, const char *fmt, ...);
void shutdown_fatal(void);

int wsplc_disable_cloning(wsplcd_data_t* wspd);
int wsplc_stop_cloning(wsplcd_data_t* wspd);
int wsplc_is_cloning_runnig(wsplcd_data_t* wspd);
int wsplcd_hyfi10_init(wsplcd_data_t* wspd);
int wsplcd_hyfi10_startup(wsplcd_data_t* wspd);
int wsplcd_hyfi10_stop(wsplcd_data_t* wspd);

/****************************************************
 ****************************************************
 **** Hyfi2.0 / IEEE1905 AP Auto-Configuration ******
 ****************************************************
 ****************************************************/

#include "ieee1905_defs.h"

#define APAC_SEARCH_TIMEOUT                 60
#define APAC_PUSHBUTTON_TIMEOUT            120
#define APAC_RM_COLLECT_TIMEOUT             10
#define APAC_PB_SEARCH_TIMEOUT              10
#define APAC_CHANNEL_POLLING_TIMEOUT        10

#define APAC_WPS_SESSION_TIMEOUT            30
#define APAC_WPS_RETRANSMISSION_TIMEOUT      5
#define APAC_WPS_MSG_PROCESSING_TIMEOUT     15

#define APAC_MAXNUM_HYIF                    45  /* number of Hyfi/1905 interfaces assuming 3 radio and 15 BSSeS per Radio */
#define APAC_MAXNUM_NTWK_NODES              64  /* number of nodes in network */
#define MAX_NW_KEY_LEN                     256

#define APAC_CONF_FILE_PATH         "/tmp/wsplcd.conf"
#define APAC_PIPE_PATH              "/var/run/wsplc.pipe"
#define APAC_LOG_FILE_PATH          "/tmp/wsplcd.log"
#define APAC_LOCK_FILE_PATH         "/var/run/wsplcd.lock"
#define APAC_MAP_CONF_FILE          "/etc/config/map.conf"
#define APAC_CONF_FILE_NAME_MAX_LEN 128
/* TODO: use local variable instead of this global one */
char g_cfg_file[APAC_CONF_FILE_NAME_MAX_LEN];
char g_log_file_path[APAC_CONF_FILE_NAME_MAX_LEN];
char g_map_cfg_file[APAC_CONF_FILE_NAME_MAX_LEN]; //to hold map config


/* IEEE1905 defined */
#define APAC_MULTICAST_ADDR         IEEE1905_MULTICAST_ADDR
#define APAC_ETH_P_IEEE1905         IEEE1905_ETHER_TYPE

#define APAC_TLVLEN_ROLE            sizeof(u8)
#define APAC_TLVLEN_FREQ            sizeof(u8)

#define APAC_MID_DELTA              64
#define AVLN_LEN                    7

/* Default maximum number of seconds to wait for APAC completes on each
 * band since the first Wi-Fi configuration gets stored.
 * It will only be used when the configuration parameter not provided. */
#define APAC_WAIT_WIFI_CONFIG_SECS_OTHER            20

/* Default maximum number of seconds to wait for APAC completes on the first
 * band after WPS success.
 * It will only be used when the configuration parameter not provided. */
#define APAC_WAIT_WIFI_CONFIG_SECS_FIRST            30
#define MAP_BSS_TYPE_TEARDOWN  0x10
#define MAP_BSS_TYPE_FRONTHAUL 0x20
#define MAP_BSS_TYPE_BACKHAUL  0x40
#define MAP_BSS_TYPE_BSTA      0x80


/* log file mode */
typedef enum apacLogFileMode_e {
    APAC_LOG_FILE_APPEND,
    APAC_LOG_FILE_TRUNCATE,

    APAC_LOG_FILE_INVALID
} apacLogFileMode_e;

/* boolean */
typedef enum apacBool_e {
    APAC_FALSE = 0,
    APAC_TRUE = !APAC_FALSE
} apacBool_e;
#define APAC_CONFIG_STA         APAC_TRUE


/* device type */
typedef enum apacHyfi20DeviceType_e {
    APAC_IEEE1905,
    APAC_HYFI10
} apacHyfi20DeviceType_e;

/* WPS method used in registration. Only Registrar can control it */
typedef enum {
    APAC_WPS_M2,
    APAC_WPS_M8
} apacHyfi2020WPSMethod_e;
#define APAC_WPS_METHOD             APAC_WPS_M2


typedef enum apacHyfi20Role_e {
    APAC_REGISTRAR,
    APAC_MAP_CONTROLLER = APAC_REGISTRAR,
    APAC_ENROLLEE,
    APAC_MAP_AGENT = APAC_ENROLLEE,
    APAC_OTHER = ~0
} apacHyfi20Role_e;

typedef enum apacHyfi20WifiFreq_e {
    APAC_WIFI_FREQ_2,
    APAC_WIFI_FREQ_5,
    APAC_WIFI_FREQ_60,

    // we can have two 5G radio now
    //(not looking into freq to mark it lower or upper so name it as other)
    APAC_WIFI_FREQ_5_OTHER,

    APAC_NUM_WIFI_FREQ,

    APAC_WIFI_FREQ_INVALID = ~0
} apacHyfi20WifiFreq_e;

typedef enum apacHyfi20WlanDeviceMode_e {
    APAC_WLAN_AP,
    APAC_WLAN_STA,

    APAC_INVALID_DEVICE_MODE = ~0
} apacHyfi20WlanDeviceMode_e;

enum {
    APAC_SB,
    APAC_DB,
    APAC_DBDC
};

typedef enum apacHyfi20MediaType_e {
    APAC_MEDIATYPE_ETH,
    APAC_MEDIATYPE_WIFI,
    APAC_MEDIATYPE_PLC,
    APAC_MEDIATYPE_MOCA,
    APAC_MEDIATYPE_WIFI_VLAN,

    APAC_MEDIATYPE_INVALID = ~0
} apacHyfi20MediaType_e;

typedef enum {
    /* Enrolle with PB mode */
    APAC_E_PB_IDLE = 0,     /* 0 PB de-activated */
    APAC_E_PB_WAIT_RESP,    /* 1 set Search message is sent */
    APAC_E_PB_WPS,          /* 2 set after M1 is sent */

    /* Enrollee with AP Auto Config mode */
    APAC_E_IDLE,            /* 3 initial state, set when Registration is done */
    APAC_E_WAIT_RESP,       /* 4 set after Search message is sent */
    APAC_E_WPS,             /* 5 set after sending M1 */

    /* Registrar with PB mode */
    APAC_R_PB_IDLE,             /* 6 PB de-activated */
    APAC_R_PB_WAIT_SEARCH,      /* 7 set when PB is activated */
    APAC_R_PB_WAIT_M1,          /* 8 set when Response message is sent */
    APAC_R_PB_WPS,

    /* Registrar with AP Auto Config mode */
    APAC_R_NO_PB,               /* 10 */

    APAC_INVALID_STATE = ~0
} apacHyfi20State_e;

typedef struct apacMapAP_t {
    char    ssid[MAX_SSID_LEN+1];
    u32     ssid_len;
    u16     auth;
    u16     encr;
    u8      nw_key_index;
    char    nw_key[MAX_NW_KEY_LEN+1];
    u32     nw_key_len;
    u8      ap_mac[ETH_ALEN];
    u8      passphrase[MAX_PASSPHRASE_LEN+1];
    u32     passphraseLen;
    u8      new_password[MAX_PASSPHRASE_LEN+1];
    u32     new_password_len;
    u32     device_password_id;
    u32     key_wrap_authen;
    u8      mapBssType;
} apacMapAP_t;

typedef struct apacMapEProfile_t {
    char    *alId;
    u8    *opclass;
    u8    *ssid;
    u8    *auth;
    u8    *encr;
    u8    *nw_key;
    u8    *mapbh;
    u8    *mapfh;
} apacMapEProfile_t;

typedef struct apacPifMap {
    ieee80211req_map_apcap_data reg;
    map_unoperable_ch mapOpClass[IEEE80211_MAX_OPERATING_CLASS];
} apacPifMap_t;

/* AP information */
typedef struct apacHyfi20AP_t {
    apacBool_e valid;
    apacBool_e isAutoConfigured;
    apacBool_e isDualBand;
    apacHyfi20WifiFreq_e freq;
    s32      vap_index;
    char     *ifName;
    apacBool_e isStaOnly;

    /* Wifi encryption settings (IEEE1905 Table 10-1); info read from MIB */
    char    ssid[MAX_SSID_LEN+1];
    u32     ssid_len;
    u16     auth;
    u16     encr;
    u8      nw_key_index;
    char    nw_key[MAX_NW_KEY_LEN+1];
    u32     nw_key_len;
    u8      ap_mac[ETH_ALEN];
    u8      passphrase[MAX_PASSPHRASE_LEN+1];
    u32     passphraseLen;
    u8      new_password[MAX_PASSPHRASE_LEN+1];
    u32     new_password_len;
    u32     device_password_id;
    u32     key_wrap_authen;

    /* QCA vendor settings */
    u8      *qca_ext;
    u32     qca_ext_len;
    u32     channel;
#define APAC_STD_MAX_LEN 20
    u_int8_t standard_len;
    char standard[APAC_STD_MAX_LEN];
    apacPifMap_t pIFMapData;
    u8      mapfh;
    u8      mapbh;
    int     radio_index;
} apacHyfi20AP_t;
/* information for interface */
typedef struct apacHyfi20IF_t {
    apacBool_e valid;
    apacBool_e is1905Interface;
    apacBool_e nonPBC;   /* whether PBC is disabled */
    apacHyfi20MediaType_e mediaType;
    apacHyfi20WlanDeviceMode_e wlanDeviceMode;
    apacHyfi20WifiFreq_e wifiFreq;

    u8      mac_addr[ETH_ALEN];
    s32     ifIndex;
    char    ifName[IFNAMSIZ];
    s32     sock;

    s32     vapIndex;
    s32     ctrlSock;

    /* The time when last WPS success happens on this interface */
    struct os_time last_wps_success_time;
} apacHyfi20IF_t;

/* configurable parameters */
typedef struct apacHyfi20Config_t {
    s32                 debug_level;
    apacHyfi20Role_e    role;
    apacHyfi20State_e   state;
    apacBool_e          config_sta;
    u32                 search_to;
    u32                 pushbutton_to;

    u32                 wlan_chip_cap;
    apacBool_e          band_sel_enabled;
    apacHyfi20WifiFreq_e band_choice;
    u32                 rm_collect_to;
    apacBool_e          deep_clone_enabled;
    apacBool_e          deep_clone_no_bssid;
    apacBool_e          manage_vap_ind;
    apacBool_e          designated_pb_ap_enabled;

    apacHyfi2020WPSMethod_e wps_method;
    u32                 wps_session_to;
    u32                 wps_retransmit_to;
    u32                 wps_per_msg_to;
    struct wps_config*  wpsConf;

    apacBool_e          hyfi10_compatible;
    apacBool_e          sendOnAllIFs;
    char                ucpk[64+1];
    char                salt[64+1];
    u32                 wpa_passphrase_type;
    char                ssid_suffix[128];

    apacBool_e          pbmode_enabled;
    u32                 pb_search_to;

    /* the maximum number of seconds to wait for APAC completes on all
     * other bands after the first Wi-Fi configuration gets stored */
    u32                 wait_wifi_config_secs_other;

    /* the maximum number of seconds to wait for first Wi-Fi configured
     * after WPS success */
    u32                 wait_wifi_config_secs_first;
    apacBool_e          atf_config_enabled;     /* Enable/Disable ATF configurations */
    u32                 apac_atf_num_repeaters; /* Num Repeaters with ATF Configurations */
    ATF_REP_CONFIG      *atfConf;               /* ATF Configuration */
    u32                 cfg_changed;
    u32                 cfg_restart_short_timeout;
    u32                 cfg_restart_long_timeout;
    u32                 cfg_apply_timeout;
} apacHyfi20Config_t;


typedef struct apacHyfi20Data_t {
    u8                      alid[ETH_ALEN];
    s32                     nlSock;
    s32                     unPlcSock;
    s32                     pipeFd;
    u32                     mid;
    u32                     isCfg80211; /* Flag to enable CFG80211 */

    apacHyfi20Config_t      config;
    apacHyfi20AP_t          ap[APAC_NUM_WIFI_FREQ];
    apacHyfi20IF_t          hyif[APAC_MAXNUM_HYIF];
    apacHyfi20IF_t          bridge;                   /* hy0 */

    struct apac_wps_session*    sess_list;
    struct wpa_supp*            wpas;

    /* storage handle used to store Wi-Fi configuration params */
    void *wifiConfigHandle;

    /* the time elapsed since the first Wi-Fi configuration gets stored */
    u8 wifiConfigWaitSecs;
} apacHyfi20Data_t;

typedef struct apacMapData_t {
    apacBool_e enable;
    u8 MapConfMaxBss;
    apacMapAP_t mapEncr[MAX_WLAN_CONFIGURATION];
    u8 mapEncrCnt;
    apacMapEProfile_t eProfile[APAC_MAXNUM_NTWK_NODES];
    u8 eProfileCnt;
    u8 m1SentBand; // to differnentiate between 5G L and 5G h
    u8 mapBssType[MAX_WLAN_CONFIGURATION];
} apacMapData_t;
/* hold it all */

typedef struct apacInfo_t {
    wsplcd_data_t           hyfi10;
    apacHyfi20Data_t        hyfi20;
    apacMapData_t           mapData;
} apacInfo_t;

/*HYFI 2.0 and 1.0 shares some basic configuration and Operations,
  following macro provides an easy way to access each other */
#define HYFI10ToHYFI20(m) ((apacHyfi20Data_t *)&((apacInfo_t*)((char *)m - offsetof(apacInfo_t, hyfi10)))->hyfi20)
#define HYFI20ToHYFI10(m) ((wsplcd_data_t *)&((apacInfo_t*)((char *)m - offsetof(apacInfo_t, hyfi20)))->hyfi10)
#define HYFI20ToMAP(m) ((apacMapData_t *)&((apacInfo_t*)((char *)m - offsetof(apacInfo_t, hyfi20)))->mapData)
#define MAPToHYFI20(m) ((apacHyfi20Data_t *)&((apacInfo_t*)((char *)m - offsetof(apacInfo_t, mapData)))->hyfi20)


/* Public APIs */
/*
 * The function gets called if SimpleConnect (activated by wsplcd)
 * has successfully added a new node
 * (out) plc_mac: the PLC MAC address of the newly added node
 */
void pbcPlcSimpleConnectAddNode(u8 *plc_mac);

/*
 * The function gets called if hostapd has activated (by wsplcd) WPS on an 1905 AP
 * and this AP successfully added a new node
 * (out) wifi_mac: the added WIFI MAC address of the new station
 */
void pbcWifiWpsAddNode(u8 *mac_ap, u8 *mac_sta);
#endif // _WSPLCD_H
