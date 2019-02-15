/*
 * Copyright (c) 2017 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

/* SON Libraries - Common header file */

#ifndef __SONLIB_CMN_H__
#define __SONLIB_CMN_H__
#include <net/if.h>
#include <bufrd.h>
#include <ieee80211_band_steering_api.h>
#include <dbg.h>

struct soncmnDrvHandle{
    void *ctx;
    struct soncmnOps *ops;
};

/* enum for vendors */
enum soncmnVendors {
    SONCMN_VENDOR_QTI=0,
    SONCMN_VENDOR_ATHXK,
    SONCMN_VENDOR_BRCM,
    SONCMN_VENDOR_INTC,
    SONCMN_VENDOR_MTEK,
    SONCMN_VENDOR_RTEK,
    /* Add new vendor enums here */
    SONCMN_VENDOR_UNKNOWN, //unknown vendor
    SONCMN_VENDOR_MAX  /* This is always the last enum */
};

/* For debugging support */
struct soncmnDbg_t{
     struct dbgModule *dbgModule;
}soncmnDbgS;

typedef enum
{
        SONCMN_OK = 0,
        SONCMN_NOK = -1

} SONCMN_STATUS;

//This is always enabled in QCA driver.
//TODO: Get this value from Makefile flags
#define QCN_IE 1

typedef struct wlanifBSteerEventsPriv_t * wlanifBSteerEventsHandle_t;
void wlanifBSteerEventsMsgRx(wlanifBSteerEventsHandle_t state, const ath_netlink_bsteering_event_t *event);

/***********************************************************************************/
/******** Soncmn structures used to commuinicate between driver and SON modules ****/
/***********************************************************************************/

/*** Structure to pass Station Info ***/
struct soncmn_ieee80211_bsteering_datarate_info_t {
    /* Maximum bandwidth the client supports, valid values are enumerated
     * in enum ieee80211_cwm_width in _ieee80211.h. But the header file cannot
     * be included here because of potential circular dependency. Caller should
     * make sure that only valid values can be written/read. */
    u_int8_t max_chwidth;
    /* Number of spatial streams the client supports */
    u_int8_t num_streams;
    /* PHY mode the client supports. Same as max_chwidth field, only valid values
     * enumerated in enum ieee80211_phymode can be used here. */
    u_int8_t phymode;
    /* Maximum MCS the client supports */
    u_int8_t max_MCS;
    /* Maximum TX power the client supports */
    u_int8_t max_txpower;
    /* Set to 1 if this client is operating in Static SM Power Save mode */
    u_int8_t is_static_smps : 1;
    /* Set to 1 if this client supports MU-MIMO */
    u_int8_t is_mu_mimo_supported : 1;
} ;

struct soncmn_sta_info_t {
    /* Station mac address */
    uint8_t   stamac[6];
    /* Set to 1 if client is BTM capable */
    uint8_t   isbtm;
    /* Set to 1 if client is RRM capable */
    uint8_t   isrrm;
    /* Operating bands if sta is 2.4G or 5G or both */
    /* 0th bit - 2.4G band, 1st bit - 5G band */
    uint8_t   operating_band;
    /* When set to 1, datarateInfo below is valid, else ignore datarateInfo */
    uint8_t   phy_cap_valid;
    /* Rssi value */
    int8_t    rssi;
    /* Data rate info as defined above */
    struct soncmn_ieee80211_bsteering_datarate_info_t datarateInfo;
};

#define SONCMN_MAX_STA_CLIENTS 1023
struct soncmn_req_stainfo_t {
    /* Total number of clients/stations */
    uint8_t numSta;
    /* Info for each client/station */
    struct soncmn_sta_info_t stainfo[SONCMN_MAX_STA_CLIENTS];
};


/****** Structure to pass Station Stats *******/
struct soncmn_staStatsSnapshot_t {
    /// Number of bytes sent to the STA by this AP.
    u_int64_t txBytes;
    /// Number of bytes received from the STA by this AP.
    u_int64_t rxBytes;
    /// Last rate (in Kbps) at which packets sent to the STA by this AP were sent.
    uint32_t lastTxRate;
    /// Last rate (in Kbps) at which the packets sent by the STA to this AP were sent.
    uint32_t lastRxRate;
};

/***** Structure for Beacon Report Request  ****/
#define SONCMN_IEEE80211_RRM_CHAN_MAX            255

#define SONCMN_IEEE80211_RRM_NUM_CHANREQ_MAX     5
#define SONCMN_IEEE80211_RRM_NUM_CHANREP_MAX     2

struct soncmn_ieee80211_beaconreq_chaninfo {
    /* Requglatory class to identify set of channels */
    u_int8_t regclass;
    /* Total number of channels */
    u_int8_t numchans;
    /* List of Channel numbers */
    u_int8_t channum[SONCMN_IEEE80211_RRM_NUM_CHANREQ_MAX];
};

/* Structure containing information for creating Measurement  */
/* request of type Beacon request. Different fields contain   */
/* info needed as per Measurement request element in 11k spec */
struct soncmn_ieee80211_rrm_beaconreq_info_t {
    // Number of repetitions for the measurement
    u_int16_t   num_rpt;
    // Regulatory class identifying channel set
    // for which the measurement request applies
    u_int8_t    regclass;
    // Channel number for the measurement
    u_int8_t    channum;
    // Randomization Interval field specifies the upper bound of the random
    // delay to be used prior to making the measurement, in units of TUs
    u_int16_t   random_ivl;
    // Measurement Duration field is set to the preferred or
    // mandatory duration of the requested measurement, in units of TUs
    u_int16_t   duration;
    // Measurement Mode: Bits for Parallel, Enable, Request, report etc.
    // Default value used: 0
    u_int8_t    reqmode;
    // Measurement request type: e.g. Beacon (5)
    u_int8_t    reqtype;
    // BSSID for which a beacon report is requested
    u_int8_t    bssid[6];
    // Beacon request Mode: Active, Passive, Beacon table
    u_int8_t    mode;
    // Optional element: SSID subelement indicates the ESS for which
    // a beacon report is requested.
    u_int8_t    req_ssid;
    // Optional Beacon Reporting subelement: reporting condition
    // indicates the condition for issuing a Beacon report
    u_int8_t    rep_cond;
    // Option Beacon reporting subelement: reporting threshold value
    // to be used for conditional reporting
    u_int8_t    rep_thresh;
    // Optional Reporting Detail subelement defines the level of
    // detail per AP to be reported to the requesting STA
    u_int8_t    rep_detail;
    // Optional Request sublement
    u_int8_t    req_ie;
    // Optional subelement: AP Channel Report (indicates if
    // additional channels are provided for measurement)
    u_int8_t    num_chanrep;
    // List of additional channels for iterative measurement
    // Measurement is done on these only when one or more AP Channel
    // Report elements are included in the request
    struct soncmn_ieee80211_beaconreq_chaninfo
        apchanrep[SONCMN_IEEE80211_RRM_NUM_CHANREP_MAX];
};


/**** Structure for BTM Request ****/
/* candidate BSSID for BSS Transition Management Request */
struct soncmn_ieee80211_bstm_candidate {
    /* candidate BSSID */
    u_int8_t bssid[6];
    /* channel number for the candidate BSSID */
    u_int8_t channel_number;
    /* preference from 1-255 (higher number = higher preference) */
    u_int8_t preference;
    /* operating class */
    u_int8_t op_class;
    /* PHY type */
    u_int8_t phy_type;
};

/* maximum number of candidates in the list.  Value 3 was selected based on a
   2 AP network, so may be increased if needed */
#define SONCMN_IEEE80211_BSTM_REQ_MAX_CANDIDATES 3
/* BSS Transition Management Request information that can be specified via ioctl */
struct soncmn_ieee80211_bstm_reqinfo_target {
    u_int8_t dialogtoken;
    u_int8_t num_candidates;
#if QCN_IE
    /*If we use trans reason code in QCN IE */
    u_int8_t qcn_trans_reason;
#endif
    u_int8_t trans_reason;
    u_int8_t disassoc;
    u_int16_t disassoc_timer;
    struct soncmn_ieee80211_bstm_candidate
       candidates[SONCMN_IEEE80211_BSTM_REQ_MAX_CANDIDATES];
};


/* Ops structure: API function pointers */
/* NOTE: Mapping to vendor APIs should be in same seqeunce and order as defined here */
/* 3rd party vendor should implement No-Op if not implementing an API */
struct soncmnOps {
    int (* init) (struct soncmnDrvHandle *handle);
    void (* deinit) (struct soncmnDrvHandle *handle);
    int (* getName) (const void *,const char *, char *, size_t len);
    int (* getBSSID) (const void *, const char *, struct ether_addr *bssid );
    int (* getSSID) (const void *, const const char * , void *, uint32_t * );
    int (* isAP) (const void *, const char *, uint32_t *result);
    int (* getFreq) (const void *, const char *, int32_t * freq);
    int (* getIfFlags) (const void *, const const char * , struct ifreq *ifr );
    int (* getAcsState) (const void *, const char *, int * acsstate);
    int (* getCacState) (const void *, const char *, int * cacstate);
    int (* setBSteerAuthAllow) (const void *, const char *, const uint8_t *dest_addr, uint8_t authAllow);
    int (* setBSteerProbeRespWH) (const void *, const char *, const uint8_t *dest_addr, uint8_t probeRespWHEnable);
    int (* setBSteerProbeRespAllow2G) (const void *, const char *, const uint8_t *dest_addr, uint8_t allowProbeResp2G);
    int (* setBSteerOverload) (const void *, const char *, uint8_t setOverload);
    int (* performLocalDisassoc) (const void *, const char *, const uint8_t *dest_addr);
    int (* performKickMacDisassoc) (const void *, const char *, const uint8_t *dest_addr);
    int (* setBSteering) (const void *, const char *, uint8_t bSteerEnable); //per radio
    int (* setBSteerEvents) (const void *, const char *, uint8_t bSteerEventsEnable); //per VAP
    int (* setBSteerInProgress) (const void *, const char *, const uint8_t *dest_addr, uint8_t bSteerInProgress); //InProgress flag
    int (* setBSteerParams) (const void *, const char *, void *data, uint32_t data_len); //static config params
    int (* getBSteerRSSI) (const void *, const char *, const uint8_t *dest_addr, uint8_t numSamples);
    int (* getDataRateInfo) (const void *, const char *, const uint8_t *dest_addr, struct soncmn_ieee80211_bsteering_datarate_info_t *);
    int (* getStaInfo) (const void *, const char *, struct soncmn_req_stainfo_t *getStaInfo);
    int (* getStaStats) (const void *, const char *, const uint8_t *dest_addr, struct soncmn_staStatsSnapshot_t *);
    int (* setAclPolicy) (const void *, const char *, int aclCmd);
    int (* sendBcnRptReq) (const void *, const char *, const uint8_t *dest_addr, struct soncmn_ieee80211_rrm_beaconreq_info_t *bcnreq);
    int (* sendBTMReq) (const void *, const char *, const uint8_t *dest_addr, struct soncmn_ieee80211_bstm_reqinfo_target *btmreq);
    int (* setMacFiltering) (const void *, const char *, const uint8_t *stamac , uint8_t isAdd);
    int (* getChannelWidth) (const void *, const char *, int *chwidth);
    int (* getOperatingMode) (const void *, const char *, int *opMode);
    int (* getChannelExtOffset) (const void *, const char *, int *choffset);
    int (* getCenterFreq160) (const void *, const char *, uint8_t channum, uint8_t *cfreq);
    int (* getCenterFreqSeg1) (const void *, const char *, int32_t *cFreqSeg1);
    int (* getCenterFreqSeg0) (const void *, const char *, uint8_t channum, uint8_t *cFreqSeg0);
    int (* enableBSteerEvents) (uint32_t sysIndex);
    int (* dumpAtfTable) (const void *, const char *, void *atfInfo, int32_t len);
};



/***********************************************************************/
/***** Structures/functions for Ifname-Vendor-DrvHandle mapping ********/
/***********************************************************************/

/**
 * @brief Function to obtain LBD Event handler opaque pointer
 *        Used by vendor modules for handling events from driver
 *
 */
void * soncmnGetLbdEventHandler(void);

/**
 * @brief Function called by LBD to provide Event Handler
 *        pointer to SON Lib, used later to handle events
 *
 * @param [in] evHandler   opaque pointer to LBD event Handler
 *
 */
extern void soncmnSetLbdEventHandler(void *evHandler);

/**
 * @brief Function to create ifname, vendor, drvHandle mappings
 *        Called by HYD/LBD during its Init. Goes through list of
 *        ifnames in config file, creating corresponding drvHandles
 *
 * @param [in] wlanInterfaces wlanIfname-to-radio mapping from config file
 * @param [in] radioVendorMap  radio-to-vendor mapping from config file
 * @param [in] isHYD  flag to indicate if HYD is running
 * @param [in] isLBD  flag to indicate if LBD/WLB is running
 *
 */
extern void soncmnIfnameVendorMapResolve(const char*, const char*, uint8_t, uint8_t);

/**
 * @brief Function to get DrvHandle for a given Ifname
 *
 * @param [in] ifname  wlan interface name
 *
 * @return Driver Handle for this ifname
 *
 */
extern struct soncmnDrvHandle * soncmnGetDrvHandleFromIfname(const char *);

/**
 * @brief Function to get Vendor name for a given Ifname
 *
 * @param [in] ifname  wlan interface name
 *
 * @return Vendor integer as per enum soncmnVendors
 *
 */
extern enum soncmnVendors soncmnGetVendorFromIfname(const char *ifname);

/**
 * @brief Function to get Vendor name for a given Radio Name
 *
 * @param [in] ifname  wlan radio name (wifi0, wifi1..)
 *
 * @return Vendor integer as per enum soncmnVendors
 *
 */
extern enum soncmnVendors soncmnGetVendorFromRadioName(const char *radioName);

/**
 * @brief Function to free up memory for DrvHandle
 *        and any private memory allocated by vendor
 *        by calling vendor specific deInit
 *
 * @param [in] drvHandle  vendor specific drvHandle
 *
 */
extern void soncmnDeinit(struct soncmnDrvHandle *);

/***************************************************************/
/************ Enums used by SON modules ************************/
/***************************************************************/

#define MAX_VAP_PER_BAND 16
#define INTFNAMESIZE 16 /* if name, e.g. "en0" */
#define MAX_RADIOS 3 /* Max tri-radio platforms */
#define MIN_NUM_IFACES 2 /* Minimum 1 interface per band (2G and 5G) */


#endif /* #define __SONLIB_CMN_H__ */
