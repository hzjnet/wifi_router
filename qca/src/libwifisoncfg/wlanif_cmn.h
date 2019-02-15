/*
 * Copyright (c) 2017 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

struct wlanif_config{
    void *ctx;
    uint32_t IsCfg80211;
    struct wlanif_config_ops *ops;
};

struct wlanif_config_ops {
    int (* init) (struct wlanif_config *wext_conf);
    void (* deinit) (struct wlanif_config *wext_conf);
    int (* getName) (void *,const char *, char *);
    int (* isAP) (void *, const char *, uint32_t *);
    int (* getBSSID) (void *, const char *, struct ether_addr *BSSID );
    int (* getESSID) (void *, const const char * , void *, uint32_t * );
    int (* getFreq) (void *, const char * , int32_t * freq);
    int (* getChannelWidth) (void *, const char *, int *);
    int (* getChannelExtOffset) (void *, const char *, int *);
    int (* getChannelBandwidth) (void *, const char *, int *);
    int (* getAcsState) (void *, const char *, int *);
    int (* getCacState) (void *, const char *, int *);
    int (* getParentIfindex) (void *, const char *, int *);
    int (* getSmartMonitor) (void *, const char *, int *);
    int (* getGenericInfoAtf) (void *, const char *, int, void *, int);
    int (* getGenericInfoAld) (void *, const char *, void *, int);
    int (* getGenericHmwds) (void *, const char *, void *, int);
    int (* getGenericNac) (void *, const char *, void *, int);
    int (* getCfreq2) (void *, const char * , int32_t *);
    int (* getChannelInfo) (void *, const char *, void *, int);
    int (* getChannelInfo160) (void *, const char *, void *, int);
    int (* getStationInfo) (void *, const char *, void *, int *);
    int (* getDbgreq) (void *, const char *, void *, uint32_t);
    int (* getExtended) (void *, const char *, void *, uint32_t);
    int (* addDelKickMAC) (void *, const char *, int , void *, uint32_t);
    int (* setFilter) (void *, const char *, void *, uint32_t);
    int (* getWirelessMode)(void *, const char *, void *, uint32_t);
    int (* sendMgmt) (void *, const char *, void *, uint32_t);
    int (* setParamMaccmd)(void *, const char *, void *, uint32_t);
    int (* setParam)(void *, const char *,int, void *, uint32_t);
    int (* getStaStats)(void *, const char *, void *, uint32_t);
};

/*enum to handle MAC operations*/
enum wlanif_ioops_t
{
    IO_OPERATION_ADDMAC=0,
    IO_OPERATION_DELMAC,
    IO_OPERATION_KICKMAC
};

/* enum to handle wext/cfg80211 mode*/
enum wlanif_cfg_mode {
    WLANIF_CFG80211=0,
    WLANIF_WEXT
};

extern struct wlanif_config * wlanif_config_init(enum wlanif_cfg_mode mode);
extern void wlanif_config_deinit(struct wlanif_config *);
