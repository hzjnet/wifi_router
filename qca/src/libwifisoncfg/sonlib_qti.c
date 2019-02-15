/*
 * Copyright (c) 2017 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

/* SON Libraries - Vendor specific module file */
/* This implements SON library APIs            */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <asm/types.h>
#include <linux/socket.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <assert.h>

#include <sys/types.h>
#include <net/if.h>
#include <net/ethernet.h>
#define _LINUX_IF_H /* Avoid redefinition of stuff */
#include <linux/wireless.h>
#include <linux/netlink.h>
#include <linux/if.h>

#include "sonlib_cmn.h"
#include "ieee80211_external.h"

#define DEBUG

#ifdef DEBUG
#define TRACE_ENTRY() dbgf(soncmnDbgS.dbgModule, DBGDUMP,"%s: Enter ",__func__)
#define TRACE_EXIT() dbgf(soncmnDbgS.dbgModule, DBGDUMP, "%s: Exit ",__func__)
#define TRACE_EXIT_ERR() dbgf(soncmnDbgS.dbgModule, DBGERR, "%s: Exit with err %d",__func__,ret)
#else
#define TRACE_ENTRY()
#define TRACE_EXIT()
#define TRACE_EXIT_ERR()
#endif

//MAC address print marcos
#define qtiMACAddFmt(_sep) "%02X" _sep "%02X" _sep "%02X" _sep "%02X" _sep "%02X" _sep "%02X"
#define qtiMACAddData(_arg) __qtiMidx(_arg, 0), __qtiMidx(_arg, 1), __qtiMidx(_arg, 2), \
                             __qtiMidx(_arg, 3), __qtiMidx(_arg, 4), __qtiMidx(_arg, 5)
#define __qtiMidx(_arg, _i) (((uint8_t *)_arg)[_i])

#define qtiCopyMACAddr(src, dst) memcpy( dst, src, ETH_ALEN )
#define ARPHRD_ETHER_FAMILY    1

#ifdef QCA_PARTNER_PLATFORM
extern size_t strlcpy(char *dest_addr, const char *src_addr, size_t size);
#endif

static void eventUnregister_qti(void);
static void eventRegister_qti(void);
static int enableBSteerEvents_qti(uint32_t sysIndex);

/* QTI private structure */
struct priv_qti {
    int32_t Sock;  // Socket for ioctls to driver
};

/* Structure to handle events from driver */
static struct eventHandler_t
{
    uint8_t isInit;                /* Flag to check if Init was done */
    int32_t lbdNLSocket;           /* lbd netlink socket */
    struct bufrd lbdReadBuf;       /* for reading from - lbd BSteering */
} eventHandler;


/**
 * @brief Function to create socket for ioctls to wlan driver
 *
 * @param [in] priv  private vendor structure
 *
 * @return Success: 0, Failure: -1
 */
static inline int sockInit_qti(struct priv_qti * priv)
{
    int ret;

    if ((ret = priv->Sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        goto out;
    }

    if ((ret = fcntl(priv->Sock, F_SETFL, fcntl(priv->Sock, F_GETFL) | O_NONBLOCK))) {
        goto err;
    }

    return 0;
err:
    close(priv->Sock);
out:
    return -1;
}


/**
 * @brief Callback function to handle events from wlan driver
 *        Reads event buffer and calls LBD event handler
 *
 */
static void lbdBSteerEventsBufRdCB(void * cookie)
{
    u_int32_t numBytes;
    const u_int8_t *msg;

    numBytes = bufrdNBytesGet(&eventHandler.lbdReadBuf);
    msg = bufrdBufGet(&eventHandler.lbdReadBuf);

    do {
        if (bufrdErrorGet(&eventHandler.lbdReadBuf)) {
            dbgf(soncmnDbgS.dbgModule, DBGERR, "%s: Read error! # bytes=%u",
                 __func__, numBytes);

            eventUnregister_qti();
            eventRegister_qti();
            return;
        }

        if (!numBytes) {
            return;
        }

        const struct nlmsghdr *hdr = (const struct nlmsghdr *) msg;
        if (numBytes < sizeof(struct nlmsghdr) +
                       sizeof(ath_netlink_bsteering_event_t) ||
            hdr->nlmsg_len < sizeof(ath_netlink_bsteering_event_t)) {
            dbgf(soncmnDbgS.dbgModule, DBGERR, "%s: Invalid message len: %u bytes",
                 __func__, numBytes);
            break;
        }

        const ath_netlink_bsteering_event_t *event = NLMSG_DATA(hdr);
        wlanifBSteerEventsHandle_t lbdEvHandle =
            (wlanifBSteerEventsHandle_t ) soncmnGetLbdEventHandler();
        wlanifBSteerEventsMsgRx(lbdEvHandle, event);
    } while (0);

    bufrdConsume(&eventHandler.lbdReadBuf, numBytes);
}


/**
 * @brief Function to register event handler for LBD
 *        Opens Netlink socket to recieve events from driver
 *
 */
static void eventRegister_qti()
{
    if (eventHandler.isInit) {
        return;
    }
    eventHandler.lbdNLSocket = -1;

    eventHandler.lbdNLSocket = socket(PF_NETLINK, SOCK_RAW,
                                  NETLINK_BAND_STEERING_EVENT);
    if (-1 == eventHandler.lbdNLSocket) {
        dbgf(soncmnDbgS.dbgModule, DBGERR, "%s: Netlink socket creation failed",__func__);
        return;
    }

    struct sockaddr_nl addr;
    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = getpid();
    addr.nl_groups = 0;  // using unicast for now

    if (-1 == bind(eventHandler.lbdNLSocket, (const struct sockaddr *) &addr,
                   sizeof(addr))) {
        dbgf(soncmnDbgS.dbgModule, DBGERR, "%s: Failed to bind netlink socket",__func__);
        close(eventHandler.lbdNLSocket);
        eventHandler.lbdNLSocket = -1;
        return;
    }

    u_int32_t bufferSize = NLMSG_SPACE(sizeof(struct nlmsghdr) +
                                       sizeof(struct ath_netlink_bsteering_event));

    bufrdCreate(&eventHandler.lbdReadBuf, "soncmnBSteerEvents-rd",
                eventHandler.lbdNLSocket, bufferSize,
                lbdBSteerEventsBufRdCB, NULL);
    eventHandler.isInit = 1;
    dbgf(soncmnDbgS.dbgModule, DBGINFO, "%s: Event Handler was successfully created", __func__);
    return;
}

/**
 * @brief Function to tear down Netlink socket for event handling
 *
 */
static void eventUnregister_qti()
{
    if (eventHandler.lbdNLSocket != -1)
    {
        close(eventHandler.lbdNLSocket);
        bufrdDestroy(&eventHandler.lbdReadBuf);
        eventHandler.lbdNLSocket = -1;
    }
    return;
}


/**
 * @brief Function to close Socket created for ioctls to driver
 *
 * @param [in] priv  private vendor structure
 *
 */
static inline void sockClose_qti(struct priv_qti * priv)
{
    close(priv->Sock);
}

/********************************************************************/
/************************ Southbound APIs ***************************/
/********************************************************************/

/**
 * @brief Function to get name of the device
 *
 * @param [in] ctx     opaque pointer to private vendor struct
 * @param [in] ifname  interface name
 *
 * @param [out] name   char pointer, filled by this function for
 *                     name of protocol
 *
 * @return Success: 0, Failure: -1
 *
 */
static int getName_qti(const void *ctx, const char * ifname, char *name, size_t len )
{
    struct iwreq Wrq;
    int ret;
    struct priv_qti * priv;

    TRACE_ENTRY();

    priv = (struct priv_qti *) ctx;
    assert(priv != NULL);

    strlcpy( Wrq.ifr_name, ifname, IFNAMSIZ );

    if ((ret = ioctl(priv->Sock, SIOCGIWNAME, &Wrq)) < 0) {
        goto err;
    }

    strlcpy( name, ifname, len );

    TRACE_EXIT();

    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}


/**
 * @brief Function to get BSSID address
 *
 * @param [in] ctx     opaque pointer to private vendor struct
 * @param [in] ifname  interface name
 *
 * @param [out] bssid  bssid pointer to be filled by this function
 *                     with BSSID address
 *
 * @return Success: 0, Failure: -1
 *
 */
static int getBSSID_qti(const void *ctx, const char * ifname, struct ether_addr *bssid )
{
    struct iwreq Wrq;
    int ret;
    struct priv_qti * priv;

    TRACE_ENTRY();

    priv = (struct priv_qti *) ctx;
    assert(priv != NULL);

    strlcpy(Wrq.ifr_name, ifname, IFNAMSIZ );

    if ((ret = ioctl(priv->Sock, SIOCGIWAP, &Wrq)) < 0) {
        goto err;
    }

    memcpy( bssid, &Wrq.u.ap_addr.sa_data, ETH_ALEN );

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

/**
 * @brief Function to get SSID info
 *
 * @param [in] ctx     opaque pointer to private vendor struct
 * @param [in] ifname  interface name
 *
 * @param [out] buf    ssid pointer to be filled by this function
 *                     with SSID name
 * @param [out] len    length pointer to be filled by this function
 *                     with length of SSID
 *
 * @return Success: 0, Failure: -1
 *
 */
static int getSSID_qti(const void *ctx, const const char * ifname, void *buf, uint32_t *len )
{
    struct iwreq Wrq;
    int ret;
    struct priv_qti * priv;

    TRACE_ENTRY();

    priv = (struct priv_qti *) ctx;
    assert(priv != NULL);

    memset(&Wrq, 0, sizeof(Wrq));
    strlcpy(Wrq.ifr_name, ifname, IFNAMSIZ );
    Wrq.u.data.pointer = buf;
    Wrq.u.data.length = *len;

    if ((ret = ioctl(priv->Sock, SIOCGIWESSID, &Wrq)) < 0) {
        goto err;
    }

    /* Update the ssid length if the ioctl succeeds */
    *len = Wrq.u.data.length;

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

/**
 * @brief Function to check whether the current device is AP
 *
 * @param [in] ctx     opaque pointer to private vendor struct
 * @param [in] ifname  interface name
 *
 * @param [out] result result pointer to be filled by this function
 *                     set to 1 if device is AP, else 0
 *
 * @return Success: 0, Failure: -1
 *
 */
static int isAP_qti(const void *ctx, const char * ifname, uint32_t *result)
{
    int ret;
    struct iwreq Wrq;
    struct priv_qti * priv;

    TRACE_ENTRY();

    priv = (struct priv_qti *) ctx;
    assert(priv != NULL);

    *result = 0;

    strlcpy(Wrq.ifr_name, ifname, IFNAMSIZ );

    if ((ret = ioctl(priv->Sock, SIOCGIWMODE, &Wrq)) < 0) {
        goto err;
    }

    *result = (Wrq.u.mode == IW_MODE_MASTER ? 1 : 0);

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

/**
 * @brief Function to get frequency info
 *
 * @param [in] ctx     opaque pointer to private vendor struct
 * @param [in] ifname  interface name
 *
 * @param [out] freq   frequency pointer to be filled by this function
 *                     with frequency value in Hz
 *
 * @return Success: 0, Failure: -1
 *
 */
static int getFreq_qti(const void *context, const char * ifname, int32_t * freq)
{
    int ret;
    struct iwreq Wrq;
    struct priv_qti * priv;

    TRACE_ENTRY();

    priv = (struct priv_qti *) context;
    assert(priv != NULL);

    strlcpy(Wrq.ifr_name, ifname, IFNAMSIZ );
    if ((ret = ioctl(priv->Sock, SIOCGIWFREQ, &Wrq)) < 0) {
        goto err;
    }

    *freq = Wrq.u.freq.m;

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}


/**
 * @brief Function to get Interface Flags state
 *
 * @param [in] ctx     opaque pointer to private vendor struct
 * @param [in] ifname  interface name
 *
 * @param [out] ifr    pointer to ifreq struct, to be filled by
 *                     this function with interface flags
 *
 * @return Success: 0, Failure: -1
 *
 */
static int getIfFlags_qti(const void *ctx, const const char *ifname , struct ifreq *ifr )
{
    int ret;
    struct priv_qti * priv;

    TRACE_ENTRY();

    priv = (struct priv_qti *) ctx;
    assert(priv != NULL);

    if ((ret = ioctl(priv->Sock, SIOCGIFFLAGS, ifr)) < 0) {
        goto err;
    }

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

/**
 * @brief Function to get ACS State
 *
 * @param [in] ctx       opaque pointer to private vendor struct
 * @param [in] ifname    interface name
 *
 * @param [out] acsstate pointer to be filled by this function
 *                       ACS State (non-zero means ACS still in
 *                       progress, 0: ACS is done)
 *
 * @return Success: 0, Failure: -1
 *
 */
static int getAcsState_qti(const void * ctx, const char *ifname, int * acsstate)
{
    int ret,iwparam;
    struct iwreq Wrq;
    struct priv_qti * priv;

    TRACE_ENTRY();

    priv = (struct priv_qti *) ctx;
    assert(priv != NULL);

    strlcpy(Wrq.ifr_name, ifname, IFNAMSIZ );
    iwparam = IEEE80211_PARAM_GET_ACS;
    memcpy(Wrq.u.name, &iwparam, sizeof(iwparam));
    if ((ret = ioctl(priv->Sock, IEEE80211_IOCTL_GETPARAM, &Wrq)) < 0) {
        goto err;
    }
    memcpy(acsstate, Wrq.u.name, sizeof(int));

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

/**
 * @brief Function to get CAC State
 *
 * @param [in] ctx       opaque pointer to private vendor struct
 * @param [in] ifname    interface name
 *
 * @param [out] cacstate pointer to be filled by this function
 *                       CAC State (non-zero means CAC still in
 *                       progress, 0: CAC is done)
 *
 * @return Success: 0, Failure: -1
 *
 */
static int getCacState_qti(const void * ctx, const char *ifname, int * cacstate)
{
    int ret,iwparam;
    struct iwreq Wrq;
    struct priv_qti * priv;

    TRACE_ENTRY();

    priv = (struct priv_qti *) ctx;
    assert(priv != NULL);

    strlcpy(Wrq.ifr_name, ifname, IFNAMSIZ );
    iwparam = IEEE80211_PARAM_GET_CAC;
    memcpy(Wrq.u.name, &iwparam, sizeof(iwparam));
    if ((ret = ioctl(priv->Sock, IEEE80211_IOCTL_GETPARAM, &Wrq)) < 0) {
        goto err;
    }
    memcpy(cacstate, Wrq.u.name, sizeof(int));

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;

}

/**
 * @brief Common function to send all DBGReq ioctls
 *          for various set and get subcommands
 *
 * @param [in] ctx    opaque pointer to private vendor struct
 * @param [in] ifname interface name
 * @param [in] data   data for ioctl
 * @param [in] len    length of the data
 *
 * @return Success: 0, Failure: -1
 *
 */
static int sendDbgReqSetCmn(const void * ctx , const char *ifname, void *data , uint32_t data_len)
{
    struct iwreq iwr;
    int ret;
    struct priv_qti * priv;

    TRACE_ENTRY();

    priv = (struct priv_qti *) ctx;
    assert(priv != NULL);

    strlcpy(iwr.ifr_name, ifname, IFNAMSIZ);

    iwr.u.data.pointer = data;
    iwr.u.data.length = data_len;
    if(( ret = ioctl( priv->Sock, IEEE80211_IOCTL_DBGREQ, &iwr )) < 0 )
    {
        goto err;
    }

    TRACE_EXIT();
    return 0;
err:
    TRACE_EXIT_ERR();
    return ret;
}

/**
 * @brief Function to update whether authentication
 *          should be allowed for a given MAC or not
 *
 * @param [in] context   opaque pointer to private vendor struct
 * @param [in] ifname    interface name
 * @param [in] destAddr  stamac for which Auth will be allowed/disallowed
 * @param [in] authAllow flag, 1: allow Auth, 0: not allow Auth
 *
 * @return Success: 0, Failure: -1
 *
 */
static int setBSteerAuthAllow_qti (const void *context, const char *ifname,
                               const uint8_t *destAddr, uint8_t authAllow)
{
    struct ieee80211req_athdbg req;
    TRACE_ENTRY();
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));

    assert(destAddr != NULL);
    qtiCopyMACAddr(destAddr, req.dstmac);

    req.cmd = IEEE80211_DBGREQ_BSTEERING_SET_AUTH_ALLOW;
    memcpy(&req.data, &authAllow, sizeof(authAllow));
    return sendDbgReqSetCmn(context, ifname, &req, sizeof(struct ieee80211req_athdbg));
}

/**
 * @brief Function to Enable/Disable probe responses
 *          withholding for a given MAC
 *
 * @param [in] context   opaque pointer to private vendor struct
 * @param [in] ifname    interface name
 * @param [in] destAddr stamac for which enable/disable probe resp withholding
 * @param [in] probeRespWHEnable flag, 1: Enable Withholding, 0: Disable withholding
 *
 * @return Success: 0, Failure: -1
 *
 */
static int setBSteerProbeRespWH_qti (const void *context, const char *ifname,
                             const uint8_t *destAddr, uint8_t probeRespWHEnable)
{
    struct ieee80211req_athdbg req;
    TRACE_ENTRY();
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));

    assert(destAddr != NULL);
    qtiCopyMACAddr(destAddr, req.dstmac);

    req.cmd = IEEE80211_DBGREQ_BSTEERING_SET_PROBE_RESP_WH;
    memcpy(&req.data, &probeRespWHEnable, sizeof(probeRespWHEnable));
    return sendDbgReqSetCmn(context, ifname, &req, sizeof(struct ieee80211req_athdbg));
}

/**
 * @brief Function to update whether probe responses
 *        should be allowed or not for a MAC in 2.4G band
 *
 * @param [in] context   opaque pointer to private vendor struct
 * @param [in] ifname    interface name
 * @param [in] destAddr stamac for which enable/disable 2G probe response
 * @param [in] allowProbeResp2G  flag, 1: Enable probe resp, 0: Disable probe resp
 *
 * @return Success: 0, Failure: -1
 *
 */
static int setBSteerProbeRespAllow2G_qti (const void *context, const char *ifname,
                              const uint8_t *destAddr, uint8_t allowProbeResp2G)
{
    struct ieee80211req_athdbg req;
    TRACE_ENTRY();
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));

    assert(destAddr != NULL);
    qtiCopyMACAddr(destAddr, req.dstmac);

    req.cmd = IEEE80211_DBGREQ_BSTEERING_SET_PROBE_RESP_ALLOW_24G;
    memcpy(&req.data, &allowProbeResp2G, sizeof(allowProbeResp2G));
    return sendDbgReqSetCmn(context, ifname, &req, sizeof(struct ieee80211req_athdbg));
}

/**
 * @brief Function to toggle a VAP's overloaded status based
 *          on channel utilization and thresholds
 *
 * @param [in] context   opaque pointer to private vendor struct
 * @param [in] ifname    interface name
 * @param [in] setOverload flag, 1: Set overload status, 0: Clear overload
 *
 * @return Success: 0, Failure: -1
 *
 */
static int setBSteerOverload_qti (const void *context, const char *ifname, uint8_t setOverload)
{
    struct ieee80211req_athdbg req;
    TRACE_ENTRY();
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));

    req.cmd = IEEE80211_DBGREQ_BSTEERING_SET_OVERLOAD;
    memcpy(&req.data, &setOverload, sizeof(setOverload));
    return sendDbgReqSetCmn(context, ifname, &req, sizeof(struct ieee80211req_athdbg));
}

/**
 * @brief Function to cleanup all STA state (equivalent to
 *        disassociation, without sending the frame OTA)
 *
 * @param [in] context   opaque pointer to private vendor struct
 * @param [in] ifname    interface name
 * @param [in] destAddr sta addr which needs cleanup
 *
 * @return Success: 0, Failure: -1
 *
 */
static int performLocalDisassoc_qti (const void *context, const char *ifname, const uint8_t *destAddr)
{
    struct ieee80211req_athdbg req;
    TRACE_ENTRY();
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));

    assert(destAddr != NULL);
    qtiCopyMACAddr(destAddr, req.dstmac);

    req.cmd = IEEE80211_DBGREQ_BSTEERING_LOCAL_DISASSOCIATION;
    return sendDbgReqSetCmn(context, ifname, &req, sizeof(struct ieee80211req_athdbg));
}

/**
 * @brief Function to enable Band Steering on per radio
 *
 * @param [in] context   opaque pointer to private vendor struct
 * @param [in] ifname    interface name
 * @param [in] bSteerEnable flag, 1: Enable BSteering, 0: Disable BSteering
 *
 * @return Success: 0, Failure: -1
 *
 */
static int setBSteering_qti(const void *context, const char *ifname, uint8_t bSteerEnable)
{
    struct ieee80211req_athdbg req;
    TRACE_ENTRY();
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));

    req.cmd = IEEE80211_DBGREQ_BSTEERING_ENABLE;
    memcpy(&req.data, &bSteerEnable, sizeof(bSteerEnable));
    return sendDbgReqSetCmn(context, ifname, &req, sizeof(struct ieee80211req_athdbg));
}

/**
 * @brief Function to enable or disable band steering on a VAP
 *
 * @param [in] context   opaque pointer to private vendor struct
 * @param [in] ifname    interface name
 * @param [in] bSteerEventsEnable flag, 1: Enable, 0: Disable
 *
 * @return Success: 0, Failure: -1
 *
 */
static int setBSteerEvents_qti (const void *context, const char *ifname, uint8_t bSteerEventsEnable)
{
    struct ieee80211req_athdbg req;
    int ret;
    TRACE_ENTRY();
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));

    req.cmd = IEEE80211_DBGREQ_BSTEERING_ENABLE_EVENTS;
    memcpy(&req.data, &bSteerEventsEnable, sizeof(bSteerEventsEnable));
    ret = sendDbgReqSetCmn(context, ifname, &req, sizeof(struct ieee80211req_athdbg));

    /* if the state is already set, don't treat it as error */
    if(ret !=  0 && errno == EALREADY) {
        return SONCMN_OK;
    }
    //Print for debug
    if (ret != 0) {
        dbgf(soncmnDbgS.dbgModule, DBGERR, "%s: Enable/Disable BSteering on vap: %s returned errno: %d",
                   __func__, ifname, errno);
    }

    return ret;
}

/**
 * @brief Function to set/unset band steering in-progress flag for a STA
 *
 * @param [in] context   opaque pointer to private vendor struct
 * @param [in] ifname    interface name
 * @param [in] destAddr stamac for which steering-in-progress flag needs
 *                       to be set/unset
 * @param [in] bSteerInProgress flag, 1: Set, 0: Unset/Clear
 *
 * @return Success: 0, Failure: -1
 *
 */
static int setBSteerInProgress_qti(const void *context, const char *ifname,
                             const uint8_t *destAddr, uint8_t bSteerInProgress)
{
    struct ieee80211req_athdbg req;
    TRACE_ENTRY();
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));

    assert(destAddr != NULL);
    qtiCopyMACAddr(destAddr, req.dstmac);

    req.cmd = IEEE80211_DBGREQ_BSTEERING_SET_STEERING;
    memcpy(&req.data, &bSteerInProgress, sizeof(bSteerInProgress));
    return sendDbgReqSetCmn(context, ifname, &req, sizeof(struct ieee80211req_athdbg));
}

/**
 * @brief Function to set static band steering config parameters
 *
 * @param [in] context   opaque pointer to private vendor struct
 * @param [in] ifname    interface name
 * @param [in] data      data to be passed to driver (bsteering params)
 * @param [in] data_len  length of the data (here sizeof(struct
 *                       ieee80211_bsteering_param_t)
 *
 * @return Success: 0, Failure: -1
 *
 */
static int setBSteerParams_qti(const void *context, const char *ifname, void *data, uint32_t data_len)
{
    struct ieee80211req_athdbg req;
    TRACE_ENTRY();
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));

    req.cmd = IEEE80211_DBGREQ_BSTEERING_SET_PARAMS;
    memcpy(&req.data, data, data_len);
    return sendDbgReqSetCmn(context, ifname, &req, sizeof(struct ieee80211req_athdbg));
}

/**
 * @brief Function to indicate driver that SON wants RSSI info for a STA
 *
 * @param [in] context    opaque pointer to private vendor struct
 * @param [in] ifname     interface name
 * @param [in] destAddr  sta mac for which RSSI is requested
 * @param [in] numSamples number of samples to collect for RSSI reporting
 *
 * @return Success: 0, Failure: -1
 *
 */
static int getBSteerRSSI_qti (const void * context,
                               const char * ifname,
                               const uint8_t *destAddr, uint8_t numSamples)
{
    struct ieee80211req_athdbg req;
    TRACE_ENTRY();
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));

    assert(destAddr != NULL);
    qtiCopyMACAddr(destAddr, req.dstmac);

    req.cmd = IEEE80211_DBGREQ_BSTEERING_GET_RSSI;
    memcpy(&req.data, &numSamples, sizeof(numSamples));
    return sendDbgReqSetCmn(context, ifname, &req, sizeof(struct ieee80211req_athdbg));
}

/**
 * @brief Function to send Beacon report request (802.11k)
 *
 * @param [in] context    opaque pointer to private vendor struct
 * @param [in] ifname     interface name
 * @param [in] destAddr  destination mac for Beacon request
 * @param [in] bcnreq     data for Beacon request
 *
 * @return Success: 0, Failure: -1
 *
 */
static int sendBcnRptReq_qti (const void * context, const char * ifname,
        const uint8_t *destAddr, struct soncmn_ieee80211_rrm_beaconreq_info_t *bcnreq)
{
    struct ieee80211req_athdbg req;
    TRACE_ENTRY();
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));

    assert(destAddr != NULL);
    qtiCopyMACAddr(destAddr, req.dstmac);

    req.cmd = IEEE80211_DBGREQ_SENDBCNRPT;
    memcpy(&req.data, bcnreq, sizeof(struct soncmn_ieee80211_rrm_beaconreq_info_t));
    return sendDbgReqSetCmn(context, ifname, &req, sizeof(struct ieee80211req_athdbg));
}

/**
 * @brief Function to send BTM request (802.11v)
 *
 * @param [in] context    opaque pointer to private vendor struct
 * @param [in] ifname     interface name
 * @param [in] destAddr  destination mac for BTM request
 * @param [in] btmreq     data for BTM request
 *
 * @return Success: 0, Failure: -1
 *
 */
static int sendBTMReq_qti (const void * context, const char * ifname,
        const uint8_t *destAddr, struct soncmn_ieee80211_bstm_reqinfo_target *btmreq)
{
    struct ieee80211req_athdbg req;
    TRACE_ENTRY();
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));

    //Copy BTM req info to QCA driver BTM req structure
    struct ieee80211_bstm_reqinfo_target reqinfo;
    int i;
    memset(&reqinfo, 0, sizeof(struct ieee80211_bstm_reqinfo_target));

    reqinfo.dialogtoken = btmreq->dialogtoken;
    reqinfo.num_candidates = btmreq->num_candidates;
#if QCN_IE
    reqinfo.qcn_trans_reason = btmreq->qcn_trans_reason;
#endif
    reqinfo.trans_reason = btmreq->trans_reason;
    reqinfo.disassoc = btmreq->disassoc;
    reqinfo.disassoc_timer = (u_int16_t) btmreq->disassoc_timer;
    for (i = 0; i < btmreq->num_candidates; i++) {
        qtiCopyMACAddr(&btmreq->candidates[i].bssid, &reqinfo.candidates[i].bssid);
        reqinfo.candidates[i].channel_number = btmreq->candidates[i].channel_number;
        reqinfo.candidates[i].preference = btmreq->candidates[i].preference;
        reqinfo.candidates[i].op_class = btmreq->candidates[i].op_class;
        reqinfo.candidates[i].phy_type = btmreq->candidates[i].phy_type;
        dbgf(soncmnDbgS.dbgModule, DBGINFO, "%s: Sending BTM request to " qtiMACAddFmt(":")
                " Target BSSID " qtiMACAddFmt(":") " ", __func__,
                qtiMACAddData(destAddr), qtiMACAddData(reqinfo.candidates[i].bssid));
    }

    assert(destAddr != NULL);
    qtiCopyMACAddr(destAddr, req.dstmac);

    req.cmd = IEEE80211_DBGREQ_SENDBSTMREQ_TARGET;
    memcpy(&req.data, &reqinfo, sizeof(struct ieee80211_bstm_reqinfo_target));
    return sendDbgReqSetCmn(context, ifname, &req, sizeof(struct ieee80211req_athdbg));
}


/**
 * @brief Function to get Data rate Info for a Station or VAP
 *
 * @param [in] context    opaque pointer to private vendor struct
 * @param [in] ifname     interface name
 * @param [in] destAddr  sta mac for which data rate info is requested
 * @param [in] datarateInfo pointer to data, to be filled by this function
 *
 * @return Success: 0, Failure: -1
 *
 */
static int getDataRateInfo_qti (const void * context, const char * ifname,
       const uint8_t *destAddr, struct soncmn_ieee80211_bsteering_datarate_info_t *datarateInfo)
{
    struct ieee80211req_athdbg req;
    TRACE_ENTRY();
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));

    assert(destAddr != NULL);
    qtiCopyMACAddr(destAddr, req.dstmac);

    req.cmd = IEEE80211_DBGREQ_BSTEERING_GET_DATARATE_INFO;
    memcpy(&req.data, datarateInfo, sizeof(struct soncmn_ieee80211_bsteering_datarate_info_t));
    if (sendDbgReqSetCmn(context, ifname, &req, sizeof(struct ieee80211req_athdbg)) == 0 ) {
        memcpy(datarateInfo, &req.data, sizeof(struct soncmn_ieee80211_bsteering_datarate_info_t));
        return 0;
    }
    return -1;
}

/**
 * @brief Function to get associated Station information
 *
 * @param [in] context    opaque pointer to private vendor struct
 * @param [in] ifname     interface name
 * @param [in] getStaInfo pointer to StaInfo data, to be filled by this function
 *
 * @return Success: 0, Failure: -1
 *
 */
static int getStaInfo_qti (const void * context, const char * ifname, struct soncmn_req_stainfo_t *getStaInfo)
{
    int i;
    struct priv_qti * priv;
    u_int8_t *buf = NULL;
    int length = 0;
#define LIST_STATION_IOC_ALLOC_SIZE 24*1024

    TRACE_ENTRY();

    length = LIST_STATION_IOC_ALLOC_SIZE;
    buf = malloc(length);
    if (!buf) {
        dbgf(soncmnDbgS.dbgModule, DBGERR, "%s: Failed to allocate buffer for iface %s", __func__, ifname);
        return SONCMN_NOK;
    }

    priv = (struct priv_qti *) context;
    assert(priv != NULL);

    SONCMN_STATUS result = SONCMN_OK;

    do {
        struct iwreq iwr;
        memset(&iwr, 0, sizeof(iwr));
        strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = LIST_STATION_IOC_ALLOC_SIZE;

        if (ioctl(priv->Sock, IEEE80211_IOCTL_STA_INFO, &iwr) < 0) {

            dbgf(soncmnDbgS.dbgModule, DBGERR, "%s: Failed to perform ioctl for iface %s", __func__, ifname);
            result = SONCMN_NOK;
            break;
        }

        // Loop over all of the STAs, getting PHY and other capability information
        u_int8_t *currentPtr = buf;
        //u_int8_t *endPtr = buf + length;
        u_int8_t *endPtr = buf + iwr.u.data.length;
        dbgf(soncmnDbgS.dbgModule, DBGINFO, "%s: Station info length %d",__func__, iwr.u.data.length);
        i = 0;
        getStaInfo->numSta = 0;
        while (currentPtr + sizeof(struct ieee80211req_sta_info) <= endPtr) {
            const struct ieee80211req_sta_info *staInfo =
                (const struct ieee80211req_sta_info *) currentPtr;
            struct ether_addr addr;
            qtiCopyMACAddr(staInfo->isi_macaddr, addr.ether_addr_octet);

            ieee80211_bsteering_datarate_info_t datarateInfo;
            memset(&datarateInfo, 0, sizeof(ieee80211_bsteering_datarate_info_t));

            struct ieee80211req_athdbg req;
            memset(&req, 0, sizeof(struct ieee80211req_athdbg));
            qtiCopyMACAddr(&addr, req.dstmac);

            req.cmd = IEEE80211_DBGREQ_BSTEERING_GET_DATARATE_INFO;
            memcpy(&req.data, &datarateInfo, sizeof(struct ieee80211_bsteering_datarate_info_t));
            getStaInfo->stainfo[i].phy_cap_valid = 0;
            getStaInfo->stainfo[i].isbtm = 0;
            getStaInfo->stainfo[i].isrrm = 0;
            if (SONCMN_OK == sendDbgReqSetCmn(context, ifname, &req, sizeof(struct ieee80211req_athdbg)))
            {
                getStaInfo->stainfo[i].phy_cap_valid = 1;
                dbgf(soncmnDbgS.dbgModule, DBGINFO, "%s: Got valid station PHY capabilities",__func__);
                memcpy(&getStaInfo->stainfo[i].datarateInfo,
                   &req.data, sizeof(struct ieee80211_bsteering_datarate_info_t));
            }

            qtiCopyMACAddr(staInfo->isi_macaddr, getStaInfo->stainfo[i].stamac);
            getStaInfo->numSta++;
            getStaInfo->stainfo[i].isbtm = ((staInfo->isi_ext_cap & IEEE80211_EXTCAPIE_BSSTRANSITION) ? 1 : 0);
            getStaInfo->stainfo[i].isrrm = ((staInfo->isi_capinfo & IEEE80211_CAPINFO_RADIOMEAS) ? 1 : 0);

            getStaInfo->stainfo[i].operating_band = staInfo->isi_operating_bands;
            getStaInfo->stainfo[i].rssi = staInfo->isi_rssi;

            /* Get next STA record */
            i++;
            currentPtr += staInfo->isi_len;
        }
    } while (0);
    free(buf);
    return result;
}

/**
 * @brief Function to get Station statistics
 *
 * @param [in] context    opaque pointer to private vendor struct
 * @param [in] ifname     interface name
 * @param [in] destAddr  sta mac for which stats is requested
 * @param [in] stats      pointer to stats, to be filled by this function
 *
 * @return Success: 0, Failure: -1
 *
 */
static int getStaStats_qti(const void * ctx , const char *ifname,
       const uint8_t *destAddr , struct soncmn_staStatsSnapshot_t *stats)
{
    struct iwreq iwr;
    int ret;
    struct priv_qti * priv;
    struct ieee80211req_sta_stats sta_stats;

    TRACE_ENTRY();

    priv = (struct priv_qti *) ctx;
    assert(priv != NULL);

    qtiCopyMACAddr(destAddr, sta_stats.is_u.macaddr);
    strlcpy(iwr.ifr_name, ifname, IFNAMSIZ);

    iwr.u.data.pointer = &sta_stats;
    iwr.u.data.length = sizeof(sta_stats);
    if(( ret = ioctl( priv->Sock, IEEE80211_IOCTL_STA_STATS, &iwr )) < 0 )
    {
        goto err;
    }
    //Copy received sta_stats from driver to soncmn structure
    stats->txBytes = sta_stats.is_stats.ns_tx_bytes_success;
    stats->rxBytes = sta_stats.is_stats.ns_rx_bytes;
    stats->lastTxRate = sta_stats.is_stats.ns_last_tx_rate;
    stats->lastRxRate = sta_stats.is_stats.ns_last_rx_rate;

    TRACE_EXIT();
    return 0;
err:
    TRACE_EXIT_ERR();
    return ret;

}


/**
 * @brief Function to set ACL Policy
 *
 * @param [in] context   opaque pointer to private vendor struct
 * @param [in] ifname    interface name
 * @param [in] aclCmd    Access Control List policy command
 *
 * @return Success: 0, Failure: -1
 *
 */
static int setAclPolicy_qti(const void * context, const char *ifname, int aclCmd)
{
    int ret;
    struct iwreq Wrq;
    struct priv_qti * priv;
    int param[2] = { IEEE80211_PARAM_MACCMD, aclCmd };

    TRACE_ENTRY();

    priv = (struct priv_qti *) context;
    assert(priv != NULL);

    strlcpy(Wrq.ifr_name, ifname, IFNAMSIZ );
    memcpy(Wrq.u.name, &param, sizeof(param));
    if ((ret = ioctl(priv->Sock, IEEE80211_IOCTL_SETPARAM, &Wrq)) < 0) {
        goto err;
    }

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;

}

/**
 * @brief Function to add or delete MAC from ACL Policy filtering list
 *
 * @param [in] context    opaque pointer to private vendor struct
 * @param [in] ifname     interface name
 * @param [in] staAddr    sta mac which needs to be added or deleted
 *                        from mac filtering list
 * @param [in] isAdd      flag, 1: Add this mac, 0: Delete this mac
 *
 * @return Success: 0, Failure: -1
 *
 */
static int setMacFiltering_qti (const void *context, const char* ifname,
                           const uint8_t* staAddr, uint8_t isAdd)
{
    struct iwreq iwr;
    int ret;
    struct priv_qti * priv;
    struct sockaddr addr;
    int ioctl_id = -1;

    TRACE_ENTRY();

    priv = (struct priv_qti *) context;
    assert(priv != NULL);

    memset(&addr, 0, sizeof(addr));
    addr.sa_family = ARPHRD_ETHER_FAMILY;
    qtiCopyMACAddr(staAddr, addr.sa_data);

    strlcpy(iwr.ifr_name, ifname, IFNAMSIZ);

    ioctl_id = (isAdd) ? IEEE80211_IOCTL_ADDMAC : IEEE80211_IOCTL_DELMAC;

    memcpy(iwr.u.name, &addr, (sizeof(addr)));

    if(( ret = ioctl( priv->Sock, ioctl_id , &iwr )) < 0 )
    {
        goto err;
    }

    TRACE_EXIT();
    return 0;
err:
    TRACE_EXIT_ERR();
    return -1;
}

/**
 * @brief Function to disaasoc a connected client by sending disassoc MLME frame
 *
 * @param [in] context   opaque pointer to private vendor struct
 * @param [in] ifname    interface name
 * @param [in] staAddr   sta mac for which disaaosc frame needs to be sent
 *
 * @return Success: 0, Failure: -1
 *
 */
static int performKickMacDisassoc_qti (const void *context,
                    const char* ifname, const uint8_t* staAddr)
{
    struct iwreq iwr;
    int ret;
    struct priv_qti * priv;
    struct sockaddr addr;

    TRACE_ENTRY();

    priv = (struct priv_qti *) context;
    assert(priv != NULL);

    memset(&addr, 0, sizeof(addr));
    addr.sa_family = ARPHRD_ETHER_FAMILY;
    qtiCopyMACAddr(staAddr, addr.sa_data);


    strlcpy(iwr.ifr_name, ifname, IFNAMSIZ);
    memcpy(iwr.u.name, &addr, (sizeof(addr)));

    if(( ret = ioctl( priv->Sock, IEEE80211_IOCTL_KICKMAC , &iwr )) < 0 )
    {
        goto err;
    }

    TRACE_EXIT();
    return 0;
err:
    TRACE_EXIT_ERR();
    return -1;
}


/**
 * @brief Function to get channel width
 *
 * @param [in] ctxt      opaque pointer to private vendor struct
 * @param [in] ifname    interface name
 * @param [in] chwidth   channel width pointer, to be filled by this function
 *
 * @return Success: 0, Failure: -1
 *
 */
static int getChannelWidth_qti(const void *ctx, const char * ifname, int * chwidth)
{
    struct iwreq Wrq;
    int ret,iwparam;
    struct priv_qti * priv;

    TRACE_ENTRY();

    priv = (struct priv_qti *) ctx;
    assert(priv != NULL);

    strlcpy(Wrq.ifr_name, ifname, IFNAMSIZ );
    iwparam = IEEE80211_PARAM_CHWIDTH;
    memcpy(Wrq.u.name, &iwparam, sizeof(iwparam));
    if ((ret = ioctl(priv->Sock, IEEE80211_IOCTL_GETPARAM, &Wrq)) < 0) {
        goto err;
    }

    memcpy(chwidth, Wrq.u.name, sizeof(int));

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

/**
 * @brief Function to get operating mode
 *
 * @param [in] ctx       opaque pointer to private vendor struct
 * @param [in] ifname    interface name
 * @param [in] opMode    operating Mode pointer, to be filled by this function
 *
 * @return Success: 0, Failure: -1
 *
 */
static int getOperatingMode_qti(const void *ctx, const char * ifname, int *opMode)
{
    struct iwreq Wrq;
    int ret, iwparam;
    struct priv_qti * priv;

    TRACE_ENTRY();

    priv = (struct priv_qti *) ctx;
    assert(priv != NULL);

    strlcpy(Wrq.ifr_name, ifname, IFNAMSIZ );
    iwparam = IEEE80211_PARAM_BANDWIDTH;
    memcpy(Wrq.u.name, &iwparam, sizeof(iwparam));
    if ((ret = ioctl(priv->Sock, IEEE80211_IOCTL_GETPARAM, &Wrq)) < 0) {
        goto err;
    }
    memcpy(opMode, Wrq.u.name, sizeof(int));

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

/**
 * @brief Function to get channel offset
 *
 * @param [in] ctx       opaque pointer to private vendor struct
 * @param [in] ifname    interface name
 *
 * @param [out] choffset pointer to be filled by this function
 *
 * @return Success: 0, Failure: -1
 *
 */
static int getChannelExtOffset_qti (const void *ctx, const char *ifname, int *choffset)
{
    struct iwreq Wrq;
    int ret, iwparam;
    struct priv_qti * priv;

    TRACE_ENTRY();

    priv = (struct priv_qti *) ctx;
    assert(priv != NULL);

    strlcpy(Wrq.ifr_name, ifname, IFNAMSIZ );
    iwparam = IEEE80211_PARAM_CHEXTOFFSET;
    memcpy(Wrq.u.name, &iwparam, sizeof(iwparam));
    if ((ret = ioctl(priv->Sock, IEEE80211_IOCTL_GETPARAM, &Wrq)) < 0) {
        goto err;
    }
    memcpy(choffset, Wrq.u.name, sizeof(int));

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;

}

/**
 * @brief Function to get center frequency for 160MHz bandwidth channel
 *
 * @param [in] ctx       opaque pointer to private vendor struct
 * @param [in] ifname    interface name
 * @param [in] channum   channel number for which center freq is needed
 *
 * @param [out] cfreq    Center freq pointer, to be filled by this function
 *
 * @return Success: 0, Failure: -1
 *
 */
static int getCenterFreq160_qti(const void *ctx,
             const char *ifname, uint8_t channum, uint8_t *cfreq)
{
    struct iwreq Wrq;
    int ret, i;
    struct priv_qti * priv;
    struct ieee80211_wlanconfig *config;
    struct ieee80211req_chaninfo chanInfoList = {0};

    TRACE_ENTRY();

    priv = (struct priv_qti *) ctx;
    assert(priv != NULL);

    *cfreq = 0;
    memset(&Wrq, 0, sizeof(struct iwreq));
    config = (struct ieee80211_wlanconfig *)&chanInfoList;
    config->cmdtype = IEEE80211_WLANCONFIG_GETCHANINFO_160;
    strlcpy(Wrq.ifr_name, ifname, IFNAMSIZ );
    Wrq.u.data.pointer = (void *) &chanInfoList;
    Wrq.u.data.length = sizeof(chanInfoList);

    if ((ret = ioctl(priv->Sock, IEEE80211_IOCTL_CONFIG_GENERIC, &Wrq)) < 0) {
        goto err;
    }

    for (i = 0; i < chanInfoList.ic_nchans; ++i) {
        if (chanInfoList.ic_chans[i].ic_ieee == channum) {
            *cfreq = chanInfoList.ic_chans[i].ic_vhtop_ch_freq_seg1;
            break;
        }
    }

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

/**
 * @brief Function to get center frequency segment 1 for VHT 80_80 operation
 *
 * @param [in] ctx        opaque pointer to private vendor struct
 * @param [in] ifname     interface name
 *
 * @param [out] cFreqSeg1 pointer to be filled by this function with center freq
 *
 * @return Success: 0, Failure: -1
 *
 */
static int getCenterFreqSeg1_qti(const void *ctx, const char *ifname, int32_t *cFreqSeg1)
{
    int ret,iwparam;
    struct iwreq Wrq;
    struct priv_qti * priv;

    TRACE_ENTRY();

    priv = (struct priv_qti *) ctx;
    assert(priv != NULL);

    strlcpy(Wrq.ifr_name, ifname, IFNAMSIZ );
    iwparam = IEEE80211_PARAM_SECOND_CENTER_FREQ;
    memcpy(Wrq.u.name, &iwparam, sizeof(iwparam));
    if ((ret = ioctl(priv->Sock, IEEE80211_IOCTL_GETPARAM, &Wrq)) < 0) {
        goto err;
    }
    memcpy(cFreqSeg1, Wrq.u.name, sizeof(int32_t));

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

/**
 * @brief Function to get center frequency segment 0 for VHT operation
 *
 * @param [in] ctx        opaque pointer to private vendor struct
 * @param [in] ifname     interface name
 *
 * @param [out] cFreqSeg0 pointer to be filled by this function with center freq
 *
 * @return Success: 0, Failure: -1
 *
 */
static int getCenterFreqSeg0_qti(const void *ctx, const char *ifname, uint8_t channum, uint8_t *cFreqSeg0)
{
    struct iwreq Wrq;
    int ret, i;
    struct priv_qti * priv;
    struct ieee80211req_chaninfo chanInfoList = {0};

    TRACE_ENTRY();

    priv = (struct priv_qti *) ctx;
    assert(priv != NULL);

    *cFreqSeg0 = 0;
    memset(&Wrq, 0, sizeof(struct iwreq));
    strlcpy(Wrq.ifr_name, ifname, IFNAMSIZ );
    Wrq.u.data.pointer = (void *) &chanInfoList;
    Wrq.u.data.length = sizeof(chanInfoList);

    if ((ret = ioctl(priv->Sock, IEEE80211_IOCTL_GETCHANINFO, &Wrq)) < 0) {
        goto err;
    }

    for (i = 0; i < chanInfoList.ic_nchans; ++i) {
        if (chanInfoList.ic_chans[i].ic_ieee == channum) {
            *cFreqSeg0 = chanInfoList.ic_chans[i].ic_vhtop_ch_freq_seg1;
            break;
        }
    }

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

/**
 * @brief Function to dump ATF Table for a single interface. QTI only function
 *
 * @param [in] ctx       opaque pointer to private vendor struct
 * @param [in] ifname    interface name
 * @param [in] atfInfo   data pointer for ATF Info
 * @param [in] len       length of ATF data
 *
 * @return Success: 0, Failure: -1
 *
 */
static int dumpAtfTable_qti(const void *ctx, const char *ifname, void *atfInfo, int32_t len)
{
    struct iwreq Wrq;
    int ret;
    struct priv_qti * priv;

    TRACE_ENTRY();

    priv = (struct priv_qti *) ctx;
    assert(priv != NULL);

    memset(&Wrq, 0, sizeof(struct iwreq));
    strlcpy(Wrq.ifr_name, ifname, IFNAMSIZ );

    Wrq.u.data.pointer = (void *) atfInfo;
    Wrq.u.data.length = len;

    if ((ret = ioctl(priv->Sock, IEEE80211_IOCTL_CONFIG_GENERIC, &Wrq)) < 0) {
        goto err;
    }

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

/*============================================================
================= Init Functions =============================
============================================================== */

/**
 * @brief  Vendor's Init function, creates sockets for
 *          driver communication, event handlers etc.
 *
 * @param [in] drvhandle_qti   driver Handle
 *
 * @return Success: 0, Failure: -1
 *
 */
int sonInit_qti(struct soncmnDrvHandle *drvhandle_qti)
{
    struct priv_qti * priv;
    int ret;

    dbgf(soncmnDbgS.dbgModule, DBGINFO, "%s: Vendor initialization",__func__);
    assert(drvhandle_qti != NULL);

    /* For QTI, initialization happens once */
    if (drvhandle_qti->ctx != NULL){
        dbgf(soncmnDbgS.dbgModule, DBGINFO, "%s: QTI init has already happened once, return",__func__);
        return 0;
    }

    drvhandle_qti->ctx = malloc(sizeof(struct priv_qti));

    if (drvhandle_qti->ctx == NULL)
    {
        dbgf(soncmnDbgS.dbgModule, DBGERR, "%s: Vendor Init failed",__func__);
        return -ENOMEM;
    }

    priv = (struct priv_qti *) drvhandle_qti->ctx;

    if( (ret = sockInit_qti(priv)) )
    {
        return ret;
    }

    eventRegister_qti();
    dbgf(soncmnDbgS.dbgModule, DBGINFO, "%s: Successful init from Vendor QTI",__func__);
    return 0;
}

/**
 * @brief  Vendor's De-init function to free up allocated memory
 *
 * @param [in] drvhandle_qti   driver Handle
 *
 * @return Success: 0, Failure: -1
 *
 */
void sonDeinit_qti(struct soncmnDrvHandle *drvhandle_qti)
{
    struct priv_qti * priv;

    assert(drvhandle_qti != NULL);

    priv = (struct priv_qti *) drvhandle_qti->ctx;

    assert(priv != NULL);
    sockClose_qti(priv);

    free(priv);
}

/* Vendor mapping for APIs */
/* NOTE: Order of these APIs should match */
/* with somcmnOps struct defined in cmn.h */
static struct soncmnOps qti_ops = {
    .init = sonInit_qti,
    .deinit = sonDeinit_qti,
    .getName = getName_qti,
    .getBSSID = getBSSID_qti,
    .getSSID = getSSID_qti,
    .isAP = isAP_qti,
    .getFreq = getFreq_qti,
    .getIfFlags = getIfFlags_qti,
    .getAcsState = getAcsState_qti,
    .getCacState = getCacState_qti,
    .setBSteerAuthAllow = setBSteerAuthAllow_qti,
    .setBSteerProbeRespWH = setBSteerProbeRespWH_qti,
    .setBSteerProbeRespAllow2G = setBSteerProbeRespAllow2G_qti,
    .setBSteerOverload = setBSteerOverload_qti,
    .performLocalDisassoc = performLocalDisassoc_qti,
    .performKickMacDisassoc = performKickMacDisassoc_qti,
    .setBSteering = setBSteering_qti,
    .setBSteerEvents = setBSteerEvents_qti,
    .setBSteerInProgress = setBSteerInProgress_qti,
    .setBSteerParams = setBSteerParams_qti,
    .getBSteerRSSI = getBSteerRSSI_qti,
    .getDataRateInfo = getDataRateInfo_qti,
    .getStaInfo = getStaInfo_qti,
    .getStaStats = getStaStats_qti,
    .setAclPolicy = setAclPolicy_qti,
    .sendBcnRptReq = sendBcnRptReq_qti,
    .sendBTMReq = sendBTMReq_qti,
    .setMacFiltering = setMacFiltering_qti,
    .getChannelWidth = getChannelWidth_qti,
    .getOperatingMode = getOperatingMode_qti,
    .getChannelExtOffset = getChannelExtOffset_qti,
    .getCenterFreq160 = getCenterFreq160_qti,
    .getCenterFreqSeg1 = getCenterFreqSeg1_qti,
    .getCenterFreqSeg0 = getCenterFreqSeg0_qti,
    .enableBSteerEvents = enableBSteerEvents_qti,
    .dumpAtfTable = dumpAtfTable_qti,
};


/**
 * @brief  Function to map vendor APIs to soncmnOPs
 *
 */
struct soncmnOps * sonGetOps_qti()
{
    return &qti_ops;
}

/**
 * @brief  Function to enable Band Steering in driver via Netlink message
 *         QTI only function.
 *
 * @param [in] sysIndex   sys index for interface
 *
 * @return Success: 0, Failure: -1
 *
 */
static int enableBSteerEvents_qti(uint32_t sysIndex)
{
    struct sockaddr_nl destAddr;
    memset(&destAddr, 0, sizeof(destAddr));
    destAddr.nl_family = AF_NETLINK;
    destAddr.nl_pid = 0;
    destAddr.nl_groups = 0;

    struct nlmsghdr hdr;
    hdr.nlmsg_len = NLMSG_SPACE(0);
    hdr.nlmsg_flags = sysIndex;
    hdr.nlmsg_type = 0;
    hdr.nlmsg_pid = getpid();

    dbgf(soncmnDbgS.dbgModule, DBGINFO, "%s: Sending BSteering Event NL msg to driver", __func__);
    if (sendto(eventHandler.lbdNLSocket, &hdr, hdr.nlmsg_len, 0,
               (const struct sockaddr *) &destAddr, sizeof(destAddr)) < 0) {
        dbgf(soncmnDbgS.dbgModule, DBGERR, "%s: Failed to send netlink trigger",
             __func__);
        return -1;
    }

    return 0;
}
