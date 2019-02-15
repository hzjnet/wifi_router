/*
 * @@-COPYRIGHT-START-@@
 *
 * Copyright (c) 2018 Qualcomm Technologies, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 * @@-COPYRIGHT-END-@@
 */
#include <sys/socket.h>
#include <sys/file.h>
#include <fcntl.h>
#include <netinet/ether.h>
#include <string.h>
#include "apac_map.h"

ieee1905TLV_t *ieee1905MapAddRadioIdTLV(ieee1905TLV_t *TLV,
        u_int32_t *Len,
        struct apac_wps_session *sess);


apacBool_e apacHyfiMapParseAndStoreConfig(apacMapData_t *map, const char *fname)
{
    FILE *f = NULL;
    char buf[256] = {0};
    char *pos = NULL;
    int line = 0;
    int errors = 0;
    apacMapEProfile_t *eProfile = NULL;
    char tag[MAX_SSID_LEN];
    char len = 0;

    apacHyfi20TRACE();

    int lock_fd = open(APAC_LOCK_FILE_PATH, O_RDONLY);
    if (lock_fd < 0) {
        dprintf(MSG_ERROR, "Failed to open lock file %s\n", APAC_LOCK_FILE_PATH);
        return APAC_FALSE;
    }

    if (flock(lock_fd, LOCK_EX) == -1) {
        dprintf(MSG_ERROR, "Failed to flock lock file %s\n", APAC_LOCK_FILE_PATH);
        close(lock_fd);
        return APAC_FALSE;
    }

    dprintf(MSG_DEBUG, "Reading Map 1.0 configuration file %s ...\n", fname);

    f = fopen(fname, "r");

    if (f == NULL) {
        dprintf(MSG_ERROR,
                "Could not open configuration file '%s' for reading.\n",
                fname);
        return APAC_FALSE;
    }

    while (fgets(buf, sizeof(buf), f) != NULL) {
        pos = buf;
        eProfile = &map->eProfile[line];

        len = apac_atf_config_line_getparam(pos,',',tag);
        eProfile->alId = strdup(tag);

        pos += len + 1;
        len = apac_atf_config_line_getparam(pos,',',tag);
        eProfile->opclass = (u8 *)strdup(tag);

        pos += len + 1;
        len = apac_atf_config_line_getparam(pos,',',tag);
        eProfile->ssid = (u8 *)strdup(tag);

        pos += len + 1;
        len = apac_atf_config_line_getparam(pos,',',tag);
        eProfile->auth = (u8 *)strdup(tag);

        pos += len + 1;
        len = apac_atf_config_line_getparam(pos,',',tag);
        eProfile->encr = (u8 *)strdup(tag);

        pos += len + 1;
        len = apac_atf_config_line_getparam(pos,',',tag);
        eProfile->nw_key = (u8 *)strdup(tag);

        pos += len + 1;
        len = apac_atf_config_line_getparam(pos,',',tag);
        eProfile->mapbh = (u8 *)strdup(tag);
        pos += len + 1;
        eProfile->mapfh = (u8 *)strdup(pos);

        dprintf(MSG_ERROR, "buf  %u\n", strlen(buf));
        if (strlen(buf) > 1)
            line++;

        if (line >= APAC_MAXNUM_NTWK_NODES)
            break;

        memset(buf, 0x00, sizeof(buf));
    }

    if (flock(lock_fd, LOCK_UN) == 1) {
        dprintf(MSG_ERROR, "Failed to unlock file %s\n", APAC_LOCK_FILE_PATH);
        errors++;
    }

    map->eProfileCnt = line;
    dprintf(MSG_ERROR, "map eProfile %u\n", map->eProfileCnt);
    close(lock_fd);
    fclose(f);

    if (errors) {
        dprintf(MSG_ERROR,
                "%d errors found in configuration file '%s'\n",
                errors, fname);
    }

    return (errors != 0);
}

apacBool_e apacHyfiMapDInit(apacMapData_t *map)
{
    u8 i = 0;
    apacMapEProfile_t *eProfile = NULL;

    apacHyfi20TRACE();

    for(i = 0 ; i < map->eProfileCnt; i++) {
        eProfile = &map->eProfile[i];
        free(eProfile->alId);
        free(eProfile->opclass);
        free(eProfile->ssid);
        free(eProfile->auth);
        free(eProfile->encr);
        free(eProfile->nw_key);
        free(eProfile->mapbh);
        free(eProfile->mapfh);
    }

    return APAC_TRUE;
}

int apacGetPIFMapCap( apacHyfi20Data_t *pData)
{
    apacPifMap_t *pIFMapData = NULL;
    int32_t Sock;
    struct iwreq iwr;
    struct ieee80211req_athdbg req = {0};
    map_unoperable_ch *unop = NULL;
    int j, i = 0, k = 0;
    apacHyfi20AP_t *pAP = &pData->ap[0];

    apacHyfi20TRACE();

    for (i = 0; i < APAC_NUM_WIFI_FREQ; i++) {

        if (!pAP[i].valid)
            continue;

        if (!pAP[i].ifName) {
            dprintf(MSG_ERROR, "%s - Invalid arguments: ifName is NULL", __func__);
            goto out;
        }

        dprintf(MSG_ERROR,"%s  %s \n",__func__,pAP[i].ifName);

        if ((Sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
            dprintf(MSG_ERROR, "%s: Create ioctl socket failed!", __func__);
            goto out;
        }

        if (fcntl(Sock, F_SETFL, fcntl(Sock, F_GETFL) | O_NONBLOCK)) {
            dprintf(MSG_ERROR, "%s: fcntl() failed", __func__);
            goto err;
        }

        pIFMapData = &pAP[i].pIFMapData;
        strlcpy(iwr.ifr_name, pAP[i].ifName, IFNAMSIZ);
        iwr.u.data.pointer = (void *) &req;
        iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
        req.cmd = IEEE80211_DBGREQ_SON_MAP_APCAP;
        req.data.mapapcap.length = IEEE80211_MAX_OPERATING_CLASS *sizeof(map_unoperable_ch);
        req.data.mapapcap.data = malloc(IEEE80211_MAX_OPERATING_CLASS * sizeof(map_unoperable_ch));

        if (ioctl(Sock, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
            goto err;
        }

        os_memcpy(pIFMapData->reg.radiomac, req.data.mapapcap.radiomac, 6);
        pIFMapData->reg.band = req.data.mapapcap.band;//band capabitlity
        pIFMapData->reg.maxbss = req.data.mapapcap.maxbss;
        pIFMapData->reg.opclasscnt = req.data.mapapcap.opclasscnt;
        dprintf(MSG_INFO," Radio Mac %x %x %x %x %x %x \n",pIFMapData->reg.radiomac[0],
                pIFMapData->reg.radiomac[1],pIFMapData->reg.radiomac[2],pIFMapData->reg.radiomac[3],
                pIFMapData->reg.radiomac[4],pIFMapData->reg.radiomac[5]);
        unop = (map_unoperable_ch *)req.data.mapapcap.data;

        for (k = 0; k < req.data.mapapcap.opclasscnt; k++)
        {
            pIFMapData->mapOpClass[k].opclass = unop->opclass;
            pIFMapData->mapOpClass[k].txpow = unop->txpow;
            pIFMapData->mapOpClass[k].num_unopch = unop->num_unopch;

            dprintf(MSG_INFO,"Operating class  %d Txpwer %x Number of unoperable channel %d opclass %d \n",
                    unop->opclass, unop->txpow,unop->num_unopch,pIFMapData->mapOpClass[k].opclass);

            for (j = 0; j < unop->num_unopch; j++)
            {
                pIFMapData->mapOpClass[k].unopch[j] = unop->unopch[j];
                dprintf(MSG_INFO,"Unoperable channel list %d \n",
                        pIFMapData->mapOpClass[k].unopch[j]);
            }
            unop++;
        }

        free(req.data.mapapcap.data);
        close(Sock);
    }

    return 0;
err:
    close(Sock);
out:
    return -1;
}

apacBool_e apacHyfiMapInit(apacMapData_t *map)
{
    apacHyfi20Data_t *hyfi20;
    apacHyfi20TRACE();

    hyfi20 = MAPToHYFI20(map);

    if (hyfi20->config.role != APAC_REGISTRAR) {
        dprintf(MSG_ERROR, "%s, not registrar!\n", __func__);
        return APAC_TRUE;
    }

    if (!apacHyfiMapIsEnabled(map))
        return APAC_TRUE;

    apacHyfiMapParseAndStoreConfig(map, g_map_cfg_file);
    return APAC_TRUE;
}

apacBool_e apacHyfiMapConfigDump(apacMapData_t *map)
{
    u8 i = 0;
    apacMapEProfile_t *eProfile = NULL;
    apacHyfi20Data_t *hyfi20;
    apacHyfi20TRACE();

    hyfi20 = MAPToHYFI20(map);

    if (hyfi20->config.role != APAC_REGISTRAR) {
        dprintf(MSG_ERROR, "%s, not registrar!\n", __func__);
        return APAC_TRUE;
    }

    for(i = 0 ; i < map->eProfileCnt; i++) {
        eProfile = &map->eProfile[i];
        dprintf(MSG_MSGDUMP," %s,%s,%s,%s,%s,%s,%s,%s \n",
                eProfile->alId,eProfile->opclass,
                eProfile->ssid,eProfile->auth,eProfile->encr,
                eProfile->nw_key,eProfile->mapbh,eProfile->mapfh);

    }

    return APAC_TRUE;
}

apacBool_e apacHyfiMapIsEnabled(apacMapData_t *map)
{
    return map->enable;
}

/* Registrar/Enrollee sends WPS msg */
int apacHyfiMapSendMultipleM2(struct apac_wps_session *sess)
{
    u8 *frame;
    ieee1905MessageType_e msgType = IEEE1905_MSG_TYPE_AP_AUTOCONFIGURATION_WPS;
    u16 mid = apacHyfi20GetMid();
    u8 flags = 0;
    u8 *src;
    u8 *dest;
    APAC_WPS_DATA    *pWpsData = sess->pWpsData;
    struct wps_tlv *tlvList = &pWpsData->sndMsgM2[0];
    u8 fragNum = 0;
    size_t frameLen;
    ieee1905TLV_t *TLV;
    size_t sentLen = 0;
    u8  more = 0;
    u8 index = 0;
    apacBool_e radioTlvSent = APAC_FALSE;

    apacHyfi20TRACE();
    src = sess->own_addr;
    dest = sess->dest_addr;

    if (!src || !dest) {
        dprintf(MSG_ERROR, "src or dest address is null!\n");
        dprintf(MSG_ERROR, " src: "); printMac(MSG_DEBUG, src);
        dprintf(MSG_ERROR, " dest: "); printMac(MSG_DEBUG, dest);

        return -1;
    }

nextIndex:
    frame = apacHyfi20GetXmitBuf();
    frameLen = IEEE1905_FRAME_MIN_LEN;
    TLV = (ieee1905TLV_t *)((ieee1905Message_t *)frame)->content;

    if(radioTlvSent == APAC_FALSE) {
        TLV = ieee1905MapAddRadioIdTLV(TLV, &sentLen, sess);
        frameLen += sentLen;
        radioTlvSent = APAC_TRUE;
    }

    if (tlvList[index].length >= IEEE1905_CONTENT_MAXLEN) {
        return -1;
    }

    while(index < pWpsData->M2TlvCnt)
    {
        // To make sure TLV boundry fragmentation;
        // 2 * min 1 for EOM , one for TLV itself
        if (sentLen + tlvList[index].length < IEEE1905_CONTENT_MAXLEN - 2 * IEEE1905_TLV_MIN_LEN) {
            ieee1905TLVSet(TLV, tlvList[index].type, tlvList[index].length, tlvList[index].value.ptr_, frameLen);
            sentLen += tlvList[index].length;
            dprintf(MSG_ERROR, "%s sent len %d Type %x \n",__func__, sentLen,tlvList[index].type);
            index++;
        } else {
            more = 1;
            break;
        }
        TLV = ieee1905TLVGetNext(TLV);
    }

    if (!more)
        flags |= IEEE1905_HEADER_FLAG_LAST_FRAGMENT;

    ieee1905EndOfTLVSet(TLV);
    /* set up packet header */
    apacHyfi20SetPktHeader(frame, msgType, mid, fragNum, flags, src, dest);
    /* send packet */

    dprintf(MSG_INFO," %s Sending frame Length %d flags %x Mid %d fid %d Index %d \n",__func__, frameLen,
            flags, mid,fragNum, index);

    if (sess->pData->config.sendOnAllIFs == APAC_FALSE) {
        if (send(sess->pData->bridge.sock, frame, frameLen, 0) < 0) {
            perror("apacHyfi20SendWps");
            return -1;
        }
    } else {  /* send unicast packet on all interfaces. Debug Only! */
        int i;

        for (i = 0; i < APAC_MAXNUM_HYIF; i++) {
            if (sess->pData->hyif[i].ifIndex == -1)
                continue;

            if (apacHyfi20SendL2Packet(&sess->pData->hyif[i], frame, frameLen) < 0) {
                perror("apacHyfi20SendWps-onAllIFs");
            }
        }
    }

    fragNum++;

    if (more) {
        more = 0; //for next iteration
        sentLen = 0;
        frameLen = 0;
        flags = 0;
        goto nextIndex;
    }

    return 0;
}

apacBool_e apacHyfiMapParse1905TLV(struct apac_wps_session *sess,
        u8 *content, u32 contentLen,
        struct wps_tlv *container,
        s32 maxContainerSize, u8 *ieParsed)
{
    ieee1905TLV_t *TLV = (ieee1905TLV_t *)content;
    u_int32_t accumulatedLen = 0;
    ieee1905TlvType_e tlvType;
    apacBool_e retv = APAC_TRUE;
    u32 index = 0;
    struct wps_tlv *wps = NULL;
    u8 *ptr = NULL;

    accumulatedLen = ieee1905TLVLenGet(TLV) + IEEE1905_TLV_MIN_LEN;

    dprintf(MSG_ERROR,"accumulated %d contentlen %d \n",accumulatedLen, contentLen);

    while( accumulatedLen <= contentLen ) {
        tlvType = ieee1905TLVTypeGet(TLV);
        wps = &container[index];

        dprintf(MSG_INFO," %s type %d Accumulated %d Index %d \n",__func__, tlvType, accumulatedLen, index);

        if (tlvType ==  IEEE1905_TLV_TYPE_END_OF_MESSAGE ) {
            /* End-of-message */
            retv = APAC_TRUE;
            break;
        } else if( tlvType == IEEE1905_TLV_TYPE_WPS) {
            wps->type = IEEE1905_TLV_TYPE_WPS;
            wps->length = ieee1905TLVLenGet(TLV);
            if (wps->length)
                wps->value.ptr_ = os_malloc(wps->length);
            else {
                retv = APAC_FALSE;
                break;
            }

            if (!wps->value.ptr_) {
                retv = APAC_FALSE;
                break;
            }

            ptr = ieee1905TLVValGet(TLV);
            os_memcpy(wps->value.ptr_, ptr, wps->length);
            index++;
        } else if (tlvType == IEEE1905_TLV_TYPE_RADIO_IDENTIFIER) { // handle other TLV as well
            dprintf(MSG_DEBUG,"Received RADIO TLV len %d \n", ieee1905TLVLenGet(TLV));
            printMsg((u8 *)TLV, ieee1905TLVLenGet(TLV), MSG_DEBUG);
            sess->radioCap = malloc(ieee1905TLVLenGet(TLV));
            if (sess->radioCap) {
                sess->radioCapLen = ieee1905TLVLenGet(TLV);
                ptr = ieee1905TLVValGet(TLV);
                memcpy(sess->radioCap, ptr, sess->radioCapLen);
            }
        } else if (tlvType == IEEE1905_TLV_TYPE_AP_RADIO_BASIC_CAP) {
            dprintf(MSG_DEBUG,"Basic RADIO TLV len %d \n", ieee1905TLVLenGet(TLV));
            printMsg((u8 *)TLV, ieee1905TLVLenGet(TLV), MSG_DEBUG);
            sess->basicRadioCap = malloc(ieee1905TLVLenGet(TLV));
            if (sess->basicRadioCap) {
                sess->basicRadioCapLen = ieee1905TLVLenGet(TLV);
                ptr = ieee1905TLVValGet(TLV);
                memcpy(sess->basicRadioCap, ptr, sess->basicRadioCapLen);
            }
        }

        TLV = ieee1905TLVGetNext(TLV);
        accumulatedLen += ieee1905TLVLenGet(TLV) + IEEE1905_TLV_MIN_LEN;
    }

    *ieParsed = index;

    dprintf(MSG_MSGDUMP, "%s ToTal Frame received  %d \n",__func__, *ieParsed);

    return retv;
}

ieee1905TLV_t *ieee1905MapAddBasicRadioTLV(ieee1905TLV_t *TLV,
        u_int32_t *Len,
        u8 band,
        apacHyfi20Data_t *pData)
{
    u_int16_t tlvLen = 0;
    u_int8_t *ptr = NULL;
    map_unoperable_ch *unop = NULL;
    u_int16_t i = 0, j = 0;
    apacPifMap_t *mapData = NULL;
    apacMapData_t *map = NULL;

    apacHyfi20TRACE();

    map = HYFI20ToMAP(pData);

    TLV = ieee1905TLVGetNext(TLV);
    ieee1905TLVTypeSet( TLV, IEEE1905_TLV_TYPE_AP_RADIO_BASIC_CAP);
    ptr = ieee1905TLVValGet(TLV);

    mapData = &pData->ap[band].pIFMapData;

    if( !mapData )
        return TLV;

    os_memcpy(ptr, mapData->reg.radiomac, ETH_ALEN);
    tlvLen += ETH_ALEN ;/* MAC addr len */
    ptr += ETH_ALEN;

    *ptr++ = map->MapConfMaxBss;//configured value
    tlvLen++;
    *ptr++ = mapData->reg.opclasscnt;
    tlvLen++;

    unop = &mapData->mapOpClass[0];
    for (i = 0; i < mapData->reg.opclasscnt; i++) {
        *ptr++ = unop->opclass;
        tlvLen++;
        *ptr++ = unop->txpow;
        tlvLen++;
        *ptr++ = unop->num_unopch;
        tlvLen++;

        for (j = 0; j < unop->num_unopch; j++) {
            *ptr++ = unop->unopch[j];
            tlvLen++;
        }
        unop++;
    }

    ieee1905TLVLenSet(TLV, tlvLen, *Len);

    dprintf(MSG_INFO,"Added basic radio TLV(Enrollee) framelen %d tlvlen %d \n",
            *Len, tlvLen);

    printMsg((u8 *)TLV, tlvLen, MSG_DEBUG);
    return TLV;
}

ieee1905TLV_t *ieee1905MapAddRadioIdTLV(ieee1905TLV_t *TLV,
        u_int32_t *Len,
        struct apac_wps_session *sess)
{

    u_int8_t *ptr = NULL;
    u8 *Data = NULL;

    apacHyfi20TRACE();

    if(sess->basicRadioCapLen)
        Data = sess->basicRadioCap;
    else
        return TLV;

    ieee1905TLVTypeSet( TLV, IEEE1905_TLV_TYPE_RADIO_IDENTIFIER);
    ptr = ieee1905TLVValGet(TLV);
    os_memcpy(ptr, Data, ETH_ALEN);

    ieee1905TLVLenSet(TLV, ETH_ALEN, *Len);
    printMsg((u8 *)TLV, ETH_ALEN,MSG_MSGDUMP);

    return ieee1905TLVGetNext(TLV);
}

u8 ieee1905MapParseBasicRadioTLV(u8 *val,
        u_int32_t Len, u8 *maxBss,
        u8 minop, u8 maxop)
{
    u8 *ptr = NULL;
    u_int16_t i = 0, j = 0, unoperable = 0;
    u8  opclassCnt = 0, opclass = 0, txpower = 0;
    apacBool_e retv = APAC_FALSE;

    apacHyfi20TRACE();

    printMac(MSG_DEBUG, val);

    ptr = val;
    ptr += ETH_ALEN; //skipping radio mac address.

    *maxBss = *ptr++;

    opclassCnt = *ptr++;
    dprintf(MSG_INFO, "Received M1 maxbss %d opclasscnt %d  \n", *maxBss, opclassCnt);

    for (i = 0; i < opclassCnt; i++) {
        opclass = *ptr++;
        txpower = *ptr++; //skipping tx power
        unoperable = *ptr++;
        dprintf(MSG_INFO, "operating class %d TxPower %d Unoperable ch Cnt%d \n",opclass, txpower, unoperable);
        for(j = 0 ; j < unoperable; j++) {
            dprintf(MSG_INFO, "Unoperable channel %d \n", *ptr);
            ptr++;
        }

        if(opclass >= minop && opclass <= maxop) {
            retv = APAC_TRUE;
            break;
        }

    }

    dprintf(MSG_INFO, "Profile %s \n", retv == APAC_TRUE ? "Selected":"Rejected");
    return retv;
}

u8 apac_map_get_configured_maxbss(struct apac_wps_session *sess)
{
    apacHyfi20Data_t *hyfi20 = NULL;
    apacMapData_t *map = NULL;

    apacHyfi20TRACE();

    hyfi20 = sess->pData;

    map = HYFI20ToMAP(hyfi20);

    return map->MapConfMaxBss;
}


u8 apac_map_copy_apinfo(apacMapData_t *map,
        apacHyfi20AP_t *ap,
        u8 index)
{
    apacMapEProfile_t *eProfile = NULL;
    char *end = NULL;
    u16 res = 0;

    apacHyfi20TRACE();

    eProfile = &map->eProfile[index];

    memcpy(ap->ssid, eProfile->ssid, os_strlen((const char *)eProfile->ssid));
    ap->ssid_len = strlen((const char *)eProfile->ssid);

    res =(u16) strtol((const char *)eProfile->auth, &end, 16);

    if (*end) {
        dprintf(MSG_ERROR, "%s %d String conversion error \n",__func__, __LINE__);
        return -1;
    }

    ap->auth = res;

    res =(u16) strtol((const char *)eProfile->encr, &end, 16);

    if (*end) {
        dprintf(MSG_ERROR, "%s %d String conversion error \n",__func__, __LINE__);
        return -1;
    }

    ap->encr =  res;

    ap->mapbh = atoi((const char *)eProfile->mapbh);
    ap->mapfh = atoi((const char *)eProfile->mapfh);
    memcpy(ap->nw_key, eProfile->nw_key, os_strlen((const char *)eProfile->nw_key));
    ap->nw_key_len = os_strlen((const char *)eProfile->nw_key);
    os_memcpy(ap->nw_key, eProfile->nw_key, ap->nw_key_len);

    dprintf(MSG_MSGDUMP , "MAP SSID %s ssid len %d  \n",ap->ssid, ap->ssid_len);
    dprintf(MSG_MSGDUMP , "MAP AUTH %x  \n", ap->auth);
    dprintf(MSG_MSGDUMP , "MAP ENCR  %x \n",ap->encr);
    dprintf(MSG_MSGDUMP , "MAP nw_key %s \n", ap->nw_key);
    dprintf(MSG_MSGDUMP , "MAP nw_key len %d \n",ap->nw_key_len);
    dprintf(MSG_MSGDUMP , "MAP Fronthaul  %x  \n",ap->mapfh);
    dprintf(MSG_MSGDUMP , "MAP Backhaul  %x  \n",ap->mapbh);

    return 0;
}

u8 apac_map_get_eprofile(struct apac_wps_session* sess,
        u8 *list,
        u8 *requested_m2)
{
    u8  maxBSS = 0, *listptr = NULL;
    u8 i = 0, minop = 0 , maxop = 0, profilecnt = 0;
    apacMapEProfile_t *eProfile = NULL;
    apacHyfi20Data_t *hyfi20 = NULL;
    char buf[1024] = { 0 };
    apacMapData_t *map = NULL;

    apacHyfi20TRACE();

    hyfi20 = sess->pData;

    map = HYFI20ToMAP(hyfi20);

    listptr = list;
    *listptr = 0xff; //default value used in teardown
    *requested_m2 = 1; // max bss to send one teardown

    if (hyfi20->config.role != APAC_REGISTRAR || map->eProfileCnt == 0 ) {
        dprintf(MSG_ERROR, "%s, not registrar or map file not found !\n", __func__);
        return profilecnt;
    }

    snprintf(buf, 13, "%02x%02x%02x%02x%02x%02x ",sess->dest_addr[0],
            sess->dest_addr[1],
            sess->dest_addr[2],
            sess->dest_addr[3],
            sess->dest_addr[4],
            sess->dest_addr[5]);


    for(i = 0 ; i < map->eProfileCnt; i++) {
        eProfile = &map->eProfile[i];

        if (!strncasecmp(buf, eProfile->alId, IEEE80211_ADDR_LEN)) {

            dprintf(MSG_MSGDUMP," %s,%s,%s,%s,%s,%s,%s,%s \n",
                    eProfile->alId,eProfile->opclass,
                    eProfile->ssid,eProfile->auth,eProfile->encr,
                    eProfile->nw_key,eProfile->mapbh,eProfile->mapfh);

            if (!strncasecmp((char *)eProfile->opclass,"11x", 3)) {
                minop = 110;
                maxop = 120;
            } else if (!strncasecmp((char *)eProfile->opclass,"12x", 3)) {
                minop = 121;
                maxop = 130;//to compliant with WFA , ideally it should be 129
            } else if (!strncasecmp((char *)eProfile->opclass,"8x", 2)) {
                minop = 80;
                maxop = 89;
            } else { //opclass not there
                continue;
            }

            dprintf(MSG_DEBUG, "%s Profile based MinOp %d Maxop %d \n",__func__,
                    minop, maxop);

            if (ieee1905MapParseBasicRadioTLV(sess->basicRadioCap,
                        sess->basicRadioCapLen,
                        &maxBSS, minop, maxop) == APAC_TRUE) {
                *listptr++ = i;
                profilecnt++;
            }
        }
    }

    if(*listptr == 0xff) {
        ieee1905MapParseBasicRadioTLV(sess->basicRadioCap,
                sess->basicRadioCapLen,
                &maxBSS, minop, maxop);
        dprintf(MSG_DEBUG, "%s No ALID Match found for MaxBSS = %u \n",__func__,
                maxBSS);
        for (i = 0; i < maxBSS; i++) {
            *listptr++ = 0xff;
        }
    }
    *requested_m2 = maxBSS;

    return profilecnt;
}

u8 apac_map_parse_vendor_ext(struct apac_wps_session *sess,
        u8 *pos,
        u8 len, u8 *mapBssType)
{
    u32 vendor_id;
#define WPS_VENDOR_ID_WFA 14122 //37 2a
#define WFA_ELEM_MAP_BSS_CONFIGURATION 0x06
    apacHyfi20TRACE();

    if (len < 3) {
        dprintf(MSG_DEBUG, "WPS: Skip invalid Vendor Extension");
        return 0;
    }

    vendor_id = WPA_GET_BE24(pos);
    switch (vendor_id) {
        case WPS_VENDOR_ID_WFA:
            len -=3;
            pos +=3;
            const u8 *end = pos + len;
            u8 id, elen;

            while (end - pos >= 2) {
                id = *pos++;
                elen = *pos++;
                if (elen > end - pos)
                    break;

                switch(id) {
                    case WFA_ELEM_MAP_BSS_CONFIGURATION:
                        dprintf(MSG_MSGDUMP,"MAP BSS Configuration %x \n", *pos);
                        *mapBssType = *pos;
                        break;
                }
                pos += elen;
            }
    }
    return 0;
}

apacBool_e map_wps_build_cred_network_idx(struct credbuf *credentials)
{
    dprintf(MSG_MSGDUMP,"Network Index");
    WPA_PUT_BE16(credentials->buf + credentials->len, ATTR_NETWORK_INDEX);
    credentials->len += 2;
    WPA_PUT_BE16(credentials->buf + credentials->len, 1);
    credentials->len += 2;
    credentials->buf[credentials->len++] = 1;
    return APAC_TRUE;
}

apacBool_e map_wps_build_cred_ssid(struct credbuf *credentials, apacMapAP_t *map)
{
    dprintf(MSG_MSGDUMP,"SSID");
    WPA_PUT_BE16(credentials->buf + credentials->len, ATTR_SSID);
    credentials->len += 2;
    WPA_PUT_BE16(credentials->buf + credentials->len, map->ssid_len);
    credentials->len += 2;
    os_memcpy(credentials->buf + credentials->len, map->ssid, map->ssid_len);
    credentials->len += map->ssid_len;
    return APAC_TRUE;
}

apacBool_e map_wps_build_cred_auth_type(struct credbuf *credentials, apacMapAP_t *map)
{
    u16 auth_type = map->auth;
    dprintf(MSG_MSGDUMP,"Authentication Type");

    if (auth_type & WPS_AUTH_WPA2PSK)
        auth_type = WPS_AUTH_WPA2PSK;
    else if (auth_type & WPS_AUTH_WPAPSK)
        auth_type = WPS_AUTH_WPAPSK;
    else if (auth_type & WPS_AUTH_OPEN)
        auth_type = WPS_AUTH_OPEN;

    WPA_PUT_BE16(credentials->buf + credentials->len, ATTR_AUTH_TYPE);
    credentials->len += 2;
    WPA_PUT_BE16(credentials->buf + credentials->len, 2);
    credentials->len += 2;
    WPA_PUT_BE16(credentials->buf + credentials->len, auth_type);
    credentials->len += 2;
    return APAC_TRUE;
}

apacBool_e map_wps_build_cred_encr_type(struct credbuf *credentials, apacMapAP_t *map)
{
    u16 encr_type = map->encr;
    dprintf(MSG_MSGDUMP,"Encryption Type");

    if (map->auth & (WPS_AUTH_WPA2PSK | WPS_AUTH_WPAPSK)) {
        if (encr_type & WPS_ENCR_AES)
            encr_type = WPS_ENCR_AES;
        else if (encr_type & WPS_ENCR_TKIP)
            encr_type = WPS_ENCR_TKIP;
    }

    WPA_PUT_BE16(credentials->buf + credentials->len, ATTR_ENCR_TYPE);
    credentials->len += 2;
    WPA_PUT_BE16(credentials->buf + credentials->len, 2);
    credentials->len += 2;
    WPA_PUT_BE16(credentials->buf + credentials->len, encr_type);
    credentials->len += 2;
    return APAC_TRUE;
}

apacBool_e map_wps_build_cred_network_key(struct credbuf *credentials, apacMapAP_t *map)
{
    dprintf(MSG_MSGDUMP,"Network Key Index");

    WPA_PUT_BE16(credentials->buf + credentials->len, ATTR_NETWORK_KEY_INDEX);
    credentials->len += 2;
    WPA_PUT_BE16(credentials->buf + credentials->len, 1);
    credentials->len += 2;
    credentials->buf[credentials->len++] = 1;

    dprintf(MSG_MSGDUMP,"Network Key");
    WPA_PUT_BE16(credentials->buf + credentials->len, ATTR_NETWORK_KEY);
    credentials->len += 2;
    WPA_PUT_BE16(credentials->buf + credentials->len, map->nw_key_len);
    credentials->len += 2;
    os_memcpy(credentials->buf + credentials->len, map->nw_key, map->nw_key_len);
    credentials->len += map->nw_key_len;
    return APAC_TRUE;
}

apacBool_e map_wps_build_cred_mac_addr(struct credbuf *credentials, apacMapAP_t *map)
{
    u_int8_t macZero[6] = {0};
    dprintf(MSG_MSGDUMP,"MAC ADDR");
    WPA_PUT_BE16(credentials->buf + credentials->len, ATTR_MAC_ADDR);
    credentials->len += 2;
    WPA_PUT_BE16(credentials->buf + credentials->len, ETH_ALEN);
    credentials->len += 2;
    os_memcpy(credentials->buf + credentials->len, macZero , ETH_ALEN);
    credentials->len += ETH_ALEN;
    return APAC_TRUE;
}

apacBool_e apacHyfiMapBuildBackHaulCred(apacMapAP_t *map,u8 radioIdx)
{
    struct credbuf credentials;
    credentials.len = 0;
    u8 *totalLen = NULL;
    u8 *bufptr = credentials.buf;
    char filename[30];
    FILE *fp;

    snprintf(filename,2,"/var/hostapd_cred_wifi%d.bin",radioIdx - 1);
    fp = fopen(filename,"wb");

    /* Fill Auth Type */
    WPA_PUT_BE16(credentials.buf + credentials.len, ATTR_CRED);
    credentials.len += 2;
    totalLen = credentials.buf + credentials.len;
    credentials.len += 2;

    /* Fill Network */
    map_wps_build_cred_network_idx(&credentials);

    /* Fill SSID */
    map_wps_build_cred_ssid(&credentials,map);

    /* Fill Auth Type */
    map_wps_build_cred_auth_type(&credentials,map);

    /* Fill Encryption Type */
    map_wps_build_cred_encr_type(&credentials,map);

    /* Fill Network Key */
    map_wps_build_cred_network_key(&credentials,map);

    /* Fill Mac Addr */
    map_wps_build_cred_mac_addr(&credentials,map);

    *(u_int16_t*)totalLen = htons(credentials.len - 4);

    if (fp) {
        fwrite(bufptr , 1 , credentials.len , fp );
        fclose(fp);
    }

    return APAC_TRUE;
}
