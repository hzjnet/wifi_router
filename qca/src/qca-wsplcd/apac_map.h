/*
 * @@-COPYRIGHT-START-@@
 *
 * Copyright (c) 2018 Qualcomm Technologies, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 * @@-COPYRIGHT-END-@@
 */

#include "wsplcd.h"
#include "apclone.h"
#include "eloop.h"

#include "apac_hyfi20_wps.h"
#include "apac_hyfi20_mib.h"
#include "apac_priv.h"

/* Authentication Type Flags */
#define WPS_AUTH_OPEN 0x0001
#define WPS_AUTH_WPAPSK 0x0002
#define WPS_AUTH_SHARED 0x0004 /* deprecated */
#define WPS_AUTH_WPA 0x0008
#define WPS_AUTH_WPA2 0x0010
#define WPS_AUTH_WPA2PSK 0x0020
#define WPS_AUTH_TYPES (WPS_AUTH_OPEN | WPS_AUTH_WPAPSK | WPS_AUTH_SHARED | \
        WPS_AUTH_WPA | WPS_AUTH_WPA2 | WPS_AUTH_WPA2PSK)

/* Encryption Type Flags */
#define WPS_ENCR_NONE 0x0001
#define WPS_ENCR_WEP 0x0002 /* deprecated */
#define WPS_ENCR_TKIP 0x0004
#define WPS_ENCR_AES 0x0008
#define WPS_ENCR_TYPES (WPS_ENCR_NONE | WPS_ENCR_WEP | WPS_ENCR_TKIP | \
        WPS_ENCR_AES)

enum map_wps_attribute {
    ATTR_AUTH_TYPE = 0x1003,
    ATTR_CRED = 0x100e,
    ATTR_NETWORK_INDEX = 0x1026,
    ATTR_SSID = 0x1045,
    ATTR_ENCR_TYPE = 0x100f,
    ATTR_NETWORK_KEY_INDEX = 0x1028,
    ATTR_NETWORK_KEY = 0x1027,
    ATTR_MAC_ADDR = 0x1020
};

struct credbuf {
    u8 len;
    u8 buf[200];
};

apacBool_e apacHyfiMapIsEnabled(apacMapData_t *map);

int apacHyfiMapSendMultipleM2(struct apac_wps_session *sess);

apacBool_e apacHyfiMapParse1905TLV(struct apac_wps_session *sess,
        u8 *content, u32 contentLen,
        struct wps_tlv *container,
        s32 maxContainerSize, u8 *ieParsed);

apacBool_e apacHyfiMapInit(apacMapData_t *map);
apacBool_e apacHyfiMapDInit(apacMapData_t *map);
apacBool_e apacHyfiMapConfigDump(apacMapData_t *map);
apacBool_e apacHyfiMapBuildBackHaulCred(apacMapAP_t *map, u8 radioIdx);

int apacGetPIFMapCap( apacHyfi20Data_t *pData);

ieee1905TLV_t *ieee1905MapAddBasicRadioTLV(ieee1905TLV_t *TLV,
        u_int32_t *Len,
        u8 band,
        apacHyfi20Data_t *pData);

u8 apac_map_get_eprofile(struct apac_wps_session* sess, u8 *list, u8 *requested_m2);

u8 apac_map_get_configured_maxbss(struct apac_wps_session *sess);

u8 apac_map_parse_vendor_ext(struct apac_wps_session *sess,
        u8 *vendor_ext,
        u8 vendor_ext_len,
        u8 *mapBssType);

u8 apac_map_copy_apinfo(apacMapData_t *map,
        apacHyfi20AP_t *ap,
        u8 index);
