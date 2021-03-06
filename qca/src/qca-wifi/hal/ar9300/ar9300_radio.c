/*
 * Copyright (c) 2011, 2017 Qualcomm Innovation Center, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * Copyright (c) 2008-2010 Atheros Communications Inc.
 * All Rights Reserved.
 *
 * 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 * 
 */

#include "opt_ah.h"

#ifdef AH_SUPPORT_AR9300

#include "ah.h"
#include "ah_internal.h"

#include "ar9300/ar9300.h"
#include "ar9300/ar9300reg.h"
#include "ar9300/ar9300phy.h"

/* chansel table, used by Hornet and Poseidon */
static const u_int32_t ar9300_chansel_xtal_25M[] = {
    0x101479e, /* Freq 2412 - (128 << 17) + 83870  */
    0x101d027, /* Freq 2417 - (128 << 17) + 118823 */
    0x10258af, /* Freq 2422 - (129 << 17) + 22703  */
    0x102e138, /* Freq 2427 - (129 << 17) + 57656  */
    0x10369c0, /* Freq 2432 - (129 << 17) + 92608  */
    0x103f249, /* Freq 2437 - (129 << 17) + 127561 */
    0x1047ad1, /* Freq 2442 - (130 << 17) + 31441  */
    0x105035a, /* Freq 2447 - (130 << 17) + 66394  */
    0x1058be2, /* Freq 2452 - (130 << 17) + 101346 */
    0x106146b, /* Freq 2457 - (131 << 17) + 5227   */
    0x1069cf3, /* Freq 2462 - (131 << 17) + 40179  */
    0x107257c, /* Freq 2467 - (131 << 17) + 75132  */
    0x107ae04, /* Freq 2472 - (131 << 17) + 110084 */
    0x108f5b2, /* Freq 2484 - (132 << 17) + 62898  */
};

static const u_int32_t ar9300_chansel_xtal_40M[] = {
    0xa0ccbe, /* Freq 2412 - (80 << 17) + 52414  */
    0xa12213, /* Freq 2417 - (80 << 17) + 74259  */
    0xa17769, /* Freq 2422 - (80 << 17) + 96105  */
    0xa1ccbe, /* Freq 2427 - (80 << 17) + 117950 */
    0xa22213, /* Freq 2432 - (81 << 17) + 8723   */
    0xa27769, /* Freq 2437 - (81 << 17) + 30569  */
    0xa2ccbe, /* Freq 2442 - (81 << 17) + 52414  */
    0xa32213, /* Freq 2447 - (81 << 17) + 74259  */
    0xa37769, /* Freq 2452 - (81 << 17) + 96105  */
    0xa3ccbe, /* Freq 2457 - (81 << 17) + 117950 */
    0xa42213, /* Freq 2462 - (82 << 17) + 8723   */
    0xa47769, /* Freq 2467 - (82 << 17) + 30569  */
    0xa4ccbe, /* Freq 2472 - (82 << 17) + 52414  */
    0xa5998b, /* Freq 2484 - (82 << 17) + 104843 */
};

/*
 * Take the MHz channel value and set the Channel value
 *
 * ASSUMES: Writes enabled to analog bus
 *
 * Actual Expression,
 *
 * For 2GHz channel,
 * Channel Frequency = (3/4) * freq_ref * (chansel[8:0] + chanfrac[16:0]/2^17)
 * (freq_ref = 40MHz)
 *
 * For 5GHz channel,
 * Channel Frequency = (3/2) * freq_ref * (chansel[8:0] + chanfrac[16:0]/2^10)
 * (freq_ref = 40MHz/(24>>amode_ref_sel))
 *
 * For 5GHz channels which are 5MHz spaced,
 * Channel Frequency = (3/2) * freq_ref * (chansel[8:0] + chanfrac[16:0]/2^17)
 * (freq_ref = 40MHz)
 */

static bool
ar9300_set_channel(struct ath_hal *ah,  HAL_CHANNEL_INTERNAL *chan)
{
    struct ath_hal_9300 *ahp = AH9300(ah);
    int doubling_enabled = ar9300_eeprom_get(ahp, EEP_DOUBLING_ENABLED);
    u_int16_t b_mode, frac_mode = 0, a_mode_ref_sel = 0;
    u_int32_t freq, channel_sel, reg32;
    u_int8_t clk_25mhz = AH9300(ah)->clk_25mhz;
    CHAN_CENTERS centers;
#ifdef AR9300_EMULATION_BB
#if !defined(AR9330_EMULATION) && !defined(AR9485_EMULATION) && !defined(AR956X_EMULATION)
    /* conditional def to avoid compilation warnings for unused variables */
    u_int32_t ndiv, channel_frac = 0;
    u_int32_t ref_div_a = 24;
#endif
#else /* Silicon */
    int load_synth_channel;
#endif /* AR9300_EMULATION_BB */
	u_int32_t	clk_mhz;
    OS_MARK(ah, AH_MARK_SETCHANNEL, chan->channel);

    ar9300_get_channel_centers(ah, chan, &centers);
    freq = centers.synth_center;

#ifdef AR9300_EMULATION_BB
    clk_25mhz = 0;
    reg32 = OS_REG_READ(ah, AR_PHY_SYNTH_CONTROL);
    reg32 &= 0xc0000000;
#endif /* AR9300_EMULATION_BB */
    if (freq < 4800) {     /* 2 GHz, fractional mode */
        b_mode = 1; /* 2 GHz */
#ifdef AR9300_EMULATION_BB
        frac_mode = 1;
        a_mode_ref_sel = 0;
        channel_sel = CHANSEL_2G(freq);
#else /* Silicon */

        if (AR_SREV_HORNET(ah)) {
            u_int32_t ichan = ath_hal_mhz2ieee(ah, freq, chan->channel_flags);
            HALASSERT(ichan > 0 && ichan <= 14);
            if (clk_25mhz) {
                channel_sel = ar9300_chansel_xtal_25M[ichan - 1];
            } else {
                channel_sel = ar9300_chansel_xtal_40M[ichan - 1];
            }
        } else if (AR_SREV_POSEIDON(ah) || AR_SREV_APHRODITE(ah)) {
            u_int32_t channel_frac;
            /* 
             * freq_ref = (40 / (refdiva >> a_mode_ref_sel));
             *     (where refdiva = 1 and amoderefsel = 0)
             * ndiv = ((chan_mhz * 4) / 3) / freq_ref;
             * chansel = int(ndiv),  chanfrac = (ndiv - chansel) * 0x20000
             */
            channel_sel = (freq * 4) / 120;
            channel_frac = (((freq * 4) % 120) * 0x20000) / 120;
            channel_sel = (channel_sel << 17) | (channel_frac);
         } else if (AR_SREV_WASP(ah) || AR_SREV_SCORPION(ah) || AR_SREV_HONEYBEE(ah) || AR_SREV_DRAGONFLY(ah) || AR_SREV_JET(ah)) {
            u_int32_t channel_frac;
            if (clk_25mhz) {
                /* 
                 * freq_ref = (50 / (refdiva >> a_mode_ref_sel));
                 *     (where refdiva = 1 and amoderefsel = 0)
                 * ndiv = ((chan_mhz * 4) / 3) / freq_ref;
                 * chansel = int(ndiv),  chanfrac = (ndiv - chansel) * 0x20000
                 */
                if (AR_SREV_SCORPION(ah) || AR_SREV_HONEYBEE(ah) || AR_SREV_DRAGONFLY(ah) || AR_SREV_JET(ah)) {
					clk_mhz=25;

					if (AR_SREV_JET(ah) && doubling_enabled) {
                    /* Doubler is off for Scorpion */
						 clk_mhz=50;
                         OS_REG_RMW_FIELD_2(ah, SYNTH7, CHANSEL, 0x40);
                         OS_REG_RMW_FIELD_2(ah, SYNTH12, CLK_DOUBLER_EN, 0x0);
                         OS_REG_RMW_FIELD_2(ah, SYNTH12, XTAL_CLK_DIV2_EN, 0x1);
                         OS_REG_RMW_FIELD_2(ah, SYNTH13, REFDIVA_FRACN        , 0x1);
                         OS_REG_RMW_FIELD_2(ah, SYNTH8, REFDIVB               , 0x0);
                         OS_REG_RMW_FIELD_2(ah, SYNTH9, REFDIVA               , 0x0);
                         OS_REG_RMW_FIELD_2(ah, SYNTH10, INVCLK_SYNTHANA2 , 0x1);
                         OS_REG_RMW_FIELD_2(ah, SYNTH10, INVCLK_SYNTHDIG  , 0x1);
                         OS_REG_RMW_FIELD_2(ah, XTAL, XTAL_DOUBLE                 , 0x1);
                         OS_REG_RMW_FIELD_2(ah, XTAL, XTAL_DUTY                   , 0x1);
                         OS_REG_RMW_FIELD_2(ah, XTAL2, XTAL_LOCALBIAS             , 0x0);
					}
                    channel_sel = (freq * 4) / (3*clk_mhz);
                    channel_frac = (((freq * 4) % (3*clk_mhz)) * 0x20000) / (3*clk_mhz);
                } else {
                    channel_sel = (freq * 2) / 75;
                    channel_frac = (((freq * 2) % 75) * 0x20000) / 75;
                }
            } else {
                /* 
                 * freq_ref = (50 / (refdiva >> a_mode_ref_sel));
                 *     (where refdiva = 1 and amoderefsel = 0)
                 * ndiv = ((chan_mhz * 4) / 3) / freq_ref;
                 * chansel = int(ndiv),  chanfrac = (ndiv - chansel) * 0x20000
                 */
                if (AR_SREV_SCORPION(ah) || AR_SREV_HONEYBEE(ah) || AR_SREV_DRAGONFLY(ah) || AR_SREV_JET(ah)) {
                    /* Doubler is off for Scorpion */
                    channel_sel = (freq * 4) / 120;
                    channel_frac = (((freq * 4) % 120) * 0x20000) / 120;
                } else {
                    channel_sel = (freq * 2) / 120;
                    channel_frac = (((freq * 2) % 120) * 0x20000) / 120;
                }
            }
            channel_sel = (channel_sel << 17) | (channel_frac);
        } else {
            channel_sel = CHANSEL_2G(freq);
        }
#endif /* AR9300_EMULATION_BB */
    } else {
        b_mode = 0; /* 5 GHz */
#ifdef AR9340_EMULATION
        if (!frac_mode) {
            if ((freq % 20) == 0) {
                a_mode_ref_sel = 3;
            } else if ((freq % 10) == 0) {
                a_mode_ref_sel = 2;
            }
            ndiv = (freq * (ref_div_a >> a_mode_ref_sel)) / 60;
            channel_sel =  ndiv & 0x1ff;         
            channel_frac = (ndiv & 0xfffffe00) * 2;
            channel_sel = (channel_sel << 17) | channel_frac;
        }
#else
        if ((AR_SREV_WASP(ah) || AR_SREV_SCORPION(ah) || AR_SREV_HONEYBEE(ah) || AR_SREV_DRAGONFLY(ah) || AR_SREV_JET(ah)) && clk_25mhz){
            u_int32_t channel_frac;
            /* 
             * freq_ref = (50 / (refdiva >> amoderefsel));
             *     (refdiva = 1, amoderefsel = 0)
             * ndiv = ((chan_mhz * 2) / 3) / freq_ref;
             * chansel = int(ndiv),  chanfrac = (ndiv - chansel) * 0x20000
             */
            channel_sel = freq / 75 ;
            channel_frac = ((freq % 75) * 0x20000) / 75;
            channel_sel = (channel_sel << 17) | (channel_frac);
        } else {
            channel_sel = CHANSEL_5G(freq);
            /* Doubler is ON, so, divide channel_sel by 2. */
            channel_sel >>= 1;
        }
#endif
    }

#ifdef AR9300_EMULATION_BB

    reg32 |=
        (b_mode       << 29) |
        (frac_mode    << 28) |
        (a_mode_ref_sel << 26) |
        channel_sel;

    /* Set short shift */
    reg32 |= (1 << 30);
    OS_REG_WRITE(ah, AR_PHY_SYNTH_CONTROL, reg32);

#else /* Silicon */

	/* Enable fractional mode for all channels */
    frac_mode = 1;
    a_mode_ref_sel = 0;
    load_synth_channel = 0;
    
    reg32 = (b_mode << 29);
    OS_REG_WRITE(ah, AR_PHY_SYNTH_CONTROL, reg32);

	/* Enable Long shift Select for Synthesizer */
    OS_REG_RMW_FIELD(ah,
        AR_PHY_65NM_CH0_SYNTH4, AR_PHY_SYNTH4_LONG_SHIFT_SELECT, 1);

    /* program synth. setting */
    reg32 =
        (channel_sel       <<  2) |
        (a_mode_ref_sel      << 28) |
        (frac_mode         << 30) |
        (load_synth_channel << 31);
    if (IS_CHAN_QUARTER_RATE(chan)) {
        reg32 += CHANSEL_5G_DOT5MHZ;
    }
    OS_REG_WRITE(ah, AR_PHY_65NM_CH0_SYNTH7, reg32);
    /* Toggle Load Synth channel bit */
    load_synth_channel = 1;
    reg32 |= load_synth_channel << 31;
    OS_REG_WRITE(ah, AR_PHY_65NM_CH0_SYNTH7, reg32);

#endif /* AR9300_EMULATION_BB */
    AH_PRIVATE(ah)->ah_curchan = chan;

    return true;
}

#if defined(JUPITER_EMULATION) || defined(AR9300_EMULATION_BB)
static bool
ar93xx_set_channel(struct ath_hal *ah,  HAL_CHANNEL_INTERNAL *chan)
{
    u_int16_t b_mode, frac_mode = 0, a_mode_ref_sel = 0;
    u_int32_t freq, channel_sel = 0, reg32 = 0;
    CHAN_CENTERS centers;
    // u_int32_t ndiv;
    u_int32_t load_synth_channel = 1;

    OS_MARK(ah, AH_MARK_SETCHANNEL, chan->channel);

    ar9300_get_channel_centers(ah, chan, &centers);
    freq = centers.synth_center;
    reg32 = OS_REG_READ(ah, AR_PHY_SYNTH_CONTROL);
    reg32 &= 0xc0000000;

    if (freq < 4800) {     /* 2 GHz, fractional mode */
        b_mode = 1;
        frac_mode = 1;
        a_mode_ref_sel = 0;
        channel_sel = CHANSEL_2G(freq);
    }
    else {
        channel_sel = CHANSEL_5G(freq);
        /* Doubler is ON, so, divide channel_sel by 2. */
        channel_sel >>= 1;
        /* Set to 5G mode */
        b_mode = 0;
    }

    reg32 = reg32 |
        (b_mode << 29) |
        (frac_mode << 28) |
        (a_mode_ref_sel << 26) |
        channel_sel;

    OS_DELAY(1000);

    // Set long shift
    reg32 &= ~(1 << 30);
    OS_REG_WRITE(ah, AR_PHY_SYNTH_CONTROL, reg32);
    ath_hal_printf(ah, "%s: chan = %d, AR_SYNTH_CONTROL = 0x%x\n",
        __func__, chan->channel, reg32);
    OS_DELAY(400);

    OS_REG_WRITE(ah, AR_MERLIN_RADIO_SYNTH4, 0x1000580b);
    OS_DELAY(1000);// extra
    ath_hal_printf(ah, "%s: SYNTH4 = 0x%x\n", __func__,
        OS_REG_READ(ah, AR_MERLIN_RADIO_SYNTH4));

    OS_DELAY(1000);

    reg32 = OS_REG_READ(ah, AR_MERLIN_RADIO_SYNTH7);
    reg32 |= (load_synth_channel << 31);
    OS_DELAY(1000);// extra
    OS_REG_WRITE(ah, AR_MERLIN_RADIO_SYNTH7, reg32);

    OS_DELAY(1000);
    load_synth_channel = 0;
    reg32 = (channel_sel << 2) | (frac_mode << 30) | (a_mode_ref_sel << 28)
        | (load_synth_channel << 31);
    OS_REG_WRITE(ah, AR_MERLIN_RADIO_SYNTH7, reg32);
    OS_DELAY(1000); // extra
    ath_hal_printf(ah, "%s: SYNTH7 = 0x%x\n", __func__,
        OS_REG_READ(ah, AR_MERLIN_RADIO_SYNTH7));

    OS_DELAY(1000);

    AH_PRIVATE(ah)->ah_curchan = chan;

    return true;
}
#endif
static bool
ar9300_get_chip_power_limits(struct ath_hal *ah, HAL_CHANNEL *chans,
                         u_int32_t nchans)
{
    int i;

    for (i = 0; i < nchans; i++) {
        chans[i].max_tx_power = AR9300_MAX_RATE_POWER;
        chans[i].min_tx_power = AR9300_MAX_RATE_POWER;
    }
    return true;
}

bool
ar9300_rf_attach(struct ath_hal *ah, HAL_STATUS *status)
{
    struct ath_hal_9300 *ahp = AH9300(ah);

#if defined(JUPITER_EMULATION) || defined(AR9300_EMULATION_BB)
    ahp->ah_rf_hal.set_channel    = ar93xx_set_channel;
#else
    ahp->ah_rf_hal.set_channel    = ar9300_set_channel;
#endif
    ahp->ah_rf_hal.get_chip_power_lim   = ar9300_get_chip_power_limits;

    *status = HAL_OK;

    return true;
}

#endif /* AH_SUPPORT_AR9300 */
