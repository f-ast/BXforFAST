
çÔ2/* ssl/d1_both.c */2É/* $
$ * DTLS implementation written by Nagendra Modadugu$
$ * (nagendra@cs.stanford.edu) for the OpenSSL project 2005.  $
$ */2∂±/* ====================================================================$
$ * Copyright (c) 1998-2005 The OpenSSL Project.  All rights reserved.$
$ *$
$ * Redistribution and use in source and binary forms, with or without$
$ * modification, are permitted provided that the following conditions$
$ * are met:$
$ *$
$ * 1. Redistributions of source code must retain the above copyright$
$ *    notice, this list of conditions and the following disclaimer. $
$ *$
$ * 2. Redistributions in binary form must reproduce the above copyright$
$ *    notice, this list of conditions and the following disclaimer in$
$ *    the documentation and/or other materials provided with the$
$ *    distribution.$
$ *$
$ * 3. All advertising materials mentioning features or use of this$
$ *    software must display the following acknowledgment:$
$ *    "This product includes software developed by the OpenSSL Project$
$ *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"$
$ *$
$ * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to$
$ *    endorse or promote products derived from this software without$
$ *    prior written permission. For written permission, please contact$
$ *    openssl-core@openssl.org.$
$ *$
$ * 5. Products derived from this software may not be called "OpenSSL"$
$ *    nor may "OpenSSL" appear in their names without prior written$
$ *    permission of the OpenSSL Project.$
$ *$
$ * 6. Redistributions of any form whatsoever must retain the following$
$ *    acknowledgment:$
$ *    "This product includes software developed by the OpenSSL Project$
$ *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"$
$ *$
$ * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY$
$ * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE$
$ * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR$
$ * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR$
$ * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,$
$ * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT$
$ * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;$
$ * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)$
$ * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,$
$ * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)$
$ * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED$
$ * OF THE POSSIBILITY OF SUCH DAMAGE.$
$ * ====================================================================$
$ *$
$ * This product includes cryptographic software written by Eric Young$
$ * (eay@cryptsoft.com).  This product includes software written by Tim$
$ * Hudson (tjh@cryptsoft.com).$
$ *$
$ */2”Œ/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)$
$ * All rights reserved.$
$ *$
$ * This package is an SSL implementation written$
$ * by Eric Young (eay@cryptsoft.com).$
$ * The implementation was written so as to conform with Netscapes SSL.$
$ * $
$ * This library is free for commercial and non-commercial use as long as$
$ * the following conditions are aheared to.  The following conditions$
$ * apply to all code found in this distribution, be it the RC4, RSA,$
$ * lhash, DES, etc., code; not just the SSL code.  The SSL documentation$
$ * included with this distribution is covered by the same copyright terms$
$ * except that the holder is Tim Hudson (tjh@cryptsoft.com).$
$ * $
$ * Copyright remains Eric Young's, and as such any Copyright notices in$
$ * the code are not to be removed.$
$ * If this package is used in a product, Eric Young should be given attribution$
$ * as the author of the parts of the library used.$
$ * This can be in the form of a textual message at program startup or$
$ * in documentation (online or textual) provided with the package.$
$ * $
$ * Redistribution and use in source and binary forms, with or without$
$ * modification, are permitted provided that the following conditions$
$ * are met:$
$ * 1. Redistributions of source code must retain the copyright$
$ *    notice, this list of conditions and the following disclaimer.$
$ * 2. Redistributions in binary form must reproduce the above copyright$
$ *    notice, this list of conditions and the following disclaimer in the$
$ *    documentation and/or other materials provided with the distribution.$
$ * 3. All advertising materials mentioning features or use of this software$
$ *    must display the following acknowledgement:$
$ *    "This product includes cryptographic software written by$
$ *     Eric Young (eay@cryptsoft.com)"$
$ *    The word 'cryptographic' can be left out if the rouines from the library$
$ *    being used are not cryptographic related :-).$
$ * 4. If you include any Windows specific code (or a derivative thereof) from $
$ *    the apps directory (application code) you must include an acknowledgement:$
$ *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"$
$ * $
$ * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND$
$ * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE$
$ * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE$
$ * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE$
$ * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL$
$ * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS$
$ * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)$
$ * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT$
$ * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY$
$ * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF$
$ * SUCH DAMAGE.$
$ * $
$ * The licence and distribution terms for any publically available version or$
$ * derivative of this code cannot be changed.  i.e. this code cannot simply be$
$ * copied and put under another distribution licence$
$ * [including the GNU Public Licence.]$
$ */2+»#2óinclude2±&lt;limits.h&gt;2+»#2óinclude2±&lt;string.h&gt;2*»#2óinclude2±&lt;stdio.h&gt;2'»#2óinclude2±"ssl_locl.h"23»#2óinclude2±&lt;openssl/buffer.h&gt;21»#2óinclude2±&lt;openssl/rand.h&gt;24»#2óinclude2±&lt;openssl/objects.h&gt;20»#2óinclude2±&lt;openssl/evp.h&gt;21»#2óinclude2±&lt;openssl/x509.h&gt;2k…#2ódefine2:26RSMBLY_BITMASK_SIZE2e(2f2926msg_len:)2 (((msg_len) + 7) / 8)2»…#2ódefine2d26RSMBLY_BITMASK_MARK2Ge(2f2926bitmask:,2f292	6start:,2f2926end:)2Ã ∆{ \$
$                        if ((end) - (start) &lt;= 8) { \$
$                                long ii; \$
$                                for (ii = (start); ii &lt; (end); ii++) bitmask[((ii) &gt;&gt; 3)] |= (1 &lt;&lt; ((ii) &amp; 7)); \$
$                        } else { \$
$                                long ii; \$
$                                bitmask[((start) &gt;&gt; 3)] |= bitmask_start_values[((start) &amp; 7)]; \$
$                                for (ii = (((start) &gt;&gt; 3) + 1); ii &lt; ((((end) - 1)) &gt;&gt; 3); ii++) bitmask[ii] = 0xff; \$
$                                bitmask[(((end) - 1) &gt;&gt; 3)] |= bitmask_end_values[((end) &amp; 7)]; \$
$                        } }2Ó…#2ódefine2u26RSMBLY_BITMASK_IS_COMPLETE2Qe(2f2926bitmask:,2f2926msg_len:,2f2926is_complete:)2· €{ \$
$                        long ii; \$
$                        OPENSSL_assert((msg_len) &gt; 0); \$
$                        is_complete = 1; \$
$                        if (bitmask[(((msg_len) - 1) &gt;&gt; 3)] != bitmask_end_values[((msg_len) &amp; 7)]) is_complete = 0; \$
$                        if (is_complete) for (ii = (((msg_len) - 1) &gt;&gt; 3) - 1; ii &gt;= 0 ; ii--) \$
$                                if (bitmask[ii] != 0xff) { is_complete = 0; break; } }2û#2óif22	00J2ï…#2ódefine2S26RSMBLY_BITMASK_PRINT25e(2f2926bitmask:,2f2926msg_len:)2™ §{ \$
$                        long ii; \$
$                        printf("bitmask: "); for (ii = 0; ii &lt; (msg_len); ii++) \$
$                        printf("%d ", (bitmask[ii &gt;&gt; 3] &amp; (1 &lt;&lt; (ii &amp; 7))) &gt;&gt; (ii &amp; 7)); \$
$                        printf("\n"); }2À#2
óendif2ñ2ë2ÿstatic2926unsigned26char2$626bitmask_start_values2>[]2∫=2≤2≠<{2200xffJ:,2200xfeJ:,2200xfcJ:,2200xf8J:,2200xf0J:,2200xe0J:,2200xc0J:,2200x80J:}:;2î2è2ÿstatic2926unsigned26char2"626bitmask_end_values2>[]2∫=2≤2≠<{2200xffJ:,2200x01J:,2200x03J:,2200x07J:,2200x0fJ:,2200x1fJ:,2200x3fJ:,2200x7fJ:}:;2-)/* XDTLS:  figure out the right values */2€2÷2ÿstatic2926unsigned26int2626g_probable_mtu2>[]2Ü=22{<{2&201500J24-2
028J:,2%20512J24-2
028J:,2%20256J24-2
028J:}:;2}2ÿstatic2926unsigned26int26dtls1_guess_mtu2<e(22f2+2926unsigned26int26curr_mtu:):;2÷2ÿstatic2926void26dtls1_fix_message_header2òe(2$f22926SSL25*26s:,23f2,2926unsigned26long26frag_off:,23f2,2926unsigned26long26frag_len:):;2∑2ÿstatic2!926unsigned26char25*26dtls1_write_message_header2ce(2$f22926SSL25*26s:,23f2,2!926unsigned26char25*26p:):;2Ó2ÿstatic2926void2 6dtls1_set_message_header_int2¨e(2$f22926SSL25*26s:,2-f2&2926unsigned26char26mt:,2.f2'2926unsigned26long26len:,23f2,2926unsigned2	6short26seq_num:,23f2,2926unsigned26long26frag_off:,23f2,2926unsigned26long26frag_len:):;2˘2ÿstatic2926long26dtls1_get_message_fragment2πe(2$f22926SSL25*26s:,2f22926int26st1:,2f22926int26stn:,2 f22926long26max:,2%f22926int25*26ok:):;2ö2ÿstatic2926hm_fragment25*26dtls1_hm_fragment_new2be(23f2,2926unsigned26long26frag_len:,2&f22926int26
reassembly:)2Ì<{2D2@2926hm_fragment25*26frag2=226NULL:;2J2F2!926unsigned26char25*26buf2=226NULL:;2N2J2!926unsigned26char25*26bitmask2=226NULL:;2õ2ñ26frag24=24(26hm_fragment24*24)2X26OPENSSL_malloc2@i(29j222.®sizeof2!i(2j226hm_fragment:):):;2Wûif2(;(2!26frag24==26NULL:)2$C2 <2«return226NULL:;2œûif2;(226frag_len:)2©C2§<{2~2z26buf24=24(26unsigned26char24*24)2626OPENSSL_malloc2i(2j226frag_len:):;2úûif2';(2 26buf24==26NULL:)2gC2c<{2;272026OPENSSL_free2i(2j226frag:):;2«return226NULL:;:}:}2:6/* zero length fragment gets zero frag-&gt;fragment */2@2<2%626frag2	4-&gt;26fragment24=26buf:;240/* Initialize reassembly bitmask if necessary */2ùûif2;(226
reassembly:)2ıC2<{2≤2≠26bitmask24=24(26unsigned26char24*24)2e26OPENSSL_malloc2Mi(2Fj2?2;26RSMBLY_BITMASK_SIZE2i(2j226frag_len:):):;2ïûif2+;(2$26bitmask24==26NULL:)2ﬁC2Ÿ<{2tûif2';(2 26buf24!=26NULL:)2BC2><2:262/26OPENSSL_free2i(2j226buf:):;2;272026OPENSSL_free2i(2j226frag:):;2«return226NULL:;:}2õ2ì2ã2
6memset2{i(2j226bitmask:,2j22	00J:,2Fj2?2;26RSMBLY_BITMASK_SIZE2i(2j226frag_len:):):;:}2F2B2'626frag2	4-&gt;26
reassembly24=26bitmask:;2«return226frag:;:}2•2ÿstatic2926void26dtls1_hm_fragment_free26e(2/f2(2926hm_fragment25*26frag:)2±<{2£ûif2H;(2A2:626frag2	4-&gt;26
msg_header24.2
6is_ccs:)2œC2 <{2†2õ2ì26EVP_CIPHER_CTX_free2vi(2oj2h2d626frag2	4-&gt;26
msg_header24.26saved_retransmit_state24.26enc_write_ctx:):;2ü2ó2è26EVP_MD_CTX_destroy2si(2lj2e2a626frag2	4-&gt;26
msg_header24.26saved_retransmit_state24.26
write_hash:):;:}2ûûif23;(2,2%626frag2	4-&gt;26fragment:)2`C2\<2X2T2M26OPENSSL_free27i(20j2)2%626frag2	4-&gt;26fragment:):;2¢ûif25;(2.2'626frag2	4-&gt;26
reassembly:)2bC2^<2Z2V2O26OPENSSL_free29i(22j2+2'626frag2	4-&gt;26
reassembly:):;2>272026OPENSSL_free2i(2j226frag:):;:}2ie/* send s-&gt;init_buf in records of type 'type' (SSL3_RT_HANDSHAKE or SSL3_RT_CHANGE_CIPHER_SPEC) */2ŸR2926int26dtls1_do_write2Me(2$f22926SSL25*26s:,2 f22926int26type:)2‰Q<{222926int26ret:;2$2 2926int26curr_mtu:;2û2)2926unsigned26int26len:,2N2995This is just a placeholder. Please ignore this child.26frag_off:,2N2995This is just a placeholder. Please ignore this child.26mac_size:,2O2995This is just a placeholder. Please ignore this child.26	blocksize:;2?;/* AHA!  Figure out the MTU, and stick to the right size */2‹	ûif2„;(2€20626s2	4-&gt;26d12	4-&gt;26mtu24&lt;226dtls1_min_mtu2i()24
&amp;&amp;24!24(2026SSL_get_options2i(2j2	26s:)2	4&amp;26SSL_OP_NO_QUERY_MTU24):)2ÏC2Á<{2Ï2Á20626s2	4-&gt;26d12	4-&gt;26mtu24=2¶26BIO_ctrl2ìi(28j212-26SSL_get_wbio2i(2j2	26s:):,2'j2 26BIO_CTRL_DGRAM_QUERY_MTU:,2j22	00J:,2j226NULL:):;2ùò/* I've seen the kernel return bogus numbers when it doesn't know$
$                 * (initial write), so just make sure we have a reasonable number */2–ûif2g;(2`20626s2	4-&gt;26d12	4-&gt;26mtu24&lt;226dtls1_min_mtu2i():)2⁄C2’<{2M2I20626s2	4-&gt;26d12	4-&gt;26mtu24=2	00J:;2†2õ20626s2	4-&gt;26d12	4-&gt;26mtu24=2[26dtls1_guess_mtu2Bi(2;j2420626s2	4-&gt;26d12	4-&gt;26mtu:):;2€2”2À26BIO_ctrl2∏i(28j212-26SSL_get_wbio2i(2j2	26s:):,2%j226BIO_CTRL_DGRAM_SET_MTU:,2;j2420626s2	4-&gt;26d12	4-&gt;26mtu:,2j226NULL:):;:}:}2Áû#2óif22	00J:∆mtu = s-&gt;d1-&gt;mtu;$
$$
$        fprintf(stderr, "using MTU = %d\n", mtu);$
$$
$        mtu -= (DTLS1_HM_HEADER_LENGTH + DTLS1_RT_HEADER_LENGTH);$
$$
$        curr_mtu = mtu - BIO_wpending(SSL_get_wbio(s));$
$$
$        if ( curr_mtu &gt; 0)$
$                mtu = curr_mtu;$
$        else if ( ( ret = BIO_flush(SSL_get_wbio(s))) &lt;= 0)$
$                return ret;$
$$
$        if ( BIO_wpending(SSL_get_wbio(s)) + s-&gt;init_num &gt;= mtu)$
$                {$
$                ret = BIO_flush(SSL_get_wbio(s));$
$                if ( ret &lt;= 0)$
$                        return ret;$
$                mtu = s-&gt;d1-&gt;mtu - (DTLS1_HM_HEADER_LENGTH + DTLS1_RT_HEADER_LENGTH);$
$                }2À#2
óendif2ë2å2Ñ26OPENSSL_assert2li(2ej2^20626s2	4-&gt;26d12	4-&gt;26mtu2	4&gt;=226dtls1_min_mtu2i():):;2.*/* should have something reasonable now */2¸ûif2|;(2u2"626s2	4-&gt;26init_off24==2	00J24
&amp;&amp;26type24==26SSL3_RT_HANDSHAKE:)2ÙC2Ô<2Í2Â2›26OPENSSL_assert2ƒi(2ºj2¥2"626s2	4-&gt;26init_num24==24(26int24)2J626s2	4-&gt;26d12	4-&gt;26	w_msg_hdr24.26msg_len24+26DTLS1_HM_HEADER_LENGTH:):;2Ìûif22;(2+2$626s2	4-&gt;26
write_hash:)2wC2s<2o2k26mac_size24=2O26EVP_MD_CTX_size26i(2/j2(2$626s2	4-&gt;26
write_hash:):;27Delse2-<2)2%26mac_size24=2	00J:;2’ûif2·;(2Ÿ2'626s2	4-&gt;26enc_write_ctx24
&amp;&amp;24(2i26EVP_CIPHER_mode2Pi(2Ij2B2>626s2	4-&gt;26enc_write_ctx2	4-&gt;2
6cipher:)2	4&amp;26EVP_CIPH_CBC_MODE24):)2≠C2®<2£2û26	blocksize24=2	02J24*2o26EVP_CIPHER_block_size2Pi(2Ij2B2>626s2	4-&gt;26enc_write_ctx2	4-&gt;2
6cipher:):;28Delse2.<2*2&26	blocksize24=2	00J:;2)2%26frag_off24=2	00J:;23õwhile20;(2)2"626s2	4-&gt;26init_num:)2±3<{2˝2¯26curr_mtu24=20626s2	4-&gt;26d12	4-&gt;26mtu24-2U26BIO_wpending2?i(28j212-26SSL_get_wbio2i(2j2	26s:):)24-26DTLS1_RT_HEADER_LENGTH24-26mac_size24-26	blocksize:;2Öûif2A;(2:26curr_mtu2	4&lt;=26DTLS1_HM_HEADER_LENGTH:)2∏C2≥<{2=9/* grr.. we could get an error if MTU picked was wrong */2m2i26ret24=2R26	BIO_flush2?i(28j212-26SSL_get_wbio2i(2j2	26s:):):;2Yûif2+;(2$26ret2	4&lt;=2	00J:)2#C2<2«return226ret:;2¢2ö26curr_mtu24=20626s2	4-&gt;26d12	4-&gt;26mtu24-26DTLS1_RT_HEADER_LENGTH24-26mac_size24-26	blocksize:;:}2œûif2H;(2A2"626s2	4-&gt;26init_num24&gt;26curr_mtu:)2/C2+<2'2#26len24=26curr_mtu:;2KDelse2A<2=2926len24=2"626s2	4-&gt;26init_num:;2C?/* XDTLS: this function is too long.  split out the CCS part */2û	ûif25;(2.26type24==26SSL3_RT_HANDSHAKE:)2›C2ÿ<{2”ûif2C;(2<2"626s2	4-&gt;26init_off24!=2	00J:)2ÑC2ˇ<{2}2y2r26OPENSSL_assert2Zi(2Sj2L2"626s2	4-&gt;26init_off24&gt;26DTLS1_HM_HEADER_LENGTH:):;2Q2M2"626s2	4-&gt;26init_off24-=26DTLS1_HM_HEADER_LENGTH:;2Q2M2"626s2	4-&gt;26init_num24+=26DTLS1_HM_HEADER_LENGTH:;2“ûif2H;(2A2"626s2	4-&gt;26init_num24&gt;26curr_mtu:)2/C2+<2'2#26len24=26curr_mtu:;2KDelse2A<2=2926len24=2"626s2	4-&gt;26init_num:;:}2ñ2ë2â26dtls1_fix_message_header2gi(2j2	26s:,2j226frag_off:,25j2.26len24-26DTLS1_HM_HEADER_LENGTH:):;2˘2Ù2Ï26dtls1_write_message_header2«i(2j2	26s:,2≠j2•24(26unsigned26char24*24)2	4&amp;2i626s2	4-&gt;26init_buf2	4-&gt;26data20>[2)2"626s2	4-&gt;26init_off:]:):;2f2_2X26OPENSSL_assert2@i(29j2226len2	4&gt;=26DTLS1_HM_HEADER_LENGTH:):;:}2˙2ı26ret24=2›26dtls1_write_bytes2¡i(2j2	26s:,2j226type:,2j2x2	4&amp;2i626s2	4-&gt;26init_buf2	4-&gt;26data20>[2)2"626s2	4-&gt;26init_off:]:,2j226len:):;2Ïûif2*;(2#26ret24&lt;2	00J:)2îC2è<{2ÓÈ/* might need to update MTU here, but we don't know$
$                         * which previous packet caused the failure -- so can't$
$                         * really retransmit anything.  continue as if everything$
$                         * is fine and wait for an alert to handle the$
$                         * retransmit $
$                         */2ñûif2Œ;(2∆2©26BIO_ctrl2ñi(28j212-26SSL_get_wbio2i(2j2	26s:):,2*j2#26BIO_CTRL_DGRAM_MTU_EXCEEDED:,2j22	00J:,2j226NULL:)24&gt;2	00J:)2ˆC2Ò<2Ï2Á20626s2	4-&gt;26d12	4-&gt;26mtu24=2¶26BIO_ctrl2ìi(28j212-26SSL_get_wbio2i(2j2	26s:):,2'j2 26BIO_CTRL_DGRAM_QUERY_MTU:,2j22	00J:,2j226NULL:):;2@Delse26<22«return2%24(24-2	01J24):;:}2úDelse2ë<{2äÖ/* bad if this assert fails, only part of the handshake$
$                         * message got sent.  but why would this happen? */2r2n2g26OPENSSL_assert2Oi(2Hj2A26len24==24(26unsigned26int24)26ret:):;2Éûif2ä;(2Ç26type24==26SSL3_RT_HANDSHAKE24
&amp;&amp;24!2;626s2	4-&gt;26d12	4-&gt;26retransmitting:)2ÏC2Á<{2àÉ/* should not be done for 'Hello Request's, but in that case$
$                                 * we'll ignore the result anyway */2‰2ﬂ2!926unsigned26char25*26p2≠=2•24(26unsigned26char24*24)2	4&amp;2i626s2	4-&gt;26init_buf2	4-&gt;26data20>[2)2"626s2	4-&gt;26init_off:]:;2û2ô2792
ÿconst2 62
6struct26hm_header_st25*26msg_hdr2L=2E2	4&amp;26626s2	4-&gt;26d12	4-&gt;26	w_msg_hdr:;2 22926int26xlen:;2√ûif2{;(2t26frag_off24==2	00J24
&amp;&amp;2!626s2	4-&gt;26version24!=26DTLS1_BAD_VER:)2®C2£<{2{w/* reconstruct message header is if it$
$                                         * is being sent in single fragment */2L2H24*26p24++24=2$626msg_hdr2	4-&gt;26type:;2d2`2Y26l2n32Ki(22j2+2'626msg_hdr2	4-&gt;26msg_len:,2j2	26p:):;2_2[2T26s2n2Gi(2.j2'2#626msg_hdr2	4-&gt;26seq:,2j2	26p:):;2F2B2;26l2n32-i(2j22	00J:,2j2	26p:):;2d2`2Y26l2n32Ki(22j2+2'626msg_hdr2	4-&gt;26msg_len:,2j2	26p:):;242026p24-=26DTLS1_HM_HEADER_LENGTH:;2&226xlen24=26ret:;:}2ëDelse2Ü<{242026p24+=26DTLS1_HM_HEADER_LENGTH:;2I2B26xlen24=26ret24-26DTLS1_HM_HEADER_LENGTH:;:}2e2^2W26ssl3_finish_mac2>i(2j2	26s:,2j2	26p:,2j226xlen:):;:}2£ûif2A;(2:26ret24==2"626s2	4-&gt;26init_num:)2÷C2—<{2Úûif24;(2-2&626s2	4-&gt;26msg_callback:)2≤C2≠<2®2£2õ2&626s2	4-&gt;26msg_callback2Ói(2j22	01J:,2,j2%2!626s2	4-&gt;26version:,2j226type:,2Bj2;27626s2	4-&gt;26init_buf2	4-&gt;26data:,2Äj2y2u(26size_t:)2_i(2Xj2Q2"626s2	4-&gt;26init_off24+2"626s2	4-&gt;26init_num:):,2j2	26s:,25j2.2*626s2	4-&gt;26msg_callback_arg:):;2?2;2"626s2	4-&gt;26init_off24=2	00J:;2#/* done writing this message */2?2;2"626s2	4-&gt;26init_num24=2	00J:;2.«return224(2	01J24):;:}2>2:2"626s2	4-&gt;26init_off24+=26ret:;2>2:2"626s2	4-&gt;26init_num24-=26ret:;2]2V26frag_off24+=24(26ret24-=26DTLS1_HM_HEADER_LENGTH24):;:}:}2.«return224(2	00J24):;:}2Œ…/* Obtain handshake message of message type 'mt' (any if mt == -1),$
$ * maximum acceptable body length 'max'.$
$ * Read an entire handshake message.  Handshake messages arrive in$
$ * fragments.$
$ */2Ô#2926long26dtls1_get_message2÷e(2$f22926SSL25*26s:,2f22926int26st1:,2f22926int26stn:,2f22926int26mt:,2 f22926long26max:,2%f22926int25*26ok:)2Ï!<{2g22926int26i:,2H2995This is just a placeholder. Please ignore this child.26al:;2C2?2+92 62
6struct26hm_header_st25*26msg_hdr:;232/2!926unsigned26char25*26p:;222.2926unsigned26long26msg_len:;2àÉ/* s3-&gt;tmp is used to store messages that are unexpected, caused$
$         * by the absence of an optional handshake message */2Äûif2X;(2Q2J626s2	4-&gt;26s32	4-&gt;26tmp24.26reuse_message:)2úC2ó<{2g2c2J626s2	4-&gt;26s32	4-&gt;26tmp24.26reuse_message24=2	00J:;2ëûif2≤;(2™24(26mt2	4&gt;=2	00J24)24
&amp;&amp;24(2I626s2	4-&gt;26s32	4-&gt;26tmp24.26message_type24!=26mt24):)2“C2Õ<{272326al24=26SSL_AD_UNEXPECTED_MESSAGE:;2q2m2f2
6SSLerr2Vi(2&j226SSL_F_DTLS1_GET_MESSAGE:,2'j2 26SSL_R_UNEXPECTED_MESSAGE:):;2•goto26f_err:;:}2*2&24*26ok24=2	01J:;2ë2å2"626s2	4-&gt;26init_msg24=27626s2	4-&gt;26init_buf2	4-&gt;26data24+26DTLS1_HM_HEADER_LENGTH:;2ó2í2"626s2	4-&gt;26init_num24=24(26int24)2I626s2	4-&gt;26s32	4-&gt;26tmp24.26message_size:;29«return2)2"626s2	4-&gt;26init_num:;:}2`2\26msg_hdr24=2	4&amp;26626s2	4-&gt;26d12	4-&gt;26	r_msg_hdr:;2ó2í2ä2
6memset2zi(2j226msg_hdr:,2j2200x00J:,2Bj2;27®sizeof2*i(2#j2struct26hm_header_st:):):;2[26again::2•2†26i24=2ä26dtls1_get_message_fragment2fi(2j2	26s:,2j226st1:,2j226stn:,2j226max:,2j2
26ok:):;2Ωûif2j;(2c26i24==26DTLS1_HM_BAD_FRAGMENT24||26i24==26DTLS1_HM_FRAGMENT_RETRY:)2@C2/* bad fragment received */2<2•goto26again:;2ÖEelse2{ûif2O;(2H26i2	4&lt;=2	00J24
&amp;&amp;24!24*26ok:)2!C2<2«return226i:;2}2y26p24=24(26unsigned26char24*24)27626s2	4-&gt;26init_buf2	4-&gt;26data:;2F2B26msg_len24=2'626msg_hdr2	4-&gt;26msg_len:;2$ /* reconstruct message header */2Z2V24*24(26p24++24)24=2$626msg_hdr2	4-&gt;26type:;2H2D2=26l2n32/i(2j226msg_len:,2j2	26p:):;2_2[2T26s2n2Gi(2.j2'2#626msg_hdr2	4-&gt;26seq:,2j2	26p:):;2F2B2;26l2n32-i(2j22	00J:,2j2	26p:):;2H2D2=26l2n32/i(2j226msg_len:,2j2	26p:):;2”ûif2J;(2C2!626s2	4-&gt;26version24!=26DTLS1_BAD_VER:)2~C2z<{242026p24-=26DTLS1_HM_HEADER_LENGTH:;2=2626msg_len24+=26DTLS1_HM_HEADER_LENGTH:;:}2e2a2Z26ssl3_finish_mac2Ai(2j2	26s:,2j2	26p:,2j226msg_len:):;2‚ûif24;(2-2&626s2	4-&gt;26msg_callback:)2¢C2ù<2ò2ì2ã2&626s2	4-&gt;26msg_callback2ﬁi(2j22	00J:,2,j2%2!626s2	4-&gt;26version:,2 j226SSL3_RT_HANDSHAKE:,2j2	26p:,2j226msg_len:,2j2	26s:,25j2.2*626s2	4-&gt;26msg_callback_arg:):;2ó2í2ä2
6memset2zi(2j226msg_hdr:,2j2200x00J:,2Bj2;27®sizeof2*i(2#j2struct26hm_header_st:):):;273/* Don't change sequence numbers while listening */2≠ûif2H;(2A24!23626s2	4-&gt;26d12	4-&gt;2
6listen:)2ZC2V<2R2N2?626s2	4-&gt;26d12	4-&gt;26handshake_read_seq24++:;2ë2å2"626s2	4-&gt;26init_msg24=27626s2	4-&gt;26init_buf2	4-&gt;26data24+26DTLS1_HM_HEADER_LENGTH:;26«return2)2"626s2	4-&gt;26init_num:;2[26f_err::2l2h2a26ssl3_send_alert2Hi(2j2	26s:,2j226SSL3_AL_FATAL:,2j2
26al:):;2*2&24*26ok24=2	00J:;2'«return224-2	01J:;:}2»2ÿstatic2926int26dtls1_preprocess_fragment2ëe(2$f22926SSL25*26s:,2Cf2<2+92 62
6struct26hm_header_st25*26msg_hdr:,2f22926int26max:)2ˆ<{2∆2#292
6size_t26frag_off:,2N2995This is just a placeholder. Please ignore this child.26frag_len:,2M2995This is just a placeholder. Please ignore this child.26msg_len:;2F2B26msg_len24=2'626msg_hdr2	4-&gt;26msg_len:;2H2D26frag_off24=2(626msg_hdr2	4-&gt;26frag_off:;2H2D26frag_len24=2(626msg_hdr2	4-&gt;26frag_len:;2/* sanity checking */2ûûif2T;(2M24(26frag_off24+26frag_len24)24&gt;26msg_len:)2æC2π<{2}2y2r2
6SSLerr2bi(2.j2'2#6SSL_F_DTLS1_PREPROCESS_FRAGMENT:,2+j2$2 6SSL_R_EXCESSIVE_MESSAGE_SIZE:):;23«return2#26SSL_AD_ILLEGAL_PARAMETER:;:}2¿ûif2v;(2o24(26frag_off24+26frag_len24)24&gt;24(26unsigned26long24)26max:)2æC2π<{2}2y2r2
6SSLerr2bi(2.j2'2#6SSL_F_DTLS1_PREPROCESS_FRAGMENT:,2+j2$2 6SSL_R_EXCESSIVE_MESSAGE_SIZE:):;23«return2#26SSL_AD_ILLEGAL_PARAMETER:;:}2îûif2l;(2e2K626s2	4-&gt;26d12	4-&gt;26	r_msg_hdr24.26frag_off24==2	00J:)2»C2/* first fragment */2©<{2gc/* msg_len is limited to 2^24, but is effectively checked$
$                 * against max above */2€ûif2¢;(2ö24!2ã26BUF_MEM_grow_clean2oi(2-j2&2"626s2	4-&gt;26init_buf:,29j2226msg_len24+26DTLS1_HM_HEADER_LENGTH:):)2¨C2ß<{2n2j2c2
6SSLerr2Si(2.j2'2#6SSL_F_DTLS1_PREPROCESS_FRAGMENT:,2j226ERR_R_BUF_LIB:):;20«return2 26SSL_AD_INTERNAL_ERROR:;:}2h2d2I626s2	4-&gt;26s32	4-&gt;26tmp24.26message_size24=26msg_len:;2i2e2J626s2	4-&gt;26d12	4-&gt;26	r_msg_hdr24.26msg_len24=26msg_len:;2Å2}2I626s2	4-&gt;26s32	4-&gt;26tmp24.26message_type24=2$626msg_hdr2	4-&gt;26type:;22{2G626s2	4-&gt;26d12	4-&gt;26	r_msg_hdr24.26type24=2$626msg_hdr2	4-&gt;26type:;2Ä2y2F626s2	4-&gt;26d12	4-&gt;26	r_msg_hdr24.26seq24=2#626msg_hdr2	4-&gt;26seq:;:}2—Eelse2∆ûif2m;(2f26msg_len24!=2J626s2	4-&gt;26d12	4-&gt;26	r_msg_hdr24.26msg_len:)2ÕC2»<{2åá/* They must be playing with us! BTW, failure to enforce$
$                 * upper limit would open possibility for buffer overrun. */2}2y2r2
6SSLerr2bi(2.j2'2#6SSL_F_DTLS1_PREPROCESS_FRAGMENT:,2+j2$2 6SSL_R_EXCESSIVE_MESSAGE_SIZE:):;23«return2#26SSL_AD_ILLEGAL_PARAMETER:;:}2«return22	00J:;2/* no error */:}2„2ÿstatic2926int2$6 dtls1_retrieve_buffered_fragment2te(2$f22926SSL25*26s:,2 f22926long26max:,2%f22926int25*26ok:)2®<{2…ƒ/* (0) check whether the desired fragment is available$
$         * if so:$
$         * (1) copy over the fragment to s-&gt;init_buf-&gt;data[]$
$         * (2) update s-&gt;init_num$
$         */2)2%292	6pitem25*26item:;2/2+2926hm_fragment25*26frag:;222926int26al:;2*2&24*26ok24=2	00J:;2Å2}26item24=2e26pqueue_peek2Pi(2Ij2B2>626s2	4-&gt;26d12	4-&gt;26buffered_messages:):;2Xûif2(;(2!26item24==26NULL:)2%C2!<2«return22	00J:;2c2_26frag24=24(26hm_fragment24*24)2!626item2	4-&gt;26data:;262/* Don't return if reassembly still in progress */2wûif2G;(2@2'626frag2	4-&gt;26
reassembly24!=26NULL:)2%C2!<2«return22	00J:;2∏ûif2è;(2á2?626s2	4-&gt;26d12	4-&gt;26handshake_read_seq24==27626frag2	4-&gt;26
msg_header24.26seq:)2ÏC2Á<{2|2x2926unsigned26long26frag_len2G=2@2<626frag2	4-&gt;26
msg_header24.26frag_len:;2o2k2d26
pqueue_pop2Pi(2Ij2B2>626s2	4-&gt;26d12	4-&gt;26buffered_messages:):;2©2§26al24=2ç26dtls1_preprocess_fragment2ji(2j2	26s:,2=j262	4&amp;2'626frag2	4-&gt;26
msg_header:,2j226max:):;2Øûif2';(2 26al24==2	00J:)2¸C2/* no alert */2„<{2 2≈2!926unsigned26char25*26p2ì=2ã24(26unsigned26char24*24)27626s2	4-&gt;26init_buf2	4-&gt;26data24+26DTLS1_HM_HEADER_LENGTH:;2é2Ü2˛2
6memcpy2Ìi(2kj2d2	4&amp;2U626p2J>[2C2<626frag2	4-&gt;26
msg_header24.26frag_off:]:,20j2)2%626frag2	4-&gt;26fragment:,2Gj2@2<626frag2	4-&gt;26
msg_header24.26frag_len:):;:}2E2A2:26dtls1_hm_fragment_free2i(2j226frag:):;29252.26
pitem_free2i(2j226item:):;2åûif2';(2 26al24==2	00J:)2ZC2V<{2*2&24*26ok24=2	01J:;2#«return226frag_len:;:}2l2h2a26ssl3_send_alert2Hi(2j2	26s:,2j226SSL3_AL_FATAL:,2j2
26al:):;2?2;2"626s2	4-&gt;26init_num24=2	00J:;2*2&24*26ok24=2	00J:;2'«return224-2	01J:;:}2+Delse2!<2«return22	00J:;:}2˛22ÿstatic2926int26dtls1_reassemble_fragment2óe(2$f22926SSL25*26s:,2Cf2<2+92 62
6struct26hm_header_st25*26msg_hdr:,2%f22926int25*26ok:)2¶1<{2D2@2926hm_fragment25*26frag2=226NULL:;2>2:292	6pitem25*26item2=226NULL:;2ç262926int26i2=224-2	01J:,2Q2995This is just a placeholder. Please ignore this child.26is_complete:;2O2K2926unsigned26char2(626seq64be2>[22	08J:]:;2∑2d2926unsigned26long26frag_len23=2,2(626msg_hdr2	4-&gt;26frag_len:,2M2995This is just a placeholder. Please ignore this child.26max_len:;2∂ûif2ç;(2Ö24(2(626msg_hdr2	4-&gt;26frag_off24+26frag_len24)24&gt;2'626msg_hdr2	4-&gt;26msg_len:)2C2<2•goto2
6err:;2êã/* Determine maximum allowed message size. Depends on (user set)$
$         * maximum certificate length, but 16k is minimum.$
$         */2–ûif2Ñ;(2}26DTLS1_HM_HEADER_LENGTH24+2 6SSL3_RT_MAX_ENCRYPTED_LENGTH24&lt;2'626s2	4-&gt;26max_cert_list:)2NC2J<2F2B26max_len24=2'626s2	4-&gt;26max_cert_list:;2pDelse2f<2b2^26max_len24=26DTLS1_HM_HEADER_LENGTH24+2 6SSL3_RT_MAX_ENCRYPTED_LENGTH:;2òûif2p;(2i24(2(626msg_hdr2	4-&gt;26frag_off24+26frag_len24)24&gt;26max_len:)2C2<2•goto2
6err:;2#/* Try to find item in queue */2Ü2Å2z2
6memset2ji(2j226seq64be:,2j22	00J:,25j2.2*®sizeof2i(2j226seq64be:):):;2≠2®2(626seq64be2>[22	06J:]24=2p(26unsigned26char:)2Ni(2Gj2@2#626msg_hdr2	4-&gt;26seq24&gt;&gt;2	08J:):;2Ü2Å2(626seq64be2>[22	07J:]24=24(26unsigned26char24)2#626msg_hdr2	4-&gt;26seq:;2ö2ï26item24=2}26pqueue_find2hi(2Ij2B2>626s2	4-&gt;26d12	4-&gt;26buffered_messages:,2j226seq64be:):;2«ûif2(;(2!26item24==26NULL:)2†C2õ<{2ã2Ü26frag24=2n26dtls1_hm_fragment_new2Oi(22j2+2'626msg_hdr2	4-&gt;26msg_len:,2j22	01J:):;2Pûif2(;(2!26frag24==26NULL:)2C2<2•goto2
6err:;2∆2¡2π2
6memcpy2®i(2Kj2D2	4&amp;24(2'626frag2	4-&gt;26
msg_header24):,2j226msg_hdr:,2<j2521®sizeof2$i(2j224*26msg_hdr:):):;2å2á2<626frag2	4-&gt;26
msg_header24.26frag_len24=2;626frag2	4-&gt;26
msg_header24.26msg_len:;2\2U2<626frag2	4-&gt;26
msg_header24.26frag_off24=2	00J:;:}2qDelse2g<2c2_26frag24=24(26hm_fragment24*24)2!626item2	4-&gt;26data:;2rn/* If message is already reassembled, this must be a$
$         * retransmit and can be dropped.$
$         */2åûif2G;(2@2'626frag2	4-&gt;26
reassembly24==26NULL:)2πC2¥<{2Q2M2926unsigned26char2*626devnull2>[220256J:]:;2•õwhile2;(226frag_len:)2¸<{2ˆ2Ò26i24=2€2?626s2	4-&gt;2
6method2	4-&gt;26ssl_read_bytes2ïi(2j2	26s:,2 j226SSL3_RT_HANDSHAKE:,2j226devnull:,2´j2£2ûB2M;2I26frag_len24&gt;2*®sizeof2i(2j226devnull:):?22C2.2*®sizeof2i(2j226devnull:)2D:226frag_len:,2j22	00J:):;2Qûif2);(2"26i2	4&lt;=2	00J:)2C2<2•goto2
6err:;2)2"26frag_len24-=26i:;:}22«return2"26DTLS1_HM_FRAGMENT_RETRY:;:}2EA/* read the body of the fragment (header has already been read */2¨2ß26i24=2ë2?626s2	4-&gt;2
6method2	4-&gt;26ssl_read_bytes2Ài(2j2	26s:,2 j226SSL3_RT_HANDSHAKE:,2aj2Z2%626frag2	4-&gt;26fragment24+2(626msg_hdr2	4-&gt;26frag_off:,2j226frag_len:,2j22	00J:):;2úûif2t;(2m26i2	4&lt;=2	00J24||24(26unsigned26long24)26i24!=26frag_len:)2C2<2•goto2
6err:;2°2ú2î26RSMBLY_BITMASK_MARK2ˆi(22j2+2'626frag2	4-&gt;26
reassembly:,2Kj2D24(26long24)2(626msg_hdr2	4-&gt;26frag_off:,2nj2g2c(26long:)2Oi(2Hj2A2(626msg_hdr2	4-&gt;26frag_off24+26frag_len:):):;2”2Œ2∆26RSMBLY_BITMASK_IS_COMPLETE2°i(22j2+2'626frag2	4-&gt;26
reassembly:,2Jj2C24(26long24)2'626msg_hdr2	4-&gt;26msg_len:,2j226is_complete:):;2◊ûif2;(226is_complete:)2ÆC2©<{2Z2V2O26OPENSSL_free29i(22j2+2'626frag2	4-&gt;26
reassembly:):;2F2?2'626frag2	4-&gt;26
reassembly24=26NULL:;:}2Éûif2(;(2!26item24==26NULL:)2œC2 <{2Ü2Å2z2
6memset2ji(2j226seq64be:,2j22	00J:,25j2.2*®sizeof2i(2j226seq64be:):):;2≠2®2(626seq64be2>[22	06J:]24=2p(26unsigned26char:)2Ni(2Gj2@2#626msg_hdr2	4-&gt;26seq24&gt;&gt;2	08J:):;2î2è2(626seq64be2>[22	07J:]24=2W(26unsigned26char:)25i(2.j2'2#626msg_hdr2	4-&gt;26seq:):;2a2]26item24=2E26	pitem_new22i(2j226seq64be:,2j226frag:):;2Åûif2(;(2!26item24==26NULL:)2NC2J<{2•goto2
6err:;2,2%26i24=24-2	01J:;:}2ã2É2|26pqueue_insert2ei(2Ij2B2>626s2	4-&gt;26d12	4-&gt;26buffered_messages:,2j226item:):;:}2/«return2"26DTLS1_HM_FRAGMENT_RETRY:;2[2
6err::2Äûif2(;(2!26frag24!=26NULL:)2MC2I<2E2A2:26dtls1_hm_fragment_free2i(2j226frag:):;2vûif2(;(2!26item24!=26NULL:)2CC2?<2;272026OPENSSL_free2i(2j226item:):;2*2&24*26ok24=2	00J:;2«return226i:;:}2”+2ÿstatic2926int2$6 dtls1_process_out_of_seq_message2óe(2$f22926SSL25*26s:,2Cf2<2+92 62
6struct26hm_header_st25*26msg_hdr:,2%f22926int25*26ok:)2Ù)<{2:262926int26i2=224-2	01J:;2D2@2926hm_fragment25*26frag2=226NULL:;2>2:292	6pitem25*26item2=226NULL:;2O2K2926unsigned26char2(626seq64be2>[22	08J:]:;2h2d2926unsigned26long26frag_len23=2,2(626msg_hdr2	4-&gt;26frag_len:;2∂ûif2ç;(2Ö24(2(626msg_hdr2	4-&gt;26frag_off24+26frag_len24)24&gt;2'626msg_hdr2	4-&gt;26msg_len:)2C2<2•goto2
6err:;2A=/* Try to find item in queue, to prevent duplicate entries */2Ü2Å2z2
6memset2ji(2j226seq64be:,2j22	00J:,25j2.2*®sizeof2i(2j226seq64be:):):;2≠2®2(626seq64be2>[22	06J:]24=2p(26unsigned26char:)2Ni(2Gj2@2#626msg_hdr2	4-&gt;26seq24&gt;&gt;2	08J:):;2Ü2Å2(626seq64be2>[22	07J:]24=24(26unsigned26char24)2#626msg_hdr2	4-&gt;26seq:;2ö2ï26item24=2}26pqueue_find2hi(2Ij2B2>626s2	4-&gt;26d12	4-&gt;26buffered_messages:,2j226seq64be:):;2åá/* If we already have an entry and this one is a fragment,$
$         * don't discard it and rather try to reassemble it.$
$         */2∞ûif2y;(2r26item24!=26NULL24
&amp;&amp;26frag_len24&lt;2'626msg_hdr2	4-&gt;26msg_len:)2,C2(<2$2 26item24=26NULL:;2Ç˝/* Discard the message if sequence number was already there, is$
$         * too far in the future, already in the queue or if we received$
$         * a FINISHED before the SERVER_HELLO, which then must be a stale$
$         * retransmit.$
$         */2«ûif2Î;(2„2#626msg_hdr2	4-&gt;26seq2	4&lt;=2?626s2	4-&gt;26d12	4-&gt;26handshake_read_seq24||2#626msg_hdr2	4-&gt;26seq24&gt;2?626s2	4-&gt;26d12	4-&gt;26handshake_read_seq24+2
010J24||26item24!=26NULL24||24(2?626s2	4-&gt;26d12	4-&gt;26handshake_read_seq24==2	00J24
&amp;&amp;2$626msg_hdr2	4-&gt;26type24==26SSL3_MT_FINISHED24):)2àC2É<{2Q2M2926unsigned26char2*626devnull2>[220256J:]:;2®õwhile2;(226frag_len:)2¸<{2ˆ2Ò26i24=2€2?626s2	4-&gt;2
6method2	4-&gt;26ssl_read_bytes2ïi(2j2	26s:,2 j226SSL3_RT_HANDSHAKE:,2j226devnull:,2´j2£2ûB2M;2I26frag_len24&gt;2*®sizeof2i(2j226devnull:):?22C2.2*®sizeof2i(2j226devnull:)2D:226frag_len:,2j22	00J:):;2Qûif2);(2"26i2	4&lt;=2	00J:)2C2<2•goto2
6err:;2)2"26frag_len24-=26i:;:}:}2ƒDelse2π<{2¯ûif2k;(2d26frag_len24
&amp;&amp;26frag_len24&lt;2'626msg_hdr2	4-&gt;26msg_len:)2ÅC2}<2y«return2l2e26dtls1_reassemble_fragment2Bi(2j2	26s:,2j226msg_hdr:,2j2
26ok:):;2o2k26frag24=2S26dtls1_hm_fragment_new24i(2j226frag_len:,2j22	00J:):;2Pûif2(;(2!26frag24==26NULL:)2C2<2•goto2
6err:;2∆2¡2π2
6memcpy2®i(2Kj2D2	4&amp;24(2'626frag2	4-&gt;26
msg_header24):,2j226msg_hdr:,2<j2521®sizeof2$i(2j224*26msg_hdr:):):;2óûif2;(226frag_len:)2ÒC2Ï<{2EA/* read the body of the fragment (header has already been read */2˚2ˆ26i24=2‡2?626s2	4-&gt;2
6method2	4-&gt;26ssl_read_bytes2öi(2j2	26s:,2 j226SSL3_RT_HANDSHAKE:,20j2)2%626frag2	4-&gt;26fragment:,2j226frag_len:,2j22	00J:):;2üûif2t;(2m26i2	4&lt;=2	00J24||24(26unsigned26long24)26i24!=26frag_len:)2C2<2•goto2
6err:;:}2Ü2Å2z2
6memset2ji(2j226seq64be:,2j22	00J:,25j2.2*®sizeof2i(2j226seq64be:):):;2≠2®2(626seq64be2>[22	06J:]24=2p(26unsigned26char:)2Ni(2Gj2@2#626msg_hdr2	4-&gt;26seq24&gt;&gt;2	08J:):;2î2è2(626seq64be2>[22	07J:]24=2W(26unsigned26char:)25i(2.j2'2#626msg_hdr2	4-&gt;26seq:):;2a2]26item24=2E26	pitem_new22i(2j226seq64be:,2j226frag:):;2Pûif2(;(2!26item24==26NULL:)2C2<2•goto2
6err:;2ã2É2|26pqueue_insert2ei(2Ij2B2>626s2	4-&gt;26d12	4-&gt;26buffered_messages:,2j226item:):;:}2/«return2"26DTLS1_HM_FRAGMENT_RETRY:;2[2
6err::2Äûif2(;(2!26frag24!=26NULL:)2MC2I<2E2A2:26dtls1_hm_fragment_free2i(2j226frag:):;2vûif2(;(2!26item24!=26NULL:)2CC2?<2;272026OPENSSL_free2i(2j226item:):;2*2&24*26ok24=2	00J:;2«return226i:;:}2Ñ92ÿstatic2926long26dtls1_get_message_fragment2∂e(2$f22926SSL25*26s:,2f22926int26st1:,2f22926int26stn:,2 f22926long26max:,2%f22926int25*26ok:)2ã7<{2]2Y2926unsigned26char26626wire2(>[2!26DTLS1_HM_HEADER_LENGTH:]:;2Œ2*2926unsigned26long26len:,2N2995This is just a placeholder. Please ignore this child.26frag_off:,2N2995This is just a placeholder. Please ignore this child.26frag_len:;2g22926int26i:,2H2995This is just a placeholder. Please ignore this child.26al:;2<282$92 62
6struct26hm_header_st26msg_hdr:;262/* see if we have the required fragment already */2ﬂûif2±;(2©24(26frag_len24=2h2$6 dtls1_retrieve_buffered_fragment2>i(2j2	26s:,2j226max:,2j2
26ok:)24)24||24*26ok:)2°C2ú<{2pûif2;(224*26ok:)2JC2F<2B2>2"626s2	4-&gt;26init_num24=26frag_len:;2#«return226frag_len:;:}2'#/* read handshake message header */2Ï2Á26i24=2—2?626s2	4-&gt;2
6method2	4-&gt;26ssl_read_bytes2ãi(2j2	26s:,2 j226SSL3_RT_HANDSHAKE:,2j226wire:,2%j226DTLS1_HM_HEADER_LENGTH:,2j22	00J:):;2Ïûif2);(2"26i2	4&lt;=2	00J:)2∑C2/* nbio, or an error */2ï<{2D2@2!626s2	4-&gt;26rwstate24=26SSL_READING:;2*2&24*26ok24=2	00J:;2«return226i:;:}295/* Handshake fails if message header is incomplete */2ûûif27;(2026i24!=26DTLS1_HM_HEADER_LENGTH:)2€C2÷<{272326al24=26SSL_AD_UNEXPECTED_MESSAGE:;2z2v2o2
6SSLerr2_i(2/j2(2$6 SSL_F_DTLS1_GET_MESSAGE_FRAGMENT:,2'j2 26SSL_R_UNEXPECTED_MESSAGE:):;2•goto26f_err:;:}2+'/* parse the message fragment header */2j2f2_26dtls1_get_message_header2=i(2j226wire:,2!j22	4&amp;26msg_hdr:):;2°ú/* $
$         * if this is a future (or stale) message it gets buffered$
$         * (or dropped)--no further processing at this time$
$         * While listening, we accept seq 1 (ClientHello with cookie)$
$         * although we're still expecting seq 0 (ClientHello)$
$         */2∑ûif2ï;(2ç2626msg_hdr24.26seq24!=2?626s2	4-&gt;26d12	4-&gt;26handshake_read_seq24
&amp;&amp;24!24(23626s2	4-&gt;26d12	4-&gt;2
6listen24
&amp;&amp;2626msg_hdr24.26seq24==2	01J24):)2ïC2ê<2ã«return2~2w2$6 dtls1_process_out_of_seq_message2Mi(2j2	26s:,2!j22	4&amp;26msg_hdr:,2j2
26ok:):;2>2:26len24=2#626msg_hdr24.26msg_len:;2D2@26frag_off24=2$626msg_hdr24.26frag_off:;2D2@26frag_len24=2$626msg_hdr24.26frag_len:;2Âûif2K;(2D26frag_len24
&amp;&amp;26frag_len24&lt;26len:)2éC2â<2Ñ«return2w2p26dtls1_reassemble_fragment2Mi(2j2	26s:,2!j22	4&amp;26msg_hdr:,2j2
26ok:):;2ıûif2Ä;(2¯24!2 626s2	4-&gt;2
6server24
&amp;&amp;2K626s2	4-&gt;26d12	4-&gt;26	r_msg_hdr24.26frag_off24==2	00J24
&amp;&amp;2%626wire2>[22	00J:]24==26SSL3_MT_HELLO_REQUEST:)2Ë
C2„
<{2ÛÓ/* The server may always send 'Hello Request' messages --$
$                 * we are doing a handshake anyway now, so ignore them$
$                 * if their format is correct. Does not count for$
$                 * 'Finished' MAC. */2Âûif2€;(2”2%626wire2>[22	01J:]24==2	00J24
&amp;&amp;2%626wire2>[22	02J:]24==2	00J24
&amp;&amp;2%626wire2>[22	03J:]24==2	00J:)2ËC2„<{2Ùûif24;(2-2&626s2	4-&gt;26msg_callback:)2¥C2Ø<2™2•2ù2&626s2	4-&gt;26msg_callback2i(2j22	00J:,2,j2%2!626s2	4-&gt;26version:,2 j226SSL3_RT_HANDSHAKE:,2j226wire:,2%j226DTLS1_HM_HEADER_LENGTH:,2j2	26s:,25j2.2*626s2	4-&gt;26msg_callback_arg:):;2?2;2"626s2	4-&gt;26init_num24=2	00J:;2£«return2í2ä26dtls1_get_message_fragment2fi(2j2	26s:,2j226st1:,2j226stn:,2j226max:,2j2
26ok:):;:}2èDelse2,(/* Incorrectly formated Hello request */2÷<{272326al24=26SSL_AD_UNEXPECTED_MESSAGE:;2z2v2o2
6SSLerr2_i(2/j2(2$6 SSL_F_DTLS1_GET_MESSAGE_FRAGMENT:,2'j2 26SSL_R_UNEXPECTED_MESSAGE:):;2•goto26f_err:;:}:}2»ûif2ù;(2ï24(26al24=2q26dtls1_preprocess_fragment2Ni(2j2	26s:,2!j22	4&amp;26msg_hdr:,2j226max:)24):)2C2<2•goto26f_err:;295/* XDTLS:  ressurect this when restart is in place */2:262626s2	4-&gt;2	6state24=26stn:;2Óûif2/;(2(26frag_len24&gt;2	00J:)2ÅC2¸<{2 2≈2!926unsigned26char25*26p2ì=2ã24(26unsigned26char24*24)27626s2	4-&gt;26init_buf2	4-&gt;26data24+26DTLS1_HM_HEADER_LENGTH:;2Ü2Å26i24=2Î2?626s2	4-&gt;2
6method2	4-&gt;26ssl_read_bytes2•i(2j2	26s:,2 j226SSL3_RT_HANDSHAKE:,2;j242	4&amp;2%626p2>[226frag_off:]:,2j226frag_len:,2j22	00J:):;2JF/* XDTLS:  fix this--message fragments cannot span multiple packets */2“ûif2);(2"26i2	4&lt;=2	00J:)2öC2ï<{2D2@2!626s2	4-&gt;26rwstate24=26SSL_READING:;2*2&24*26ok24=2	00J:;2«return226i:;:}:}20Delse2&<2"226i24=2	00J:;2d`/* XDTLS:  an incorrectly formatted fragment should cause the $
$         * handshake to fail */2®ûif2@;(2926i24!=24(26int24)26frag_len:)2‹C2◊<{272326al24=26SSL3_AD_ILLEGAL_PARAMETER:;2{2w2p2
6SSLerr2`i(2/j2(2$6 SSL_F_DTLS1_GET_MESSAGE_FRAGMENT:,2(j2!26SSL3_AD_ILLEGAL_PARAMETER:):;2•goto26f_err:;:}2*2&24*26ok24=2	01J:;2íç/* Note that s-&gt;init_num is *not* used as current offset in$
$         * s-&gt;init_buf-&gt;data, but as a counter summing up fragments'$
$         * lengths: as soon as they sum up to handshake packet$
$         * length, we assume we have got all the fragments. */2B2>2"626s2	4-&gt;26init_num24=26frag_len:;2 «return226frag_len:;2[26f_err::2l2h2a26ssl3_send_alert2Hi(2j2	26s:,2j226SSL3_AL_FATAL:,2j2
26al:):;2?2;2"626s2	4-&gt;26init_num24=2	00J:;2*2&24*26ok24=2	00J:;25«return2%24(24-2	01J24):;:}2¥2926int26dtls1_send_finished2√e(2$f22926SSL25*26s:,2f22926int26a:,2f22926int26b:,26f2/292
ÿconst26char25*2
6sender:,2 f22926int26slen:)2√<{2É2/2!926unsigned26char25*26p:,25*2G2995This is just a placeholder. Please ignore this child.26d:;222926int26i:;2,2(2926unsigned26long26l:;2…ûif2<;(252626s2	4-&gt;2	6state24==26a:)2ÅC2¸<{2}2y26d24=24(26unsigned26char24*24)27626s2	4-&gt;26init_buf2	4-&gt;26data:;2e2a26p24=2	4&amp;24(23626d2(>[2!26DTLS1_HM_HEADER_LENGTH:]24):;2í2ç26i24=2˜2Z626s2	4-&gt;2
6method2	4-&gt;26ssl3_enc2	4-&gt;26final_finish_mac2ñi(2j2	26s:,2j22
6sender:,2j226slen:,2Qj2J2F626s2	4-&gt;26s32	4-&gt;26tmp24.26	finish_md:):;2c2_2J626s2	4-&gt;26s32	4-&gt;26tmp24.26finish_md_len24=26i:;2ô2î2å2
6memcpy2|i(2j2	26p:,2Qj2J2F626s2	4-&gt;26s32	4-&gt;26tmp24.26	finish_md:,2j2	26i:):;2226p24+=26i:;2226l24=26i:;2]Y/* Copy the finished so we can use it for$
$         * renegotiation checks$
$         */2±ûif2H;(2A2626s2	4-&gt;26type24==26SSL_ST_CONNECT:)2™C2•<{2Z2V2O26OPENSSL_assert27i(20j2)26i2	4&lt;=26EVP_MAX_MD_SIZE:):;2⁄2’2Õ2
6memcpy2ºi(2Pj2I2E626s2	4-&gt;26s32	4-&gt;26previous_client_finished:,2Qj2J2F626s2	4-&gt;26s32	4-&gt;26tmp24.26	finish_md:,2j2	26i:):;2e2^2I626s2	4-&gt;26s32	4-&gt;2 6previous_client_finished_len24=26i:;:}2∞Delse2•<{2Z2V2O26OPENSSL_assert27i(20j2)26i2	4&lt;=26EVP_MAX_MD_SIZE:):;2⁄2’2Õ2
6memcpy2ºi(2Pj2I2E626s2	4-&gt;26s32	4-&gt;26previous_server_finished:,2Qj2J2F626s2	4-&gt;26s32	4-&gt;26tmp24.26	finish_md:,2j2	26i:):;2e2^2I626s2	4-&gt;26s32	4-&gt;2 6previous_server_finished_len24=26i:;:}2)Œ#2
óifdef26OPENSSL_SYS_WIN162uq/* MSVC 1.5 does not clear the top bytes of the word unless$
$                 * I do this.$
$                 */2,2(26l2
4&amp;=200xffffJ:;2À#2
óendif2¬2Ω26d24=2ß26dtls1_set_message_header2Ñi(2j2	26s:,2j2	26d:,2j226SSL3_MT_FINISHED:,2j2	26l:,2j22	00J:,2j2	26l:):;2u2q2"626s2	4-&gt;26init_num24=24(26int24)26l24+26DTLS1_HM_HEADER_LENGTH:;2?2;2"626s2	4-&gt;26init_off24=2	00J:;2/+/* buffer the message to handle re-xmits */2V2R2K26dtls1_buffer_message2-i(2j2	26s:,2j22	00J:):;2;242626s2	4-&gt;2	6state24=26b:;:}2%!/* SSL3_ST_SEND_xxxxxx_HELLO_B */2v«return2f24(2Q26dtls1_do_write29i(2j2	26s:,2 j226SSL3_RT_HANDSHAKE:)24):;:}2ı/* for these 2 messages, we need to$
$ * ssl-&gt;enc_read_ctx                    re-init$
$ * ssl-&gt;s3-&gt;read_sequence               zero$
$ * ssl-&gt;s3-&gt;read_mac_secret             re-init$
$ * ssl-&gt;session-&gt;read_sym_enc           assign$
$ * ssl-&gt;session-&gt;read_compression       assign$
$ * ssl-&gt;session-&gt;read_hash              assign$
$ */2˜2926int2!6dtls1_send_change_cipher_spec2ie(2$f22926SSL25*26s:,2f22926int26a:,2f22926int26b:)2◊<{232/2!926unsigned26char25*26p:;2˙
ûif2<;(252626s2	4-&gt;2	6state24==26a:)2≤
C2≠
<{2}2y26p24=24(26unsigned26char24*24)27626s2	4-&gt;26init_buf2	4-&gt;26data:;272324*26p24++24=26SSL3_MT_CCS:;2ö2ï2@626s2	4-&gt;26d12	4-&gt;26handshake_write_seq24=2E626s2	4-&gt;26d12	4-&gt;26next_handshake_write_seq:;2Q2M2"626s2	4-&gt;26init_num24=26DTLS1_CCS_HEADER_LENGTH:;2˝ûif2J;(2C2!626s2	4-&gt;26version24==26DTLS1_BAD_VER:)2ßC2¢<{2X2T2E626s2	4-&gt;26d12	4-&gt;26next_handshake_write_seq24++:;2|2x2q26s2n2di(2Kj2D2@626s2	4-&gt;26d12	4-&gt;26handshake_write_seq:,2j2	26p:):;2C2<2"626s2	4-&gt;26init_num24+=2	02J:;:}2?2;2"626s2	4-&gt;26init_off24=2	00J:;2ˆ2Ò2È2 6dtls1_set_message_header_int2¬i(2j2	26s:,2j226SSL3_MT_CCS:,2j22	00J:,2Kj2D2@626s2	4-&gt;26d12	4-&gt;26handshake_write_seq:,2j22	00J:,2j22	00J:):;2/+/* buffer the message to handle re-xmits */2V2R2K26dtls1_buffer_message2-i(2j2	26s:,2j22	01J:):;2;242626s2	4-&gt;2	6state24=26b:;:}2/* SSL3_ST_CW_CHANGE_B */2«return2o24(2Z26dtls1_do_write2Bi(2j2	26s:,2)j2"26SSL3_RT_CHANGE_CIPHER_SPEC:)24):;:}2Ô2ÿstatic2926int26dtls1_add_cert_to_buf2çe(2*f2#2926BUF_MEM25*26buf:,23f2,2!926unsigned26long25*26l:,2%f22926X50925*26x:)2•<{222926int26n:;232/2!926unsigned26char25*26p:;2W2S26n24=2>26i2d_X5092,i(2j2	26x:,2j226NULL:):;2ﬁûif2π;(2±24!2¢26BUF_MEM_grow_clean2Öi(2j226buf:,2jj2c2_(2
6int:)2Li(2Ej2>26n24+24(24*26l24)24+2	03J:):):)2òC2ì<{2j2f2_2
6SSLerr2Oi(2*j2#26SSL_F_DTLS1_ADD_CERT_TO_BUF:,2j226ERR_R_BUF_LIB:):;2 «return22	00J:;:}2ú2ó26p24=24(26unsigned26char24*24)2	4&amp;24(2<626buf2	4-&gt;26data2>[224*26l:]24):;2B2>2726l2n32)i(2j2	26n:,2j2	26p:):;2Q2M2F26i2d_X50924i(2j2	26x:,2j22	4&amp;26p:):;282424*26l24+=26n24+2	03J:;2 «return22	01J:;:}2∞2926unsigned26long26dtls1_output_cert_chain2Re(2$f22926SSL25*26s:,2%f22926X50925*26x:)2û<{232/2!926unsigned26char25*26p:;222926int26i:;2e2a2926unsigned26long26l27=202	03J24+26DTLS1_HM_HEADER_LENGTH:;2*2&2926BUF_MEM25*26buf:;2EA/* TLSv1 sends a chain with nothing in it, instead of an alert */2=2926buf24=2"626s2	4-&gt;26init_buf:;2ïûif2a;(2Z24!2L26BUF_MEM_grow_clean20i(2j226buf:,2j22
010J:):)2®C2£<{2l2h2a2
6SSLerr2Qi(2,j2%2!6SSL_F_DTLS1_OUTPUT_CERT_CHAIN:,2j226ERR_R_BUF_LIB:):;2.«return224(2	00J24):;:}2ß
ûif2%;(226x24!=26NULL:)2ˆ	C2Ò	<{2-2)2926X509_STORE_CTX2
6xs_ctx:;2˛ûif2»;(2¿24!2±26X509_STORE_CTX_init2ìi(2 j22	4&amp;2
6xs_ctx:,2Cj2<28626s2	4-&gt;26ctx2	4-&gt;26
cert_store:,2j2	26x:,2j226NULL:):)2©C2§<{2m2i2b2
6SSLerr2Ri(2,j2%2!6SSL_F_DTLS1_OUTPUT_CERT_CHAIN:,2j226ERR_R_X509_LIB:):;2.«return224(2	00J24):;:}2L2H2A26X509_verify_cert2'i(2 j22	4&amp;2
6xs_ctx:):;2)%/* Don't leave errors in the queue */2*2&226ERR_clear_error2i():;2Ωùfor2®(2"226i24=2	00J:;2c;2_26i24&lt;2G26sk_X509_num22i(2+j2$2 62
6xs_ctx24.2	6chain:):;2	226i24++:)2á<{2t2p26x24=2[26sk_X509_value2Di(2+j2$2 62
6xs_ctx24.2	6chain:,2j2	26i:):;2âûif2|;(2u24!2g26dtls1_add_cert_to_buf2Hi(2j226buf:,2j22	4&amp;26l:,2j2	26x:):)2C2{<{2R2N2G26X509_STORE_CTX_cleanup2'i(2 j22	4&amp;2
6xs_ctx:):;2 «return22	00J:;:}:}2U2N2G26X509_STORE_CTX_cleanup2'i(2 j22	4&amp;2
6xs_ctx:):;:}2/* Thawte special :-) */2óùfor2¡(2"226i24=2	00J:;2|;2x26i24&lt;2`26sk_X509_num2Ki(2Dj2=29626s2	4-&gt;26ctx2	4-&gt;26extra_certs:):;2	226i24++:)2»<{2é2â26x24=2t26sk_X509_value2]i(2Dj2=29626s2	4-&gt;26ctx2	4-&gt;26extra_certs:,2j2	26i:):;2Øûif2|;(2u24!2g26dtls1_add_cert_to_buf2Hi(2j226buf:,2j22	4&amp;26l:,2j2	26x:):)2%C2!<2«return22	00J:;:}2T2P26l24-=24(2	03J24+26DTLS1_HM_HEADER_LENGTH24):;2™2•26p24=24(26unsigned26char24*24)2	4&amp;24(2J626buf2	4-&gt;26data2(>[2!26DTLS1_HM_HEADER_LENGTH:]24):;2B2>2726l2n32)i(2j2	26l:,2j2	26p:):;2#226l24+=2	03J:;2ô2î26p24=24(26unsigned26char24*24)2	4&amp;24(29626buf2	4-&gt;26data2>[22	00J:]24):;2≈2¿26p24=2™26dtls1_set_message_header2ái(2j2	26s:,2j2	26p:,2"j226SSL3_MT_CERTIFICATE:,2j2	26l:,2j22	00J:,2j2	26l:):;242026l24+=26DTLS1_HM_HEADER_LENGTH:;2*«return224(26l24):;:}2Ä2926int26dtls1_read_failed2Me(2$f22926SSL25*26s:,2 f22926int26code:)2à<{2Öûif2+;(2$26code24&gt;2	00J:)2ŒC2…<{2ü2ö2í26fprintf2Äi(2j22
6stderr:,20j2)2%0"invalid state reached %s:%d"J:,2j226__FILE__:,2j226__LINE__:):;2 «return22	01J:;:}2âûif2L;(2E24!2726dtls1_is_timer_expired2i(2j2	26s:):)2±C2¨<{2É/* not a timeout, none of our business, $
$                   let higher layers handle this.  in fact it's probably an error */2«return226code:;:}2.œ#2óifndef26OPENSSL_NO_HEARTBEATS2ôûif2Ö;(2~24!2,26SSL_in_init2i(2j2	26s:)24
&amp;&amp;24!2+626s2	4-&gt;26tlsext_hb_pending:)2áC2,(/* done, no need to send a retransmit */2D#2	óelse2¬<2Ωûif2A;(2:24!2,26SSL_in_init2i(2j2	26s:):)2C2,(/* done, no need to send a retransmit */2À#2
óendif2©<{2Ä2|2u26BIO_set_flags2^i(28j212-26SSL_get_rbio2i(2j2	26s:):,2j226BIO_FLAGS_READ:):;2«return226code:;:}2û#2óif22	00J2î9/* for now, each alert contains only one record number */:Uitem = pqueue_peek(state-&gt;rcvd_records);$
$        if ( item )$
$                {2Q;/* send an alert immediately for all the missing records */:}$
$        else2À#2
óendif2û#2óif22	00J2ÄE/* no more alert sending, just retransmit the last set of messages */:¥if ( state-&gt;timeout.read_timeouts &gt;= DTLS1_TMO_READ_COUNT)$
$                ssl3_send_alert(s,SSL3_AL_WARNING,$
$                        DTLS1_AD_MISSING_HANDSHAKE_MESSAGE);2À#2
óendif2L«return2<2526dtls1_handle_timeout2i(2j2	26s:):;:}2Ÿ2926int26dtls1_get_queue_priority2Ze(2/f2(2926unsigned2	6short26seq:,2"f22926int2
6is_ccs:)2Õ<{2Ä˚/* The index of the retransmission queue actually is the message sequence number,$
$         * since the queue only contains messages of a single handshake. However, the$
$         * ChangeCipherSpec has no message sequence number and so using only the sequence$
$         * will result in the CCS and Finished having the same index. To prevent this,$
$         * the sequence number is multiplied by 2. In case of a CCS 1 is subtracted.$
$         * This does not only differ CSS and Finished, it also maintains the order of the$
$         * index (important for priority queues) and fits in the unsigned short variable.$
$         */2C«return2326seq24*2	02J24-2
6is_ccs:;:}2¥2926int2&6"dtls1_retransmit_buffered_messages2+e(2$f22926SSL25*26s:)2Õ
<{2j2f292
6pqueue26sent2E=2>2:626s2	4-&gt;26d12	4-&gt;26sent_messages:;2&2"2926	piterator26iter:;2)2%292	6pitem25*26item:;2/2+2926hm_fragment25*26frag:;27232926int2	6found2=22	00J:;2O2K26iter24=2326pqueue_iterator2i(2j226sent:):;2©ùfor2‹(2V2R26item24=2:26pqueue_next2%i(2j22	4&amp;26iter:):;2%;2!26item24!=26NULL:;2V	2O26item24=2:26pqueue_next2%i(2j22	4&amp;26iter:):)2ø<{2c2_26frag24=24(26hm_fragment24*24)2!626item2	4-&gt;26data:;2“ûif2ú;(2î2€26dtls1_retransmit_message2∏i(2j2	26s:,2Áj2ﬂ24(26unsigned2	6short24)2≥26dtls1_get_queue_priority2êi(2Bj2;27626frag2	4-&gt;26
msg_header24.26seq:,2Ej2>2:626frag2	4-&gt;26
msg_header24.2
6is_ccs:):,2j22	00J:,2j22	4&amp;2	6found:)2	4&lt;=2	00J24
&amp;&amp;2	6found:)2¶C2°<{2q2m2f26fprintf2Ui(2j22
6stderr:,27j202,0$"dtls1_retransmit_message() failed
"J:):;2'«return224-2	01J:;:}:}2 «return22	01J:;:}2ß$2926int26dtls1_buffer_message2Oe(2$f22926SSL25*26s:,2"f22926int2
6is_ccs:)2™#<{2)2%292	6pitem25*26item:;2/2+2926hm_fragment25*26frag:;2O2K2926unsigned26char2(626seq64be2>[22	08J:]:;2_[/* this function is called immediately after a message has $
$         * been serialized */2j2f2_26OPENSSL_assert2Gi(2@j292"626s2	4-&gt;26init_off24==2	00J:):;2Ü2Å26frag24=2i26dtls1_hm_fragment_new2Ji(2-j2&2"626s2	4-&gt;26init_num:,2j22	00J:):;2»2√2ª2
6memcpy2™i(20j2)2%626frag2	4-&gt;26fragment:,2Bj2;27626s2	4-&gt;26init_buf2	4-&gt;26data:,2-j2&2"626s2	4-&gt;26init_num:):;2∆ûif2;(22
6is_ccs:)2ëC2å<{2Ñ2¸2Ù26OPENSSL_assert2€i(2”j2À2J626s2	4-&gt;26d12	4-&gt;26	w_msg_hdr24.26msg_len24+24(2îB2U;2Q24(2!626s2	4-&gt;26version24==26DTLS1_VERSION24):?2#C226DTLS1_CCS_HEADER_LENGTH2D:22	03J24)24==24(26unsigned26int24)2"626s2	4-&gt;26init_num:):;:}2éDelse2É<{2˚2Û2Î26OPENSSL_assert2“i(2 j2¬2J626s2	4-&gt;26d12	4-&gt;26	w_msg_hdr24.26msg_len24+26DTLS1_HM_HEADER_LENGTH24==24(26unsigned26int24)2"626s2	4-&gt;26init_num:):;:}2ö2ï2;626frag2	4-&gt;26
msg_header24.26msg_len24=2J626s2	4-&gt;26d12	4-&gt;26	w_msg_hdr24.26msg_len:;2í2ç27626frag2	4-&gt;26
msg_header24.26seq24=2F626s2	4-&gt;26d12	4-&gt;26	w_msg_hdr24.26seq:;2î2è28626frag2	4-&gt;26
msg_header24.26type24=2G626s2	4-&gt;26d12	4-&gt;26	w_msg_hdr24.26type:;2Y2U2<626frag2	4-&gt;26
msg_header24.26frag_off24=2	00J:;2õ2ñ2<626frag2	4-&gt;26
msg_header24.26frag_len24=2J626s2	4-&gt;26d12	4-&gt;26	w_msg_hdr24.26msg_len:;2X2T2:626frag2	4-&gt;26
msg_header24.2
6is_ccs24=2
6is_ccs:;2/* save current state*/2†2õ2d626frag2	4-&gt;26
msg_header24.26saved_retransmit_state24.26enc_write_ctx24=2'626s2	4-&gt;26enc_write_ctx:;2ö2ï2a626frag2	4-&gt;26
msg_header24.26saved_retransmit_state24.26
write_hash24=2$626s2	4-&gt;26
write_hash:;2ñ2ë2_626frag2	4-&gt;26
msg_header24.26saved_retransmit_state24.26compress24=2"626s2	4-&gt;26compress:;2î2è2^626frag2	4-&gt;26
msg_header24.26saved_retransmit_state24.26session24=2!626s2	4-&gt;26session:;2•2†2\626frag2	4-&gt;26
msg_header24.26saved_retransmit_state24.2	6epoch24=24626s2	4-&gt;26d12	4-&gt;26w_epoch:;2Ü2Å2z2
6memset2ji(2j226seq64be:,2j22	00J:,25j2.2*®sizeof2i(2j226seq64be:):):;2¬2Ω2(626seq64be2>[22	06J:]24=2Ñ(26unsigned26char:)2·i(2Ÿj2—2≥26dtls1_get_queue_priority2êi(2Bj2;27626frag2	4-&gt;26
msg_header24.26seq:,2Ej2>2:626frag2	4-&gt;26
msg_header24.2
6is_ccs:)24&gt;&gt;2	08J:):;2©2§2(626seq64be2>[22	07J:]24=2Î(26unsigned26char:)2»i(2¿j2∏2≥26dtls1_get_queue_priority2êi(2Bj2;27626frag2	4-&gt;26
msg_header24.26seq:,2Ej2>2:626frag2	4-&gt;26
msg_header24.2
6is_ccs:):):;2a2]26item24=2E26	pitem_new22i(2j226seq64be:,2j226frag:):;2•ûif2(;(2!26item24==26NULL:)2rC2n<{2E2A2:26dtls1_hm_fragment_free2i(2j226frag:):;2 «return22	00J:;:}2˘û#2óif22	00J:ÿfprintf( stderr, "buffered messge: \ttype = %xx\n", msg_buf-&gt;type);$
$        fprintf( stderr, "\t\t\t\t\tlen = %d\n", msg_buf-&gt;len);$
$        fprintf( stderr, "\t\t\t\t\tseq_num = %d\n", msg_buf-&gt;seq_num);2À#2
óendif2É22x26pqueue_insert2ai(2Ej2>2:626s2	4-&gt;26d12	4-&gt;26sent_messages:,2j226item:):;2 «return22	01J:;:}2¯62926int26dtls1_retransmit_message2ªe(2$f22926SSL25*26s:,2/f2(2926unsigned2	6short26seq:,23f2,2926unsigned26long26frag_off:,2(f2!2926int25*2	6found:)2ä5<{222926int26ret:;2?;/* XDTLS: for now assuming that read/writes are blocking */2)2%292	6pitem25*26item:;2/2+2926hm_fragment25*26frag:;28242926unsigned26long26header_length:;2O2K2926unsigned26char2(626seq64be2>[22	08J:]:;2J2F2.92*62
6struct26dtls1_retransmit_state26saved_state:;2[2W2926unsigned26char24626save_write_sequence2>[22	08J:]:;2vr/*$
$          OPENSSL_assert(s-&gt;init_num == 0);$
$          OPENSSL_assert(s-&gt;init_off == 0);$
$         */2JF/* XDTLS:  the requested message ought to be found, otherwise error */2Ü2Å2z2
6memset2ji(2j226seq64be:,2j22	00J:,25j2.2*®sizeof2i(2j226seq64be:):):;2ë2å2(626seq64be2>[22	06J:]24=2T(26unsigned26char:)22i(2+j2$26seq24&gt;&gt;2	08J:):;2i2e2(626seq64be2>[22	07J:]24=24(26unsigned26char24)26seq:;2ñ2ë26item24=2y26pqueue_find2di(2Ej2>2:626s2	4-&gt;26d12	4-&gt;26sent_messages:,2j226seq64be:):;2õûif2(;(2!26item24==26NULL:)2ÁC2‚<{2â2Ñ2}26fprintf2li(2j22
6stderr:,2:j232/0'"retransmit:  message %d non-existant
"J:,2j226seq:):;2-2)24*2	6found24=2	00J:;2 «return22	00J:;:}2-2)24*2	6found24=2	01J:;2c2_26frag24=24(26hm_fragment24*24)2!626item2	4-&gt;26data:;2Íûif2H;(2A2:626frag2	4-&gt;26
msg_header24.2
6is_ccs:)2HC2D<2@2<26header_length24=26DTLS1_CCS_HEADER_LENGTH:;2MDelse2C<2?2;26header_length24=26DTLS1_HM_HEADER_LENGTH:;2˚2ˆ2Ó2
6memcpy2›i(2Bj2;27626s2	4-&gt;26init_buf2	4-&gt;26data:,20j2)2%626frag2	4-&gt;26fragment:,2`j2Y2;626frag2	4-&gt;26
msg_header24.26msg_len24+26header_length:):;2å2á2"626s2	4-&gt;26init_num24=2;626frag2	4-&gt;26
msg_header24.26msg_len24+26header_length:;2˚2ˆ2Ó2 6dtls1_set_message_header_int2«i(2j2	26s:,2Cj2<28626frag2	4-&gt;26
msg_header24.26type:,2Fj2?2;626frag2	4-&gt;26
msg_header24.26msg_len:,2Bj2;27626frag2	4-&gt;26
msg_header24.26seq:,2j22	00J:,2Gj2@2<626frag2	4-&gt;26
msg_header24.26frag_len:):;2/* save current state */2h2d2-626saved_state24.26enc_write_ctx24=2'626s2	4-&gt;26enc_write_ctx:;2b2^2*626saved_state24.26
write_hash24=2$626s2	4-&gt;26
write_hash:;2^2Z2(626saved_state24.26compress24=2"626s2	4-&gt;26compress:;2\2X2'626saved_state24.26session24=2!626s2	4-&gt;26session:;2m2i2%626saved_state24.2	6epoch24=24626s2	4-&gt;26d12	4-&gt;26w_epoch:;2m2i2%626saved_state24.2	6epoch24=24626s2	4-&gt;26d12	4-&gt;26w_epoch:;2X2T2;626s2	4-&gt;26d12	4-&gt;26retransmitting24=2	01J:;2@</* restore state in which the message was originally sent */2†2õ2'626s2	4-&gt;26enc_write_ctx24=2d626frag2	4-&gt;26
msg_header24.26saved_retransmit_state24.26enc_write_ctx:;2ö2ï2$626s2	4-&gt;26
write_hash24=2a626frag2	4-&gt;26
msg_header24.26saved_retransmit_state24.26
write_hash:;2ñ2ë2"626s2	4-&gt;26compress24=2_626frag2	4-&gt;26
msg_header24.26saved_retransmit_state24.26compress:;2î2è2!626s2	4-&gt;26session24=2^626frag2	4-&gt;26
msg_header24.26saved_retransmit_state24.26session:;2•2†24626s2	4-&gt;26d12	4-&gt;26w_epoch24=2\626frag2	4-&gt;26
msg_header24.26saved_retransmit_state24.2	6epoch:;2·ûif2¨;(2§2\626frag2	4-&gt;26
msg_header24.26saved_retransmit_state24.2	6epoch24==2%626saved_state24.2	6epoch24-2	01J:)2®C2£<{2ˆ2Ò2È2
6memcpy2ÿi(2"j226save_write_sequence:,2Fj2?2;626s2	4-&gt;26s32	4-&gt;26write_sequence:,2ej2^2Z®sizeof2Mi(2Fj2?2;626s2	4-&gt;26s32	4-&gt;26write_sequence:):):;2¢2ö2í2
6memcpy2Åi(2Fj2?2;626s2	4-&gt;26s32	4-&gt;26write_sequence:,2Kj2D2@626s2	4-&gt;26d12	4-&gt;26last_write_sequence:,2ej2^2Z®sizeof2Mi(2Fj2?2;626s2	4-&gt;26s32	4-&gt;26write_sequence:):):;:}22Î26ret24=2”26dtls1_do_write2∫i(2j2	26s:,2†j2ò2ìB2E;2A2:626frag2	4-&gt;26
msg_header24.2
6is_ccs:?2&C2"26SSL3_RT_CHANGE_CIPHER_SPEC2 D:226SSL3_RT_HANDSHAKE:):;2/* restore current state */2h2d2'626s2	4-&gt;26enc_write_ctx24=2-626saved_state24.26enc_write_ctx:;2b2^2$626s2	4-&gt;26
write_hash24=2*626saved_state24.26
write_hash:;2^2Z2"626s2	4-&gt;26compress24=2(626saved_state24.26compress:;2\2X2!626s2	4-&gt;26session24=2'626saved_state24.26session:;2m2i24626s2	4-&gt;26d12	4-&gt;26w_epoch24=2%626saved_state24.2	6epoch:;2·ûif2¨;(2§2\626frag2	4-&gt;26
msg_header24.26saved_retransmit_state24.2	6epoch24==2%626saved_state24.2	6epoch24-2	01J:)2®C2£<{2ü2ö2í2
6memcpy2Åi(2Kj2D2@626s2	4-&gt;26d12	4-&gt;26last_write_sequence:,2Fj2?2;626s2	4-&gt;26s32	4-&gt;26write_sequence:,2ej2^2Z®sizeof2Mi(2Fj2?2;626s2	4-&gt;26s32	4-&gt;26write_sequence:):):;2˘2Ò2È2
6memcpy2ÿi(2Fj2?2;626s2	4-&gt;26s32	4-&gt;26write_sequence:,2"j226save_write_sequence:,2ej2^2Z®sizeof2Mi(2Fj2?2;626s2	4-&gt;26s32	4-&gt;26write_sequence:):):;:}2X2T2;626s2	4-&gt;26d12	4-&gt;26retransmitting24=2	00J:;2u2q24(26void24)2R26	BIO_flush2?i(28j212-26SSL_get_wbio2i(2j2	26s:):):;2«return226ret:;:}2LH/* call this function when the buffered messages are no longer needed */2ñ2926void26dtls1_clear_record_buffer2+e(2$f22926SSL25*26s:)2∑<{2)2%292	6pitem25*26item:;2Ñùfor2®(2|2x26item24=2`26
pqueue_pop2Li(2Ej2>2:626s2	4-&gt;26d12	4-&gt;26sent_messages:):;2%;2!26item24!=26NULL:;2|	2u26item24=2`26
pqueue_pop2Li(2Ej2>2:626s2	4-&gt;26d12	4-&gt;26sent_messages:):)2À<{2Ö2Ä2y26dtls1_hm_fragment_free2Yi(2Rj2K24(26hm_fragment24*24)2!626item2	4-&gt;26data:):;2<252.26
pitem_free2i(2j226item:):;:}:}2Ú2!926unsigned26char25*26dtls1_set_message_header2©e(2$f22926SSL25*26s:,23f2,2!926unsigned26char25*26p:,2-f2&2926unsigned26char26mt:,2.f2'2926unsigned26long26len:,23f2,2926unsigned26long26frag_off:,23f2,2926unsigned26long26frag_len:)2Ä<{273/* Don't change sequence numbers while listening */2âûif2y;(2r26frag_off24==2	00J24
&amp;&amp;24!23626s2	4-&gt;26d12	4-&gt;2
6listen:)2ÑC2ˇ<{2ö2ï2@626s2	4-&gt;26d12	4-&gt;26handshake_write_seq24=2E626s2	4-&gt;26d12	4-&gt;26next_handshake_write_seq:;2[2T2E626s2	4-&gt;26d12	4-&gt;26next_handshake_write_seq24++:;:}2Ò2Ï2‰2 6dtls1_set_message_header_int2Ωi(2j2	26s:,2j2
26mt:,2j226len:,2Kj2D2@626s2	4-&gt;26d12	4-&gt;26handshake_write_seq:,2j226frag_off:,2j226frag_len:):;2@«return2026p24+=26DTLS1_HM_HEADER_LENGTH:;:}2MI/* don't actually do the writing, wait till the MTU has been retrieved */2Á2ÿstatic2926void2 6dtls1_set_message_header_int2©e(2$f22926SSL25*26s:,2-f2&2926unsigned26char26mt:,2.f2'2926unsigned26long26len:,23f2,2926unsigned2	6short26seq_num:,23f2,2926unsigned26long26frag_off:,23f2,2926unsigned26long26frag_len:)2˘<{2í2ç2+92 62
6struct26hm_header_st25*26msg_hdr2L=2E2	4&amp;26626s2	4-&gt;26d12	4-&gt;26	w_msg_hdr:;2>2:2$626msg_hdr2	4-&gt;26type24=26mt:;2B2>2'626msg_hdr2	4-&gt;26msg_len24=26len:;2B2>2#626msg_hdr2	4-&gt;26seq24=26seq_num:;2H2D2(626msg_hdr2	4-&gt;26frag_off24=26frag_off:;2K2D2(626msg_hdr2	4-&gt;26frag_len24=26frag_len:;:}2á2ÿstatic2926void26dtls1_fix_message_header2ïe(2$f22926SSL25*26s:,23f2,2926unsigned26long26frag_off:,23f2,2926unsigned26long26frag_len:)2±<{2í2ç2+92 62
6struct26hm_header_st25*26msg_hdr2L=2E2	4&amp;26626s2	4-&gt;26d12	4-&gt;26	w_msg_hdr:;2H2D2(626msg_hdr2	4-&gt;26frag_off24=26frag_off:;2K2D2(626msg_hdr2	4-&gt;26frag_len24=26frag_len:;:}2“2ÿstatic2!926unsigned26char25*26dtls1_write_message_header2`e(2$f22926SSL25*26s:,23f2,2!926unsigned26char25*26p:)2õ<{2í2ç2+92 62
6struct26hm_header_st25*26msg_hdr2L=2E2	4&amp;26626s2	4-&gt;26d12	4-&gt;26	w_msg_hdr:;2L2H24*26p24++24=2$626msg_hdr2	4-&gt;26type:;2d2`2Y26l2n32Ki(22j2+2'626msg_hdr2	4-&gt;26msg_len:,2j2	26p:):;2_2[2T26s2n2Gi(2.j2'2#626msg_hdr2	4-&gt;26seq:,2j2	26p:):;2e2a2Z26l2n32Li(23j2,2(626msg_hdr2	4-&gt;26frag_off:,2j2	26p:):;2e2a2Z26l2n32Li(23j2,2(626msg_hdr2	4-&gt;26frag_len:,2j2	26p:):;2«return226p:;:}2“2926unsigned26int26dtls1_min_mtu2e(2f22926void:)2ˇ<{2˜«return2Ê24(2–626g_probable_mtu2∑>[2Ø24(21®sizeof2$i(2j226g_probable_mtu:)24/2N®sizeof2Ai(2:j232/626g_probable_mtu2>[22	00J:]:)24)24-2	01J:]24):;:}2˛2ÿstatic2926unsigned26int26dtls1_guess_mtu29e(22f2+2926unsigned26int26curr_mtu:)2Å<{2+2'2926unsigned26int26i:;2Éûif2-;(2&26curr_mtu24==2	00J:)2KC2G<2C«return262/626g_probable_mtu2>[22	00J:]:;2°ùfor2Î(2"226i24=2	00J:;2•;2†26i24&lt;21®sizeof2$i(2j226g_probable_mtu:)24/2N®sizeof2Ai(2:j232/626g_probable_mtu2>[22	00J:]:):;2	226i24++:)2®<2£ûif2Q;(2J26curr_mtu24&gt;2+626g_probable_mtu2>[226i:]:)2GC2C<2?«return222+626g_probable_mtu2>[226i:]:;2#«return226curr_mtu:;:}2ÿ2926void26dtls1_get_message_header2Çe(26f2/2!926unsigned26char25*26data:,2Cf2<2+92 62
6struct26hm_header_st25*26msg_hdr:)2¢<{2ó2í2ä2
6memset2zi(2j226msg_hdr:,2j2200x00J:,2Bj2;27®sizeof2*i(2#j2struct26hm_header_st:):):;2]2Y2$626msg_hdr2	4-&gt;26type24=24*24(26data24++24):;2g2c2\26n2l32Ni(2j226data:,22j2+2'626msg_hdr2	4-&gt;26msg_len:):;2b2^2W26n2s2Ji(2j226data:,2.j2'2#626msg_hdr2	4-&gt;26seq:):;2h2d2]26n2l32Oi(2j226data:,23j2,2(626msg_hdr2	4-&gt;26frag_off:):;2k2d2]26n2l32Oi(2j226data:,23j2,2(626msg_hdr2	4-&gt;26frag_len:):;:}2µ2926void26dtls1_get_ccs_header2Ée(26f2/2!926unsigned26char25*26data:,2Df2=2,92!62
6struct26ccs_header_st25*26ccs_hdr:)2Ç<{2ò2ì2ã2
6memset2{i(2j226ccs_hdr:,2j2200x00J:,2Cj2<28®sizeof2+i(2$j2struct26ccs_header_st:):):;2`2Y2$626ccs_hdr2	4-&gt;26type24=24*24(26data24++24):;:}2Ò	2926int26dtls1_shutdown2+e(2$f22926SSL25*26s:)2û	<{222926int26ret:;2(œ#2óifndef26OPENSSL_NO_SCTP2œûif2‘;(2Ã2Z26BIO_dgram_is_sctp2?i(28j212-26SSL_get_wbio2i(2j2	26s:):)24
&amp;&amp;24!24(2"626s2	4-&gt;26shutdown2	4&amp;26SSL_SENT_SHUTDOWN24):)2ÓC2È<{22{26ret24=2d26BIO_dgram_sctp_wait_for_dry2?i(28j212-26SSL_get_wbio2i(2j2	26s:):):;2aûif2*;(2#26ret24&lt;2	00J:)2,C2(<2$«return224-2	01J:;2˝ûif2(;(2!26ret24==2	00J:)2∆C2¡<2º2∑2Ø26BIO_ctrl2úi(28j212-26SSL_get_wbio2i(2j2	26s:):,20j2)2%6!BIO_CTRL_DGRAM_SCTP_SAVE_SHUTDOWN:,2j22	01J:,2j226NULL:):;:}2À#2
óendif2I2E26ret24=2.26ssl3_shutdown2i(2j2	26s:):;2(œ#2óifndef26OPENSSL_NO_SCTP2º2∑2Ø26BIO_ctrl2úi(28j212-26SSL_get_wbio2i(2j2	26s:):,20j2)2%6!BIO_CTRL_DGRAM_SCTP_SAVE_SHUTDOWN:,2j22	00J:,2j226NULL:):;2À#2
óendif2«return226ret:;:}2.œ#2óifndef26OPENSSL_NO_HEARTBEATS2∂2926int26dtls1_process_heartbeat2+e(2$f22926SSL25*26s:)2⁄<{2¯2¢2!926unsigned26char25*26p2q=2j2	4&amp;2[626s2	4-&gt;26s32	4-&gt;26rrec24.26data2>[22	00J:]:,25*2H2995This is just a placeholder. Please ignore this child.26pl:;222.2926unsigned2	6short2
6hbtype:;212-2926unsigned26int26payload:;2H2D2926unsigned26int26padding2=22
016J:;2/* Use minimum padding */2,(/* Read type and payload length first */222.2
6hbtype24=24*26p24++:;2G2C2<26n2s2/i(2j2	26p:,2j226payload:):;2226pl24=26p:;2¸ûif24;(2-2&626s2	4-&gt;26msg_callback:)2ºC2∑<2≤2≠2•2&626s2	4-&gt;26msg_callback2¯i(2j22	00J:,2,j2%2!626s2	4-&gt;26version:,2 j226TLS1_RT_HEARTBEAT:,2qj2j2	4&amp;2[626s2	4-&gt;26s32	4-&gt;26rrec24.26data2>[22	00J:]:,2Oj2H2D626s2	4-&gt;26s32	4-&gt;26rrec24.2
6length:,2j2	26s:,25j2.2*626s2	4-&gt;26msg_callback_arg:):;2öûif25;(2.2
6hbtype24==26TLS1_HB_REQUEST:)2ÉC2˛<{2â242!926unsigned26char25*2
6buffer:,25*2H2995This is just a placeholder. Please ignore this child.26bp:;222926int26r:;2æπ/* Allocate memory for the response, size is 1 byte$
$                 * message type, plus 2 bytes payload length, plus$
$                 * payload, plus padding$
$                 */2å2á2
6buffer24=2m26OPENSSL_malloc2Ui(2Nj2G2	01J24+2	02J24+26payload24+26padding:):;2$2 26bp24=2
6buffer:;262/* Enter response type, length and copy payload */2=2924*26bp24++24=26TLS1_HB_RESPONSE:;2H2D2=26s2n20i(2j226payload:,2j2
26bp:):;2^2Z2S2
6memcpy2Ci(2j2
26bp:,2j2
26pl:,2j226payload:):;2&2"26bp24+=26payload:;2/* Random padding */2V2R2K26RAND_pseudo_bytes20i(2j2
26bp:,2j226padding:):;2≈2¿26r24=2™26dtls1_write_bytes2éi(2j2	26s:,2 j226TLS1_RT_HEARTBEAT:,2j22
6buffer:,2<j252	03J24+26payload24+26padding:):;2∫ûif2a;(2Z26r2	4&gt;=2	00J24
&amp;&amp;2&626s2	4-&gt;26msg_callback:)2ÕC2»<2√2æ2∂2&626s2	4-&gt;26msg_callback2âi(2j22	01J:,2,j2%2!626s2	4-&gt;26version:,2 j226TLS1_RT_HEARTBEAT:,2j22
6buffer:,2<j252	03J24+26payload24+26padding:,2j2	26s:,25j2.2*626s2	4-&gt;26msg_callback_arg:):;2=292226OPENSSL_free2i(2j22
6buffer:):;2Wûif2(;(2!26r24&lt;2	00J:)2!C2<2«return226r:;:}2”Eelse2»ûif26;(2/2
6hbtype24==26TLS1_HB_RESPONSE:)2ÜC2Å<{2-2)2926unsigned26int26seq:;2™•/* We only send sequence numbers (2 bytes unsigned int),$
$                 * and 16 random bytes, so we just try to read the$
$                 * sequence number */2D2@2926n2s2,i(2j2
26pl:,2j226seq:):;2◊ûif2w;(2p26payload24==2
018J24
&amp;&amp;26seq24==2'626s2	4-&gt;26tlsext_hb_seq:)2—C2Ã<{2<282126dtls1_stop_timer2i(2j2	26s:):;2:262'626s2	4-&gt;26tlsext_hb_seq24++:;2K2D2+626s2	4-&gt;26tlsext_hb_pending24=2	00J:;:}:}2 «return22	00J:;:}2≤2926int26dtls1_heartbeat2+e(2$f22926SSL25*26s:)2ﬁ<{2Ö212!926unsigned26char25*26buf:,25*2G2995This is just a placeholder. Please ignore this child.26p:;222926int26ret:;2H2D2926unsigned26int26payload2=22
018J:;2($/* Sequence number + random bytes */2H2D2926unsigned26int26padding2=22
016J:;2/* Use minimum padding */2?;/* Only send if peer supports and accepts HB requests... */2òûif2Ÿ;(2—24!24(2*626s2	4-&gt;26tlsext_heartbeat2	4&amp;26SSL_TLSEXT_HB_ENABLED24)24||2*626s2	4-&gt;26tlsext_heartbeat2	4&amp;2$6 SSL_TLSEXT_HB_DONT_SEND_REQUESTS:)2≤C2≠<{2}2y2r2
6SSLerr2bi(2$j226SSL_F_DTLS1_HEARTBEAT:,25j2.2*6&SSL_R_TLS_HEARTBEAT_PEER_DOESNT_ACCEPT:):;2'«return224-2	01J:;:}2/+/* ...and there is none in flight yet... */2Ïûif29;(222+626s2	4-&gt;26tlsext_hb_pending:)2ßC2¢<{2r2n2g2
6SSLerr2Wi(2$j226SSL_F_DTLS1_HEARTBEAT:,2*j2#26SSL_R_TLS_HEARTBEAT_PENDING:):;2'«return224-2	01J:;:}2*&/* ...and no handshake in progress. */2öûif2j;(2c2,26SSL_in_init2i(2j2	26s:)24||2&626s2	4-&gt;26in_handshake:)2§C2ü<{2o2k2d2
6SSLerr2Ti(2$j226SSL_F_DTLS1_HEARTBEAT:,2'j2 26SSL_R_UNEXPECTED_MESSAGE:):;2'«return224-2	01J:;:}2ÖÄ/* Check if padding is too long, payload and padding$
$         * must not exceed 2^14 - 3 = 16381 bytes in total.$
$         */2n2j2c26OPENSSL_assert2Ki(2Dj2=26payload24+26padding2	4&lt;=2016381J:):;2ïê/* Create HeartBeat message, we just use a sequence number$
$         * as payload to distuingish different messages and add$
$         * some random stuff.$
$         *  - Message Type, 1 byte$
$         *  - Payload Length, 2 bytes (unsigned int)$
$         *  - Payload, the sequence number (2 bytes uint)$
$         *  - Payload, random bytes (16 bytes uint)$
$         *  - Padding$
$         */2â2Ñ26buf24=2m26OPENSSL_malloc2Ui(2Nj2G2	01J24+2	02J24+26payload24+26padding:):;2 226p24=26buf:;2/* Message Type */2;2724*26p24++24=26TLS1_HB_REQUEST:;2($/* Payload length (18 bytes here) */2G2C2<26s2n2/i(2j226payload:,2j2	26p:):;2/* Sequence number */2c2_2X26s2n2Ki(22j2+2'626s2	4-&gt;26tlsext_hb_seq:,2j2	26p:):;2/* 16 random bytes */2T2P2I26RAND_pseudo_bytes2.i(2j2	26p:,2j22
016J:):;2$2 26p24+=2
016J:;2/* Random padding */2U2Q2J26RAND_pseudo_bytes2/i(2j2	26p:,2j226padding:):;2ƒ2ø26ret24=2ß26dtls1_write_bytes2ãi(2j2	26s:,2 j226TLS1_RT_HEARTBEAT:,2j226buf:,2<j252	03J24+26payload24+26padding:):;2⁄ûif2+;(2$26ret2	4&gt;=2	00J:)2£C2û<{2äûif24;(2-2&626s2	4-&gt;26msg_callback:)2 C2≈<2¿2ª2≥2&626s2	4-&gt;26msg_callback2Üi(2j22	01J:,2,j2%2!626s2	4-&gt;26version:,2 j226TLS1_RT_HEARTBEAT:,2j226buf:,2<j252	03J24+26payload24+26padding:,2j2	26s:,25j2.2*626s2	4-&gt;26msg_callback_arg:):;2=292226dtls1_start_timer2i(2j2	26s:):;2K2D2+626s2	4-&gt;26tlsext_hb_pending24=2	01J:;:}2:262/26OPENSSL_free2i(2j226buf:):;2«return226ret:;:}2À#2
óendifB
src.c0.9.5