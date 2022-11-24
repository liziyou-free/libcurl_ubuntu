/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/
/* <DESC>
 * Very simple HTTP/3 GET
 * </DESC>
 */
#include <stdio.h>
#include <curl/curl.h>

//int main(void)
//{
//  CURL *curl;
//  CURLcode res;
//
//  curl = curl_easy_init();
//  if(curl) {
//    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
//
//    /* Forcing HTTP/3 will make the connection fail if the server is not
//       accessible over QUIC + HTTP/3 on the given host and port.
//       Consider using CURLOPT_ALTSVC instead! */
//    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_3);
//
//    /* Perform the request, res will get the return code */
//    res = curl_easy_perform(curl);
//    /* Check for errors */
//    if(res != CURLE_OK)
//      fprintf(stderr, "curl_easy_perform() failed: %s\n",
//              curl_easy_strerror(res));
//
//    /* always cleanup */
//    curl_easy_cleanup(curl);
//  }
//  return 0;
//}



/*
 *  SSL client demonstration program
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#include "mbedtls/mbedtls_config.h"
#include "mbedtls/platform.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
//#include "mbedtls/certs.h"

#if AOS_COMP_CLI
#include "aos/cli.h"
#endif

#include <string.h>

static const char globalsign_g2_ca_cert[] ="\
-----BEGIN CERTIFICATE-----\r\n\
MIIKEjCCCPqgAwIBAgIMRBfOhu+C7GkhzG9oMA0GCSqGSIb3DQEBCwUAMFAxCzAJ\r\n\
BgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSYwJAYDVQQDEx1H\r\n\
bG9iYWxTaWduIFJTQSBPViBTU0wgQ0EgMjAxODAeFw0yMjA3MDUwNTE2MDJaFw0y\r\n\
MzA4MDYwNTE2MDFaMIGnMQswCQYDVQQGEwJDTjEQMA4GA1UECBMHYmVpamluZzEQ\r\n\
MA4GA1UEBxMHYmVpamluZzElMCMGA1UECxMcc2VydmljZSBvcGVyYXRpb24gZGVw\r\n\
YXJ0bWVudDE5MDcGA1UEChMwQmVpamluZyBCYWlkdSBOZXRjb20gU2NpZW5jZSBU\r\n\
ZWNobm9sb2d5IENvLiwgTHRkMRIwEAYDVQQDEwliYWlkdS5jb20wggEiMA0GCSqG\r\n\
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCqL8xBjSWug+n0J8QAszlvDpgqVX0H5YBJ\r\n\
gvrT04WYtd97b7sC3e145AwHK54ehkv2aoZY11dvIVkR2G+WbtLeNij2tOPOlTIp\r\n\
AMFljmmwAP5SN/SIP4ttD7vw7MXAMe+ttQwGZq2+3EMTxGawXc9WU+LRloIcBrub\r\n\
X+1gjdLt89JQ7rvNsjaXyM570ku3XLSIyjdui875lv209Ue1IHe7/KidgbJs+McJ\r\n\
at0iboM/p1Pf8dovKWsiw+kdZejFoLoTThY/A5PwpVmKGoDoJ31JI9/R+UuXtwHE\r\n\
GfXxxf+RM9ChdMbu1M/2OAztvV6qRPuI93uZcHY0VX5V0g+ev5STAgMBAAGjggaS\r\n\
MIIGjjAOBgNVHQ8BAf8EBAMCBaAwgY4GCCsGAQUFBwEBBIGBMH8wRAYIKwYBBQUH\r\n\
MAKGOGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2dzcnNhb3Zz\r\n\
c2xjYTIwMTguY3J0MDcGCCsGAQUFBzABhitodHRwOi8vb2NzcC5nbG9iYWxzaWdu\r\n\
LmNvbS9nc3JzYW92c3NsY2EyMDE4MFYGA1UdIARPME0wQQYJKwYBBAGgMgEUMDQw\r\n\
MgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRv\r\n\
cnkvMAgGBmeBDAECAjAJBgNVHRMEAjAAMD8GA1UdHwQ4MDYwNKAyoDCGLmh0dHA6\r\n\
Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3Nyc2FvdnNzbGNhMjAxOC5jcmwwggNhBgNV\r\n\
HREEggNYMIIDVIIJYmFpZHUuY29tggxiYWlmdWJhby5jb22CDHd3dy5iYWlkdS5j\r\n\
boIQd3d3LmJhaWR1LmNvbS5jboIPbWN0LnkubnVvbWkuY29tggthcG9sbG8uYXV0\r\n\
b4IGZHd6LmNuggsqLmJhaWR1LmNvbYIOKi5iYWlmdWJhby5jb22CESouYmFpZHVz\r\n\
dGF0aWMuY29tgg4qLmJkc3RhdGljLmNvbYILKi5iZGltZy5jb22CDCouaGFvMTIz\r\n\
LmNvbYILKi5udW9taS5jb22CDSouY2h1YW5rZS5jb22CDSoudHJ1c3Rnby5jb22C\r\n\
DyouYmNlLmJhaWR1LmNvbYIQKi5leXVuLmJhaWR1LmNvbYIPKi5tYXAuYmFpZHUu\r\n\
Y29tgg8qLm1iZC5iYWlkdS5jb22CESouZmFueWkuYmFpZHUuY29tgg4qLmJhaWR1\r\n\
YmNlLmNvbYIMKi5taXBjZG4uY29tghAqLm5ld3MuYmFpZHUuY29tgg4qLmJhaWR1\r\n\
cGNzLmNvbYIMKi5haXBhZ2UuY29tggsqLmFpcGFnZS5jboINKi5iY2Vob3N0LmNv\r\n\
bYIQKi5zYWZlLmJhaWR1LmNvbYIOKi5pbS5iYWlkdS5jb22CEiouYmFpZHVjb250\r\n\
ZW50LmNvbYILKi5kbG5lbC5jb22CCyouZGxuZWwub3JnghIqLmR1ZXJvcy5iYWlk\r\n\
dS5jb22CDiouc3UuYmFpZHUuY29tgggqLjkxLmNvbYISKi5oYW8xMjMuYmFpZHUu\r\n\
Y29tgg0qLmFwb2xsby5hdXRvghIqLnh1ZXNodS5iYWlkdS5jb22CESouYmouYmFp\r\n\
ZHViY2UuY29tghEqLmd6LmJhaWR1YmNlLmNvbYIOKi5zbWFydGFwcHMuY26CDSou\r\n\
YmR0anJjdi5jb22CDCouaGFvMjIyLmNvbYIMKi5oYW9rYW4uY29tgg8qLnBhZS5i\r\n\
YWlkdS5jb22CESoudmQuYmRzdGF0aWMuY29tghEqLmNsb3VkLmJhaWR1LmNvbYIS\r\n\
Y2xpY2suaG0uYmFpZHUuY29tghBsb2cuaG0uYmFpZHUuY29tghBjbS5wb3MuYmFp\r\n\
ZHUuY29tghB3bi5wb3MuYmFpZHUuY29tghR1cGRhdGUucGFuLmJhaWR1LmNvbTAd\r\n\
BgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwHwYDVR0jBBgwFoAU+O9/8s14\r\n\
Z6jeb48kjYjxhwMCs+swHQYDVR0OBBYEFDtwLT3oGQUARxIC74EY00EI5RZSMIIB\r\n\
gQYKKwYBBAHWeQIEAgSCAXEEggFtAWsAdwDoPtDaPvUGNTLnVyi8iWvJA9PL0RFr\r\n\
7Otp4Xd9bQa9bgAAAYHMyXLxAAAEAwBIMEYCIQCAJkJ9PZHF14jjp5pQmOqVHgWc\r\n\
KJQe/CzCYYtU1jRusgIhAIKcdmnRNSZFGV0wNG9kEneZq3NtcvkKFiiNc4OV9HXe\r\n\
AHcAb1N2rDHwMRnYmQCkURX/dxUcEdkCwQApBo2yCJo32RMAAAGBzMlyzgAABAMA\r\n\
SDBGAiEA5hWVNwpM5TgNnimQHL0PCjW/sMVCuDDcCjcIn8Q+yvoCIQDuUewoBK8z\r\n\
iBT+9+oWB4PZNcn845lM6CmywA7DkbPzgQB3AFWB1MIWkDYBSuoLm1c8U/DA5Dh4\r\n\
cCUIFy+jqh0HE9MMAAABgczJcvwAAAQDAEgwRgIhAJ8GGwADLa35t5AptPcYTl8G\r\n\
w8Z/ApE7WLF/aa008TuvAiEAnn86opE4Rx90KXEWoY1UuuK3A3c0DMhNkLT7SWM+\r\n\
uRIwDQYJKoZIhvcNAQELBQADggEBAGMhByNHBuuzfHds37xVErnxXmoEYBa+0AsY\r\n\
nJQMqIIIJQ0m+93L/Iwn2Qz6SrYxtmfwJiwNlpY5ZT/Zoe7enBBNVOHI1qkOd9sA\r\n\
4jfjP7ScMU+sdNMiElM20O8YBy2O0OaRsmxKXjlTFFhO0VAEyYN+DXsVlocR111K\r\n\
F6yqn4TjqCSd1hd3JoyfensY2jkvd/crxyO4l2/D0XJMfvzGDcxzOBmB++fBeui5\r\n\
HToF3DYEm/Hw4aZHoDBPVZBs2s+esnYSEaFctmGNFaRoZZpXL3puox/1tJJaPN9x\r\n\
Cs1X1NAVNn661QMlJ0W0YM0uAsEPCudBb1hpIJ6tR1IatebljR0=\r\n\
-----END CERTIFICATE-----\r\n\
-----BEGIN CERTIFICATE-----\r\n\
MIIETjCCAzagAwIBAgINAe5fIh38YjvUMzqFVzANBgkqhkiG9w0BAQsFADBMMSAw\r\n\
HgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEGA1UEChMKR2xvYmFs\r\n\
U2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0xODExMjEwMDAwMDBaFw0yODEx\r\n\
MjEwMDAwMDBaMFAxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52\r\n\
LXNhMSYwJAYDVQQDEx1HbG9iYWxTaWduIFJTQSBPViBTU0wgQ0EgMjAxODCCASIw\r\n\
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKdaydUMGCEAI9WXD+uu3Vxoa2uP\r\n\
UGATeoHLl+6OimGUSyZ59gSnKvuk2la77qCk8HuKf1UfR5NhDW5xUTolJAgvjOH3\r\n\
idaSz6+zpz8w7bXfIa7+9UQX/dhj2S/TgVprX9NHsKzyqzskeU8fxy7quRU6fBhM\r\n\
abO1IFkJXinDY+YuRluqlJBJDrnw9UqhCS98NE3QvADFBlV5Bs6i0BDxSEPouVq1\r\n\
lVW9MdIbPYa+oewNEtssmSStR8JvA+Z6cLVwzM0nLKWMjsIYPJLJLnNvBhBWk0Cq\r\n\
o8VS++XFBdZpaFwGue5RieGKDkFNm5KQConpFmvv73W+eka440eKHRwup08CAwEA\r\n\
AaOCASkwggElMA4GA1UdDwEB/wQEAwIBhjASBgNVHRMBAf8ECDAGAQH/AgEAMB0G\r\n\
A1UdDgQWBBT473/yzXhnqN5vjySNiPGHAwKz6zAfBgNVHSMEGDAWgBSP8Et/qC5F\r\n\
JK5NUPpjmove4t0bvDA+BggrBgEFBQcBAQQyMDAwLgYIKwYBBQUHMAGGImh0dHA6\r\n\
Ly9vY3NwMi5nbG9iYWxzaWduLmNvbS9yb290cjMwNgYDVR0fBC8wLTAroCmgJ4Yl\r\n\
aHR0cDovL2NybC5nbG9iYWxzaWduLmNvbS9yb290LXIzLmNybDBHBgNVHSAEQDA+\r\n\
MDwGBFUdIAAwNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5j\r\n\
b20vcmVwb3NpdG9yeS8wDQYJKoZIhvcNAQELBQADggEBAJmQyC1fQorUC2bbmANz\r\n\
EdSIhlIoU4r7rd/9c446ZwTbw1MUcBQJfMPg+NccmBqixD7b6QDjynCy8SIwIVbb\r\n\
0615XoFYC20UgDX1b10d65pHBf9ZjQCxQNqQmJYaumxtf4z1s4DfjGRzNpZ5eWl0\r\n\
6r/4ngGPoJVpjemEuunl1Ig423g7mNA2eymw0lIYkN5SQwCuaifIFJ6GlazhgDEw\r\n\
fpolu4usBCOmmQDo8dIm7A9+O4orkjgTHY+GzYZSR+Y0fFukAj6KYXwidlNalFMz\r\n\
hriSqHKvoflShx8xpfywgVcvzfTO3PYkz6fiNJBonf6q8amaEsybwMbDqKWwIX7e\r\n\
SPY=\r\n\
-----END CERTIFICATE-----\r\n\
-----BEGIN CERTIFICATE-----\r\n\
MIIDXzCCAkegAwIBAgILBAAAAAABIVhTCKIwDQYJKoZIhvcNAQELBQAwTDEgMB4G\r\n\
A1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNp\r\n\
Z24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDkwMzE4MTAwMDAwWhcNMjkwMzE4\r\n\
MTAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEG\r\n\
A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZI\r\n\
hvcNAQEBBQADggEPADCCAQoCggEBAMwldpB5BngiFvXAg7aEyiie/QV2EcWtiHL8\r\n\
RgJDx7KKnQRfJMsuS+FggkbhUqsMgUdwbN1k0ev1LKMPgj0MK66X17YUhhB5uzsT\r\n\
gHeMCOFJ0mpiLx9e+pZo34knlTifBtc+ycsmWQ1z3rDI6SYOgxXG71uL0gRgykmm\r\n\
KPZpO/bLyCiR5Z2KYVc3rHQU3HTgOu5yLy6c+9C7v/U9AOEGM+iCK65TpjoWc4zd\r\n\
QQ4gOsC0p6Hpsk+QLjJg6VfLuQSSaGjlOCZgdbKfd/+RFO+uIEn8rUAVSNECMWEZ\r\n\
XriX7613t2Saer9fwRPvm2L7DWzgVGkWqQPabumDk3F2xmmFghcCAwEAAaNCMEAw\r\n\
DgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFI/wS3+o\r\n\
LkUkrk1Q+mOai97i3Ru8MA0GCSqGSIb3DQEBCwUAA4IBAQBLQNvAUKr+yAzv95ZU\r\n\
RUm7lgAJQayzE4aGKAczymvmdLm6AC2upArT9fHxD4q/c2dKg8dEe3jgr25sbwMp\r\n\
jjM5RcOO5LlXbKr8EpbsU8Yt5CRsuZRj+9xTaGdWPoO4zzUhw8lo/s7awlOqzJCK\r\n\
6fBdRoyV3XpYKBovHd7NADdBj+1EbddTKJd+82cEHhXXipa0095MJ6RMG3NzdvQX\r\n\
mcIfeg7jLQitChws/zyrVQ4PkX4268NXSb7hLi18YIvDQVETI53O9zJrlAGomecs\r\n\
Mx86OyXShkDOOyyGeMlhLxS67ttVb9+E7gUJTb0o2HLO02JQZR7rkpeDMdmztcpH\r\n\
WD9f\r\n\
-----END CERTIFICATE-----";


static const size_t globalsign_g2_ca_cert_len = sizeof(globalsign_g2_ca_cert);

#define SERVER_PORT "443"
#define SERVER_NAME "www.baidu.com"
#define GET_REQUEST "GET / HTTP/1.0\r\n\r\n"

#define DEBUG_LEVEL 1

static void tls_example_debug( void *ctx, int level,
                      const char *file, int line,
                      const char *str )
{
    ((void) level);

    printf("%s\n", str);
}

/* Notice: It's designed only for this example, please design your own
 * random algorithm for security concern.
 */
static int tls_example_random(void *handle, unsigned char *output, size_t output_len)
{
    uint32_t idx = 0, bytes = 0, rand_num = 0;
    struct timeval time;

    memset(&time, 0, sizeof(struct timeval));
    gettimeofday(&time, NULL);

    srand((unsigned int)(time.tv_sec * 1000 + time.tv_usec / 1000) + rand());

    for (idx = 0; idx < output_len;) {
        if (output_len - idx < 4) {
            bytes = output_len - idx;
        } else {
            bytes = 4;
        }
        rand_num = rand();
        while (bytes-- > 0) {
            output[idx++] = (uint8_t)(rand_num >> bytes * 8);
        }
    }
    return 0;
}

static int tls_example(int argc, char **argv)
{
    int ret = 1, len;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    mbedtls_net_context server_fd;
    uint32_t flags;
    unsigned char buf[1024];

    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold( DEBUG_LEVEL );
#endif

    /*
     * 0. Initialize the session data
     */
    mbedtls_net_init( &server_fd );
    mbedtls_ssl_init( &ssl );
    mbedtls_ssl_config_init( &conf );
    mbedtls_x509_crt_init( &cacert );

    /*
     * 0. Initialize certificates
     */
    mbedtls_printf( "  . Loading the CA root certificate ..." );
    fflush( stdout );

    ret = mbedtls_x509_crt_parse( &cacert, (const unsigned char *) globalsign_g2_ca_cert,
                          globalsign_g2_ca_cert_len );
    if( ret < 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n", -ret );
        goto exit;
    }

    mbedtls_printf( " ok (%d skipped)\n", ret );

    /*
     * 1. Start the connection
     */
    mbedtls_printf( "  . Connecting to tcp/%s/%s...", SERVER_NAME, SERVER_PORT );
    fflush( stdout );

    if( ( ret = mbedtls_net_connect( &server_fd, SERVER_NAME,
                                         SERVER_PORT, MBEDTLS_NET_PROTO_TCP ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_net_connect returned %d\n\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    /*
     * 2. Setup stuff
     */
    mbedtls_printf( "  . Setting up the SSL/TLS structure..." );
    fflush( stdout );

    if( ( ret = mbedtls_ssl_config_defaults( &conf,
                    MBEDTLS_SSL_IS_CLIENT,
                    MBEDTLS_SSL_TRANSPORT_STREAM,
                    MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    /* OPTIONAL is not optimal for security,
     * but makes interop easier in this simplified example */
    mbedtls_ssl_conf_authmode( &conf, MBEDTLS_SSL_VERIFY_OPTIONAL );
    mbedtls_ssl_conf_ca_chain( &conf, &cacert, NULL );
    mbedtls_ssl_conf_rng( &conf, tls_example_random, NULL );
    mbedtls_ssl_conf_dbg( &conf, tls_example_debug, stdout );

    if( ( ret = mbedtls_ssl_setup( &ssl, &conf ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
        goto exit;
    }

    if( ( ret = mbedtls_ssl_set_hostname( &ssl, SERVER_NAME ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret );
        goto exit;
    }

    mbedtls_ssl_set_bio( &ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL );

    /*
     * 4. Handshake
     */
    mbedtls_printf( "  . Performing the SSL/TLS handshake..." );
    fflush( stdout );

    while( ( ret = mbedtls_ssl_handshake( &ssl ) ) != 0 )
    {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
            mbedtls_printf( " failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret );
            goto exit;
        }
    }

    mbedtls_printf( " ok\n" );

    /*
     * 5. Verify the server certificate
     */
    mbedtls_printf( "  . Verifying peer X.509 certificate..." );

    /* In real life, we probably want to bail out when ret != 0 */
    if( ( flags = mbedtls_ssl_get_verify_result( &ssl ) ) != 0 )
    {
        char vrfy_buf[512];

        mbedtls_printf( " failed\n" );

        mbedtls_x509_crt_verify_info( vrfy_buf, sizeof( vrfy_buf ), "  ! ", flags );

        mbedtls_printf( "%s\n", vrfy_buf );
    }
    else
        mbedtls_printf( " ok\n" );

    /*
     * 3. Write the GET request
     */
    mbedtls_printf( "  > Write to server:" );
    fflush( stdout );

    len = sprintf( (char *) buf, GET_REQUEST );

    while( ( ret = mbedtls_ssl_write( &ssl, buf, len ) ) <= 0 )
    {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
            mbedtls_printf( " failed\n  ! mbedtls_ssl_write returned %d\n\n", ret );
            goto exit;
        }
    }

    len = ret;
    mbedtls_printf( " %d bytes written\n\n%s", len, (char *) buf );

    /*
     * 7. Read the HTTP response
     */
    mbedtls_printf( "  < Read from server:" );
    fflush( stdout );

    do
    {
        len = sizeof( buf ) - 1;
        memset( buf, 0, sizeof( buf ) );
        ret = mbedtls_ssl_read( &ssl, buf, len );

        if( ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE )
            continue;

        if( ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY )
            break;

        if( ret < 0 )
        {
            mbedtls_printf( "failed\n  ! mbedtls_ssl_read returned %d\n\n", ret );
            break;
        }

        if( ret == 0 )
        {
            mbedtls_printf( "\n\nEOF\n\n" );
            break;
        }

        len = ret;
        mbedtls_printf( " %d bytes read\n\n%s", len, (char *) buf );
    }
    while( 1 );

    mbedtls_ssl_close_notify( &ssl );

    exit_code = MBEDTLS_EXIT_SUCCESS;
    printf("tls_example test success!\n");

exit:

#ifdef MBEDTLS_ERROR_C
    if( exit_code != MBEDTLS_EXIT_SUCCESS )
    {
        char error_buf[100];
        mbedtls_strerror( ret, error_buf, 100 );
        mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf );
    }
#endif

    mbedtls_net_free( &server_fd );

    mbedtls_x509_crt_free( &cacert );
    mbedtls_ssl_free( &ssl );
    mbedtls_ssl_config_free( &conf );

    return( exit_code );
}

#if AOS_COMP_CLI
/* reg args: fun, cmd, description*/
ALIOS_CLI_CMD_REGISTER(tls_example, tls_example, tls client example)
#endif

//
//void main(void) {
//
//    tls_example(0,0);
//}



int main9(void)
{
  CURL *curl;
  CURLcode res;

  curl = curl_easy_init();
  if(curl) {

    /* Forcing HTTP/3 will make the connection fail if the server is not
       accessible over QUIC + HTTP/3 on the given host and port.
       Consider using CURLOPT_ALTSVC instead! */
    struct curl_blob stblob;
    stblob.data = globalsign_g2_ca_cert;
    stblob.len =  sizeof(globalsign_g2_ca_cert);
    stblob.flags = CURL_BLOB_COPY;

    curl_easy_setopt(curl, CURLOPT_URL, "https://www.baidu.com");

    curl_easy_setopt(curl, CURLOPT_CAPATH, "/home/freedom/curl-test");

   if(CURLE_OK == curl_easy_setopt(curl, CURLOPT_SSLCERT_BLOB, &stblob)) {
    printf("\r\n###: setup_ok!\r\n");
   }

   fflush(stdout);

   curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "PEM");

   curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_3);

    /* Perform the request, res will get the return code */
    res = curl_easy_perform(curl);
    /* Check for errors */
    if(res != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));

    /* always cleanup */
    curl_easy_cleanup(curl);
  }
  return 0;
}






















