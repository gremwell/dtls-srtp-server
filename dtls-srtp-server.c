/*
 The projects used to copy-paste code
 - https://gitlab.com/gnutls/gnutls/blob/master/tests/mini-dtls-srtp.c
 - https://github.com/persmule/libdtlssrtp/blob/master/example.c
 -
 https://www.gnutls.org/manual/html_node/DTLS-echo-server-with-X_002e509-authentication.html#DTLS-echo-server-with-X_002e509-authentication
*/

#include <stdio.h>

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <unistd.h>

#include <gnutls/dtls.h>
#include <gnutls/gnutls.h>

/*
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 5550018979492260217 (0x4d05a0db494fe979)
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: CN = WebRTC
        Validity
            Not Before: Mar 11 15:14:00 2020 GMT
            Not After : Mar 11 15:14:00 2030 GMT
        Subject: CN = WebRTC
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:6d:49:e5:56:72:f8:f3:13:34:94:ae:a2:0e:11:
                    dc:a9:a1:6e:62:1e:8c:e6:59:80:f3:6d:c6:42:5c:
                    22:e6:c9:20:83:ba:f2:49:1d:18:ad:38:a6:5f:d1:
                    7a:2b:d9:03:08:9b:bf:ef:39:96:94:f8:b2:6f:fd:
                    44:15:61:2d:93
                ASN1 OID: prime256v1
                NIST CURVE: P-256
    Signature Algorithm: ecdsa-with-SHA256
         30:44:02:20:1e:5d:99:c5:9b:c9:9e:b1:ee:bb:64:fd:30:86:
         c2:70:be:72:61:8e:fe:6d:bf:23:8d:da:87:91:e8:7e:c9:ad:
         02:20:77:f6:27:ce:ec:87:8e:e6:28:ab:df:e7:13:70:12:d9:
         8b:31:7c:84:3e:a5:37:88:f5:32:fd:1c:52:55:3f:7a
 */
static char server_cert_pem[] = "-----BEGIN CERTIFICATE-----\n"
                                "MIIBFDCBvKADAgECAghNBaDbSU/peTAKBggqhkjOPQQDAjARMQ8wDQYDVQQDEwZX\n"
                                "ZWJSVEMwHhcNMjAwMzExMTUxNDAwWhcNMzAwMzExMTUxNDAwWjARMQ8wDQYDVQQD\n"
                                "EwZXZWJSVEMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARtSeVWcvjzEzSUrqIO\n"
                                "EdypoW5iHozmWYDzbcZCXCLmySCDuvJJHRitOKZf0Xor2QMIm7/vOZaU+LJv/UQV\n"
                                "YS2TMAoGCCqGSM49BAMCA0cAMEQCIB5dmcWbyZ6x7rtk/TCGwnC+cmGO/m2/I43a\n"
                                "h5HofsmtAiB39ifO7IeO5iir3+cTcBLZizF8hD6lN4j1Mv0cUlU/eg==\n"
                                "-----END CERTIFICATE-----\n";

const gnutls_datum_t server_cert
        = { (unsigned char *)server_cert_pem, sizeof(server_cert_pem) - 1 };

/* it is essential that private key uses prime256v1 curve! */
static char server_key_pem[] = "-----BEGIN EC PRIVATE KEY-----\n"
                               "MHgCAQEEIQDn1XFX7QxTKXl2ekfSrEARsq+06ySEeeOB+N0igwcNLqAKBggqhkjO\n"
                               "PQMBB6FEA0IABG1J5VZy+PMTNJSuog4R3KmhbmIejOZZgPNtxkJcIubJIIO68kkd\n"
                               "GK04pl/ReivZAwibv+85lpT4sm/9RBVhLZM=\n"
                               "-----END EC PRIVATE KEY-----\n";

const gnutls_datum_t server_key = { (unsigned char *)server_key_pem, sizeof(server_key_pem) - 1 };

static void server_log_func(int level, const char *str)
{
        fprintf(stderr, "server|<%d>| %s", level, str);
}

#define MAX_KEY_MATERIAL 64 * 4

#define MAX_BUFFER 1024

#define LOOP_CHECK(rval, cmd)                                                                      \
        do {                                                                                       \
                rval = cmd;                                                                        \
        } while (rval == GNUTLS_E_AGAIN || rval == GNUTLS_E_INTERRUPTED)

typedef struct
{
        gnutls_session_t session;
        int fd;
        struct sockaddr *cli_addr;
        socklen_t cli_addr_size;
} priv_data_st;

static int pull_timeout_func(gnutls_transport_ptr_t ptr, unsigned int ms);
static ssize_t push_func(gnutls_transport_ptr_t p, const void *data, long unsigned int size);
static ssize_t pull_func(gnutls_transport_ptr_t p, void *data, long unsigned int size);
static const char *human_addr(const struct sockaddr *sa, socklen_t salen, char *buf, ssize_t buflen);
static int wait_for_connection(int fd);

static gnutls_priority_t priority_cache;

static void server()
{
        int ret;
        gnutls_session_t session;
        uint8_t km[MAX_KEY_MATERIAL];
        char buf[2 * MAX_KEY_MATERIAL];
        gnutls_datum_t srtp_cli_key, srtp_cli_salt, srtp_server_key, srtp_server_salt;
        gnutls_certificate_credentials_t x509_cred;
        gnutls_datum_t skey;

        int listen_sd;
        int sock;
        struct sockaddr_in sa_serv;
        struct sockaddr_in cli_addr;
        socklen_t cli_addr_size;
        char buffer[MAX_BUFFER];
        gnutls_datum_t cookie_key;
        gnutls_dtls_prestate_st prestate;
        priv_data_st priv;
        unsigned char sequence[8];

        /* this must be called once in the program */
        gnutls_global_init();

        gnutls_global_set_log_function(server_log_func);
        gnutls_global_set_log_level(4711);

        assert(gnutls_certificate_allocate_credentials(&x509_cred) >= 0);
        assert(gnutls_certificate_set_x509_key_mem(
                       x509_cred, &server_cert, &server_key, GNUTLS_X509_FMT_PEM)
                >= 0);

        gnutls_init(&session, GNUTLS_SERVER | GNUTLS_DATAGRAM);
        gnutls_handshake_set_timeout(session, 10 * 60 * 1000);
        gnutls_heartbeat_enable(session, GNUTLS_HB_PEER_ALLOWED_TO_SEND);
        gnutls_dtls_set_mtu(session, 1500);
        assert(gnutls_session_ticket_key_generate(&skey) >= 0);
        assert(gnutls_session_ticket_enable_server(session, &skey) >= 0);

        gnutls_priority_set_direct(
                session, "NORMAL:-VERS-ALL:+VERS-DTLS1.2:-KX-ALL:+ECDHE-ECDSA", NULL);

        ret = gnutls_srtp_set_profile_direct(session, "SRTP_AES128_CM_HMAC_SHA1_80", NULL);
        if (ret < 0) {
                gnutls_perror(ret);
                exit(1);
        }

        gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, x509_cred);

        gnutls_certificate_server_set_request(session, GNUTLS_CERT_REQUEST);

        /* Socket operations */
        listen_sd = socket(AF_INET, SOCK_DGRAM, 0);

        memset(&sa_serv, '\0', sizeof(sa_serv));
        sa_serv.sin_family = AF_INET;
        sa_serv.sin_addr.s_addr = INADDR_ANY;
        sa_serv.sin_port = htons(8443);

        { /* DTLS requires the IP don't fragment (DF) bit to be set */
#if defined(IP_DONTFRAG)
                int optval = 1;
                setsockopt(
                        listen_sd, IPPROTO_IP, IP_DONTFRAG, (const void *)&optval, sizeof(optval));
#elif defined(IP_MTU_DISCOVER)
                int optval = IP_PMTUDISC_DO;
                setsockopt(listen_sd, IPPROTO_IP, IP_MTU_DISCOVER, (const void *)&optval,
                        sizeof(optval));
#endif
        }

        bind(listen_sd, (struct sockaddr *)&sa_serv, sizeof(sa_serv));

        for (;;) {
                sock = wait_for_connection(listen_sd);
                if (sock < 0)
                        continue;

                cli_addr_size = sizeof(cli_addr);
                ret = recvfrom(sock, buffer, sizeof(buffer), MSG_PEEK, (struct sockaddr *)&cli_addr,
                        &cli_addr_size);
                if (ret > 0) {
#if 0
            memset(&prestate, 0, sizeof(prestate));
            ret = gnutls_dtls_cookie_verify(&cookie_key,
                                            &cli_addr,
                                            sizeof(cli_addr),
                                            buffer, ret,
                                            &prestate);
#endif

                        printf("Accepted connection from %s\n",
                                human_addr((struct sockaddr *)&cli_addr, sizeof(cli_addr), buffer,
                                        sizeof(buffer)));
                } else {
                        continue;
                }

                // gnutls_dtls_prestate_set(session, &prestate);

                priv.session = session;
                priv.fd = sock;
                priv.cli_addr = (struct sockaddr *)&cli_addr;
                priv.cli_addr_size = sizeof(cli_addr);

                gnutls_transport_set_ptr(session, &priv);
                gnutls_transport_set_push_function(session, push_func);
                gnutls_transport_set_pull_function(session, pull_func);
                gnutls_transport_set_pull_timeout_function(session, pull_timeout_func);

                LOOP_CHECK(ret, gnutls_handshake(session));

                /* Note that DTLS may also receive GNUTLS_E_LARGE_PACKET.
		 * In that case the MTU should be adjusted. */
                if (ret < 0) {
                        fprintf(stderr, "Error in handshake(): %s\n", gnutls_strerror(ret));
                        gnutls_deinit(session);
                        continue;
                }

                printf("- Handshake was completed\n");
                printf("server: TLS version is: %s\n",
                        gnutls_protocol_get_name(gnutls_protocol_get_version(session)));

                ret = gnutls_srtp_get_keys(session, km, sizeof(km), &srtp_cli_key, &srtp_cli_salt,
                        &srtp_server_key, &srtp_server_salt);
                if (ret < 0) {
                        gnutls_perror(ret);
                        exit(1);
                }

                size_t size = sizeof(buf);
                gnutls_hex_encode(&srtp_cli_key, buf, &size);
                printf("Client key: %s\n", buf);

                size = sizeof(buf);
                gnutls_hex_encode(&srtp_cli_salt, buf, &size);
                printf("Client salt: %s\n", buf);

                size = sizeof(buf);
                gnutls_hex_encode(&srtp_server_key, buf, &size);
                printf("Server key: %s\n", buf);

                size = sizeof(buf);
                gnutls_hex_encode(&srtp_server_salt, buf, &size);
                printf("Server salt: %s\n", buf);

                for (;;) {
                        LOOP_CHECK(
                                ret, gnutls_record_recv_seq(session, buffer, MAX_BUFFER, sequence));

                        if (ret < 0 && gnutls_error_is_fatal(ret) == 0) {
                                fprintf(stderr, "*** Warning: %s\n", gnutls_strerror(ret));
                                continue;
                        } else if (ret < 0) {
                                fprintf(stderr, "Error in recv(): %s\n", gnutls_strerror(ret));
                                break;
                        }

                        if (ret == 0) {
                                printf("EOF\n\n");
                                break;
                        }

                        buffer[ret] = 0;
                        printf("received[%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x]: "
                               "%s\n",
                                sequence[0], sequence[1], sequence[2], sequence[3], sequence[4],
                                sequence[5], sequence[6], sequence[7], buffer);

                        /* reply back */
                        LOOP_CHECK(ret, gnutls_record_send(session, buffer, ret));
                        if (ret < 0) {
                                fprintf(stderr, "Error in send(): %s\n", gnutls_strerror(ret));
                                break;
                        }
                }

                LOOP_CHECK(ret, gnutls_bye(session, GNUTLS_SHUT_WR));
                gnutls_deinit(session);
        }
        close(listen_sd);

        gnutls_certificate_free_credentials(x509_cred);
        gnutls_priority_deinit(priority_cache);

        gnutls_global_deinit();

        printf("server: finished\n");
}

int main()
{
        server();

        return 0;
}

static int wait_for_connection(int fd)
{
        fd_set rd, wr;
        int n;

        FD_ZERO(&rd);
        FD_ZERO(&wr);

        FD_SET(fd, &rd);

        /* waiting part */
        n = select(fd + 1, &rd, &wr, NULL, NULL);
        if (n == -1 && errno == EINTR)
                return -1;
        if (n < 0) {
                perror("select()");
                exit(1);
        }

        return fd;
}

static const char *human_addr(const struct sockaddr *sa, socklen_t salen, char *buf, ssize_t buflen)
{
        const char *save_buf = buf;
        ssize_t l;

        if (!buf || !buflen)
                return NULL;

        *buf = '\0';

        switch (sa->sa_family) {
#if HAVE_IPV6
        case AF_INET6:
                snprintf(buf, buflen, "IPv6 ");
                break;
#endif

        case AF_INET:
                snprintf(buf, buflen, "IPv4 ");
                break;
        }

        l = strlen(buf);
        buf += l;
        buflen -= l;

        if (getnameinfo(sa, salen, buf, buflen, NULL, 0, NI_NUMERICHOST) != 0)
                return NULL;

        l = strlen(buf);
        buf += l;
        buflen -= l;

        strncat(buf, " port ", buflen);

        l = strlen(buf);
        buf += l;
        buflen -= l;

        if (getnameinfo(sa, salen, NULL, 0, buf, buflen, NI_NUMERICSERV) != 0)
                return NULL;

        return save_buf;
}

static ssize_t push_func(gnutls_transport_ptr_t p, const void *data, long unsigned int size)
{
        priv_data_st *priv = p;

        return sendto(priv->fd, data, size, 0, priv->cli_addr, priv->cli_addr_size);
}

static ssize_t pull_func(gnutls_transport_ptr_t p, void *data, long unsigned int size)
{
        priv_data_st *priv = p;
        struct sockaddr_in cli_addr;
        socklen_t cli_addr_size;
        char buffer[64];
        int ret;

        cli_addr_size = sizeof(cli_addr);
        ret = recvfrom(priv->fd, data, size, 0, (struct sockaddr *)&cli_addr, &cli_addr_size);
        if (ret == -1)
                return ret;

        if (cli_addr_size == priv->cli_addr_size
                && memcmp(&cli_addr, priv->cli_addr, sizeof(cli_addr)) == 0)
                return ret;

        printf("Denied connection from %s\n",
                human_addr((struct sockaddr *)&cli_addr, sizeof(cli_addr), buffer, sizeof(buffer)));

        gnutls_transport_set_errno(priv->session, EAGAIN);
        return -1;
}

/* Wait for data to be received within a timeout period in milliseconds
 */
static int pull_timeout_func(gnutls_transport_ptr_t ptr, unsigned int ms)
{
        fd_set rfds;
        struct timeval tv;
        priv_data_st *priv = ptr;
        struct sockaddr_in cli_addr;
        socklen_t cli_addr_size;
        int ret;
        char c;

        FD_ZERO(&rfds);
        FD_SET(priv->fd, &rfds);

        tv.tv_sec = ms / 1000;
        tv.tv_usec = (ms % 1000) * 1000;

        ret = select(priv->fd + 1, &rfds, NULL, NULL, &tv);

        if (ret <= 0)
                return ret;

        /* only report ok if the next message is from the peer we expect
	 * from
	 */
        cli_addr_size = sizeof(cli_addr);
        ret = recvfrom(priv->fd, &c, 1, MSG_PEEK, (struct sockaddr *)&cli_addr, &cli_addr_size);
        if (ret > 0) {
                if (cli_addr_size == priv->cli_addr_size
                        && memcmp(&cli_addr, priv->cli_addr, sizeof(cli_addr)) == 0)
                        return 1;
        }

        return 0;
}
