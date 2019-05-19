/* based on the coap-server example in libcoap. */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <dirent.h>

#include <coap2/coap.h>

/* temporary storage for dynamic resource representations */
static int quit = 0;

static char *cert_file = NULL;    /* Combined certificate and private key in PEM */
static char *ca_file = NULL;      /* CA for cert_file - for cert checking in PEM */
static char *root_ca_file = NULL; /* List of trusted Root CAs in PEM */
static int require_peer_cert = 1; /* By default require peer cert */
#define MAX_KEY 64                /* Maximum length of a key (i.e., PSK) in bytes. */
static uint8_t key[MAX_KEY];
static ssize_t key_length = 0;
int key_defined = 0;
static const char *hint = "CoAP";
static int support_dynamic = 0;

#ifdef __GNUC__
#define UNUSED_PARAM __attribute__((unused))
#else /* not a GCC */
#define UNUSED_PARAM
#endif /* GCC */

/* SIGINT handler: set quit to 1 for graceful termination */
static void
handle_sigint(int signum UNUSED_PARAM)
{
    quit = 1;
}

#define INDEX "This is the CoAP.cloud frontend, based on libcoap (see https://libcoap.net)\n"

static void
hnd_get_index(coap_context_t *ctx UNUSED_PARAM,
              struct coap_resource_t *resource,
              coap_session_t *session,
              coap_pdu_t *request,
              coap_binary_t *token,
              coap_string_t *query UNUSED_PARAM,
              coap_pdu_t *response)
{

    coap_add_data_blocked_response(resource, session, request, response, token,
                                   COAP_MEDIATYPE_TEXT_PLAIN, 0x2ffff,
                                   strlen(INDEX),
                                   (const uint8_t *)INDEX);
}

static void
init_resources(coap_context_t *ctx)
{
    coap_resource_t *r;

    r = coap_resource_init(NULL, 0);
    coap_register_handler(r, COAP_REQUEST_GET, hnd_get_index);

    coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("0"), 0);
    coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"General Info\""), 0);
    coap_add_resource(ctx, r);
}

static coap_dtls_key_t *
verify_sni_callback(const char *sni, void *arg UNUSED_PARAM)
{
    static coap_dtls_key_t dtls_key;

    /* Just use the defined keys for now */
    memset(&dtls_key, 0, sizeof(dtls_key));
    dtls_key.key_type = COAP_PKI_KEY_PEM;
    dtls_key.key.pem.public_cert = cert_file;
    dtls_key.key.pem.private_key = cert_file;
    dtls_key.key.pem.ca_file = ca_file;
    if (sni[0])
    {
        coap_log(LOG_INFO, "SNI '%s' requested\n", sni);
    }
    else
    {
        coap_log(LOG_DEBUG, "SNI not requested\n");
    }
    return &dtls_key;
}

static int
verify_cn_callback(const char *cn,
                   const uint8_t *asn1_public_cert UNUSED_PARAM,
                   size_t asn1_length UNUSED_PARAM,
                   coap_session_t *session UNUSED_PARAM,
                   unsigned depth,
                   int validated UNUSED_PARAM,
                   void *arg UNUSED_PARAM)
{
    coap_log(LOG_INFO, "CN '%s' presented by client (%s)\n",
             cn, depth ? "CA" : "Certificate");
    return 1;
}

static void
fill_keystore(coap_context_t *ctx)
{
    if (cert_file)
    {
        coap_dtls_pki_t dtls_pki;
        memset(&dtls_pki, 0, sizeof(dtls_pki));
        dtls_pki.version = COAP_DTLS_PKI_SETUP_VERSION;
        if (ca_file)
        {
            /*
       * Add in additional certificate checking.
       * This list of enabled can be tuned for the specific
       * requirements - see 'man coap_encryption'.
       */
            dtls_pki.verify_peer_cert = 1;
            dtls_pki.require_peer_cert = require_peer_cert;
            dtls_pki.allow_self_signed = 1;
            dtls_pki.allow_expired_certs = 1;
            dtls_pki.cert_chain_validation = 1;
            dtls_pki.cert_chain_verify_depth = 2;
            dtls_pki.check_cert_revocation = 1;
            dtls_pki.allow_no_crl = 1;
            dtls_pki.allow_expired_crl = 1;
            dtls_pki.validate_cn_call_back = verify_cn_callback;
            dtls_pki.cn_call_back_arg = NULL;
            dtls_pki.validate_sni_call_back = verify_sni_callback;
            dtls_pki.sni_call_back_arg = NULL;
        }
        dtls_pki.pki_key.key_type = COAP_PKI_KEY_PEM;
        dtls_pki.pki_key.key.pem.public_cert = cert_file;
        dtls_pki.pki_key.key.pem.private_key = cert_file;
        dtls_pki.pki_key.key.pem.ca_file = ca_file;
        /* If general root CAs are defined */
        if (root_ca_file)
        {
            struct stat stbuf;
            if ((stat(root_ca_file, &stbuf) == 0) && S_ISDIR(stbuf.st_mode))
            {
                coap_context_set_pki_root_cas(ctx, NULL, root_ca_file);
            }
            else
            {
                coap_context_set_pki_root_cas(ctx, root_ca_file, NULL);
            }
        }
        if (key_defined)
            coap_context_set_psk(ctx, hint, key, key_length);
        coap_context_set_pki(ctx, &dtls_pki);
    }
    else if (key_defined)
    {
        coap_context_set_psk(ctx, hint, key, key_length);
    }
    else if (coap_dtls_is_supported() || coap_tls_is_supported())
    {
        coap_log(LOG_DEBUG,
                 "(D)TLS not enabled as neither -k or -c options specified\n");
    }
}

static coap_context_t *
get_context(const char *node, const char *port)
{
    coap_context_t *ctx = NULL;
    int s;
    struct addrinfo hints;
    struct addrinfo *result, *rp;

    ctx = coap_new_context(NULL);
    if (!ctx)
    {
        return NULL;
    }
    /* Need PSK set up before we set up (D)TLS endpoints */
    fill_keystore(ctx);

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_DGRAM; /* Coap uses UDP */
    hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;

    s = getaddrinfo(node, port, &hints, &result);
    if (s != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        coap_free_context(ctx);
        return NULL;
    }

    /* iterate through results until success */
    for (rp = result; rp != NULL; rp = rp->ai_next)
    {
        coap_address_t addr, addrs;
        coap_endpoint_t *ep_udp = NULL, *ep_dtls = NULL, *ep_tcp = NULL, *ep_tls = NULL;

        if (rp->ai_addrlen <= sizeof(addr.addr))
        {
            coap_address_init(&addr);
            addr.size = rp->ai_addrlen;
            memcpy(&addr.addr, rp->ai_addr, rp->ai_addrlen);
            addrs = addr;
            if (addr.addr.sa.sa_family == AF_INET)
            {
                uint16_t temp = ntohs(addr.addr.sin.sin_port) + 1;
                addrs.addr.sin.sin_port = htons(temp);
            }
            else if (addr.addr.sa.sa_family == AF_INET6)
            {
                uint16_t temp = ntohs(addr.addr.sin6.sin6_port) + 1;
                addrs.addr.sin6.sin6_port = htons(temp);
            }
            else
            {
                goto finish;
            }

            ep_udp = coap_new_endpoint(ctx, &addr, COAP_PROTO_UDP);
            if (ep_udp)
            {
                if (coap_dtls_is_supported() && (key_defined || cert_file))
                {
                    ep_dtls = coap_new_endpoint(ctx, &addrs, COAP_PROTO_DTLS);
                    if (!ep_dtls)
                        coap_log(LOG_CRIT, "cannot create DTLS endpoint\n");
                }
            }
            else
            {
                coap_log(LOG_CRIT, "cannot create UDP endpoint\n");
                continue;
            }
            ep_tcp = coap_new_endpoint(ctx, &addr, COAP_PROTO_TCP);
            if (ep_tcp)
            {
                if (coap_tls_is_supported() && (key_defined || cert_file))
                {
                    ep_tls = coap_new_endpoint(ctx, &addrs, COAP_PROTO_TLS);
                    if (!ep_tls)
                        coap_log(LOG_CRIT, "cannot create TLS endpoint\n");
                }
            }
            else
            {
                coap_log(LOG_CRIT, "cannot create TCP endpoint\n");
            }
            if (ep_udp)
                goto finish;
        }
    }

    fprintf(stderr, "no context available for interface '%s'\n", node);

finish:
    freeaddrinfo(result);
    return ctx;
}

int main(int argc, char **argv)
{
    coap_context_t *ctx;
    char addr_str[NI_MAXHOST] = "::";
    char port_str[NI_MAXSERV] = "5683";
    coap_log_t log_level = LOG_DEBUG;
    unsigned wait_ms;
#ifndef _WIN32
    struct sigaction sa;
#endif

    coap_startup();
    coap_dtls_set_log_level(log_level);
    coap_set_log_level(log_level);

    ctx = get_context(addr_str, port_str);
    if (!ctx)
        return -1;

    init_resources(ctx);

    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = handle_sigint;
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    wait_ms = COAP_RESOURCE_CHECK_TIME * 1000;

    while (!quit)
    {
        int result = coap_run_once(ctx, wait_ms);
        /* code */
    }

    coap_free_context(ctx);
    coap_cleanup();

    return 0;
}