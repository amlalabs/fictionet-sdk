/* An ngtcp2 QUIC endpoint with no sockets and no clock.
 *
 * The test supplies every datagram and every timestamp, so the peer runs on
 * the same virtual network and time as the SDK. A server answers
 * hq-interop requests ("GET /path\r\n") with the files the test registered;
 * a client fetches paths over hq-interop or, through nghttp3, HTTP/3. TLS is
 * the system OpenSSL through ngtcp2's own crypto backend. */

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>
#include <nghttp3/nghttp3.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { APP_HQ = 0, APP_H3 = 1 };

#define MAX_VERSIONS 4
#define MAX_REQUESTS 64

typedef struct {
  uint8_t *data;
  size_t len, cap;
} buffer;

static int append(buffer *b, const uint8_t *data, size_t len) {
  if (b->len + len > b->cap) {
    size_t cap = b->cap ? b->cap : 256;
    while (cap < b->len + len)
      cap *= 2;
    uint8_t *grown = realloc(b->data, cap);
    if (!grown)
      return -1;
    b->data = grown;
    b->cap = cap;
  }
  if (len)
    memcpy(b->data + b->len, data, len);
  b->len += len;
  return 0;
}

/* One hq-interop stream: the bytes to send and the bytes received */
typedef struct stream {
  int64_t id;
  buffer out;
  size_t sent;
  int fin, fin_sent, blocked;
  buffer in;
  int request; /* the client's request index, or -1 */
  struct stream *next;
} stream;

typedef struct file {
  char *path;
  buffer data;
  struct file *next;
} file;

typedef struct {
  char path[256];
  int64_t stream;
  int opened, done, status;
  buffer body;
} request;

typedef struct fn_peer {
  int server, app, retry;
  SSL_CTX *ctx;
  SSL *ssl;
  ngtcp2_crypto_ossl_ctx *ossl;
  ngtcp2_crypto_conn_ref ref;
  ngtcp2_conn *conn;
  struct sockaddr_in local, remote;
  uint64_t rng;
  uint32_t versions[MAX_VERSIONS];
  size_t nversions;
  uint32_t chosen;
  uint8_t secret[32];
  uint8_t pending[1500];
  size_t pending_len;
  int sent; /* the connection has written a datagram */
  ngtcp2_cid first_dcid; /* of the Initial the server connection came from */
  int closed, failed;
  ngtcp2_ccerr peer_close;
  int peer_closed;
  stream *streams;
  file *files;
  request requests[MAX_REQUESTS];
  size_t nrequests;
  nghttp3_conn *h3;
} fn_peer;

static uint64_t next_random(fn_peer *p) {
  /* splitmix64: deterministic from the test's seed */
  uint64_t z = (p->rng += 0x9e3779b97f4a7c15ULL);
  z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
  z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
  return z ^ (z >> 31);
}

static void fill(fn_peer *p, uint8_t *dest, size_t len) {
  for (size_t i = 0; i < len; i++)
    dest[i] = (uint8_t)next_random(p);
}

static void rand_cb(uint8_t *dest, size_t len, const ngtcp2_rand_ctx *ctx) {
  fill(ctx->native_handle, dest, len);
}

static int new_cid(ngtcp2_conn *conn, ngtcp2_cid *cid,
                   ngtcp2_stateless_reset_token *token, size_t cidlen,
                   void *user_data) {
  (void)conn;
  fn_peer *p = user_data;
  fill(p, cid->data, cidlen);
  cid->datalen = cidlen;
  fill(p, token->data, sizeof(token->data));
  return 0;
}

static ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *ref) {
  return ((fn_peer *)ref->user_data)->conn;
}

static ngtcp2_path path_of(fn_peer *p) {
  ngtcp2_path path = {
      .local = {(ngtcp2_sockaddr *)&p->local, sizeof(p->local)},
      .remote = {(ngtcp2_sockaddr *)&p->remote, sizeof(p->remote)},
  };
  return path;
}

static stream *find_stream(fn_peer *p, int64_t id, int create) {
  for (stream *s = p->streams; s; s = s->next)
    if (s->id == id)
      return s;
  if (!create)
    return NULL;
  stream *s = calloc(1, sizeof(*s));
  if (!s)
    return NULL;
  s->id = id;
  s->request = -1;
  s->next = p->streams;
  p->streams = s;
  return s;
}

/* A server answers "GET /path\r\n" with the registered file and FIN */
static int respond(fn_peer *p, stream *s) {
  const char *in = (const char *)s->in.data;
  size_t len = s->in.len;
  if (len < 5 || memcmp(in, "GET /", 5) != 0)
    return -1;
  size_t end = 4;
  while (end < len && in[end] != '\r' && in[end] != '\n' && in[end] != ' ')
    end++;
  for (file *f = p->files; f; f = f->next) {
    if (strlen(f->path) == end - 4 && memcmp(f->path, in + 4, end - 4) == 0) {
      if (append(&s->out, f->data.data, f->data.len))
        return -1;
      s->fin = 1;
      return 0;
    }
  }
  s->fin = 1; /* an unknown path gets an empty response */
  return 0;
}

static int consumed(fn_peer *p, int64_t id, size_t n) {
  ngtcp2_conn_extend_max_stream_offset(p->conn, id, n);
  ngtcp2_conn_extend_max_offset(p->conn, n);
  return 0;
}

static int recv_stream_data(ngtcp2_conn *conn, uint32_t flags, int64_t id,
                            uint64_t offset, const uint8_t *data, size_t len,
                            void *user_data, void *stream_user_data) {
  (void)conn;
  (void)offset;
  (void)stream_user_data;
  fn_peer *p = user_data;
  int fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0;
  if (p->app == APP_H3) {
    stream *s = find_stream(p, id, 1);
    if (!s || append(&s->in, data, len))
      return NGTCP2_ERR_CALLBACK_FAILURE;
    nghttp3_ssize n = nghttp3_conn_read_stream(p->h3, id, data, len, fin);
    if (n < 0) {
      fprintf(stderr, "nghttp3 stream %lld: %s (%ld)\n", (long long)id,
              nghttp3_strerror((int)n), (long)n);
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    return consumed(p, id, (size_t)n);
  }
  stream *s = find_stream(p, id, 1);
  if (!s || append(&s->in, data, len))
    return NGTCP2_ERR_CALLBACK_FAILURE;
  consumed(p, id, len);
  if (fin) {
    if (p->server) {
      if (respond(p, s))
        return NGTCP2_ERR_CALLBACK_FAILURE;
    } else if (s->request >= 0) {
      request *r = &p->requests[s->request];
      if (append(&r->body, s->in.data, s->in.len))
        return NGTCP2_ERR_CALLBACK_FAILURE;
      r->done = 1;
    }
  }
  return 0;
}

static int acked(ngtcp2_conn *conn, int64_t id, uint64_t offset, uint64_t len,
                 void *user_data, void *stream_user_data) {
  (void)conn;
  (void)offset;
  (void)stream_user_data;
  fn_peer *p = user_data;
  if (p->app == APP_H3) {
    int rv = nghttp3_conn_add_ack_offset(p->h3, id, len);
    if (rv) {
      fprintf(stderr, "nghttp3 ack %lld: %s\n", (long long)id, nghttp3_strerror(rv));
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }
  }
  return 0;
}

static int stream_close(ngtcp2_conn *conn, uint32_t flags, int64_t id,
                        uint64_t code, void *user_data,
                        void *stream_user_data) {
  (void)conn;
  (void)stream_user_data;
  fn_peer *p = user_data;
  if (p->app != APP_H3)
    return 0;
  if (!(flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET))
    code = NGHTTP3_H3_NO_ERROR;
  int rv = nghttp3_conn_close_stream(p->h3, id, code);
  if (rv && rv != NGHTTP3_ERR_STREAM_NOT_FOUND) {
    fprintf(stderr, "nghttp3 close %lld code %llu flags %u: %s\n", (long long)id,
            (unsigned long long)code, flags, nghttp3_strerror(rv));
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

static int extend_stream(ngtcp2_conn *conn, int64_t id, uint64_t max,
                         void *user_data, void *stream_user_data) {
  (void)conn;
  (void)max;
  (void)stream_user_data;
  fn_peer *p = user_data;
  if (p->app == APP_H3) {
    int rv = nghttp3_conn_unblock_stream(p->h3, id);
    if (rv) {
      fprintf(stderr, "nghttp3 unblock %lld: %s\n", (long long)id, nghttp3_strerror(rv));
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    return 0;
  }
  stream *s = find_stream(p, id, 0);
  if (s)
    s->blocked = 0;
  return 0;
}

/* HTTP/3 */

static int h3_recv_data(nghttp3_conn *h3, int64_t id, const uint8_t *data,
                        size_t len, void *user_data, void *stream_user_data) {
  (void)h3;
  fn_peer *p = user_data;
  request *r = stream_user_data;
  if (!r || append(&r->body, data, len))
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  consumed(p, id, len);
  return 0;
}

static int h3_deferred(nghttp3_conn *h3, int64_t id, size_t n, void *user_data,
                       void *stream_user_data) {
  (void)h3;
  (void)stream_user_data;
  return consumed(user_data, id, n);
}

static int h3_header(nghttp3_conn *h3, int64_t id, int32_t token,
                     nghttp3_rcbuf *name, nghttp3_rcbuf *value, uint8_t flags,
                     void *user_data, void *stream_user_data) {
  (void)h3;
  (void)id;
  (void)name;
  (void)flags;
  (void)user_data;
  request *r = stream_user_data;
  if (r && token == NGHTTP3_QPACK_TOKEN__STATUS) {
    nghttp3_vec v = nghttp3_rcbuf_get_buf(value);
    int status = 0;
    for (size_t i = 0; i < v.len; i++)
      status = status * 10 + (v.base[i] - '0');
    r->status = status;
  }
  return 0;
}

static int h3_end_stream(nghttp3_conn *h3, int64_t id, void *user_data,
                         void *stream_user_data) {
  (void)h3;
  (void)id;
  (void)user_data;
  request *r = stream_user_data;
  if (r)
    r->done = 1;
  return 0;
}

static int h3_start(fn_peer *p) {
  nghttp3_callbacks callbacks = {
      .recv_data = h3_recv_data,
      .deferred_consume = h3_deferred,
      .recv_header = h3_header,
      .end_stream = h3_end_stream,
  };
  nghttp3_settings settings;
  nghttp3_settings_default(&settings);
  settings.qpack_max_dtable_capacity = 4096;
  settings.qpack_blocked_streams = 16;
  if (nghttp3_conn_client_new(&p->h3, &callbacks, &settings,
                              nghttp3_mem_default(), p))
    return -1;
  int64_t control, encoder, decoder;
  if (ngtcp2_conn_open_uni_stream(p->conn, &control, NULL) ||
      nghttp3_conn_bind_control_stream(p->h3, control) ||
      ngtcp2_conn_open_uni_stream(p->conn, &encoder, NULL) ||
      ngtcp2_conn_open_uni_stream(p->conn, &decoder, NULL) ||
      nghttp3_conn_bind_qpack_streams(p->h3, encoder, decoder))
    return -1;
  return 0;
}

/* Open a stream for each request the stream limit allows */
static int open_requests(fn_peer *p) {
  if (p->server || !ngtcp2_conn_get_handshake_completed(p->conn))
    return 0;
  if (p->app == APP_H3 && !p->h3 && h3_start(p))
    return -1;
  for (size_t i = 0; i < p->nrequests; i++) {
    request *r = &p->requests[i];
    if (r->opened)
      continue;
    int64_t id;
    int rv = ngtcp2_conn_open_bidi_stream(p->conn, &id, NULL);
    if (rv == NGTCP2_ERR_STREAM_ID_BLOCKED)
      return 0;
    if (rv)
      return -1;
    r->opened = 1;
    r->stream = id;
    if (p->app == APP_H3) {
      nghttp3_nv headers[11];
      const char *names[] = {":method", ":scheme", ":authority", ":path",
                             "accept", "accept-encoding", "user-agent",
                             "accept-language", "sec-fetch-dest",
                             "sec-fetch-mode", "sec-fetch-site"};
      const char *values[] = {"GET", "https", "shop.example.test", r->path,
                              "*/*", "gzip, deflate, br",
                              "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                              "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                              "en-US,en;q=0.9", "script", "no-cors", "same-origin"};
      for (int h = 0; h < 11; h++)
        headers[h] = (nghttp3_nv){(uint8_t *)names[h], (uint8_t *)values[h],
                                  strlen(names[h]), strlen(values[h]),
                                  NGHTTP3_NV_FLAG_NONE};
      if (nghttp3_conn_submit_request(p->h3, id, headers, 11, NULL, r))
        return -1;
    } else {
      stream *s = find_stream(p, id, 1);
      if (!s)
        return -1;
      s->request = (int)i;
      if (append(&s->out, (const uint8_t *)"GET ", 4) ||
          append(&s->out, (const uint8_t *)r->path, strlen(r->path)) ||
          append(&s->out, (const uint8_t *)"\r\n", 2))
        return -1;
      s->fin = 1;
    }
  }
  return 0;
}

static int handshake_completed(ngtcp2_conn *conn, void *user_data) {
  (void)conn;
  int rv = open_requests(user_data);
  if (rv) fprintf(stderr, "open requests at handshake: %d\n", rv);
  return rv ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}

static int more_streams(ngtcp2_conn *conn, uint64_t max, void *user_data) {
  (void)conn;
  (void)max;
  int rv = open_requests(user_data);
  if (rv) fprintf(stderr, "open requests at stream credit: %d\n", rv);
  return rv ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}

static ngtcp2_callbacks callbacks(int server) {
  ngtcp2_callbacks cb = {
      .recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
      .handshake_completed = handshake_completed,
      .encrypt = ngtcp2_crypto_encrypt_cb,
      .decrypt = ngtcp2_crypto_decrypt_cb,
      .hp_mask = ngtcp2_crypto_hp_mask_cb,
      .recv_stream_data = recv_stream_data,
      .acked_stream_data_offset = acked,
      .stream_close = stream_close,
      .extend_max_local_streams_bidi = more_streams,
      .rand = rand_cb,
      .update_key = ngtcp2_crypto_update_key_cb,
      .extend_max_stream_data = extend_stream,
      .delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
      .delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
      .version_negotiation = ngtcp2_crypto_version_negotiation_cb,
      .get_new_connection_id2 = new_cid,
      .get_path_challenge_data2 = ngtcp2_crypto_get_path_challenge_data2_cb,
  };
  if (server)
    cb.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
  else {
    cb.client_initial = ngtcp2_crypto_client_initial_cb;
    cb.recv_retry = ngtcp2_crypto_recv_retry_cb;
  }
  return cb;
}

static void defaults(fn_peer *p, ngtcp2_settings *settings,
                     ngtcp2_transport_params *params, uint64_t now) {
  ngtcp2_settings_default(settings);
  settings->initial_ts = now;
  settings->rand_ctx.native_handle = p;
  settings->preferred_versions = p->versions;
  settings->preferred_versionslen = p->nversions;
  /* A client otherwise offers only its chosen version */
  settings->available_versions = p->versions;
  settings->available_versionslen = p->nversions;
  settings->handshake_timeout = UINT64_MAX;
  ngtcp2_transport_params_default(params);
  params->initial_max_streams_bidi = 100;
  params->initial_max_streams_uni = 3;
  params->initial_max_stream_data_bidi_local = 1 << 20;
  params->initial_max_stream_data_bidi_remote = 1 << 20;
  params->initial_max_stream_data_uni = 1 << 20;
  params->initial_max_data = 4 << 20;
  params->max_idle_timeout = 60 * NGTCP2_SECONDS;
}

static void addresses(fn_peer *p) {
  struct sockaddr_in server = {.sin_family = AF_INET,
                               .sin_port = htons(4433),
                               .sin_addr.s_addr = htonl(0x7f000001)};
  struct sockaddr_in client = server;
  client.sin_port = htons(4444);
  p->local = p->server ? server : client;
  p->remote = p->server ? client : server;
}

static fn_peer *peer_new(int server, int app, const uint32_t *versions,
                         size_t nversions, uint64_t seed) {
  static int initialized;
  if (!initialized) {
    if (ngtcp2_crypto_ossl_init())
      return NULL;
    initialized = 1;
  }
  if (nversions == 0 || nversions > MAX_VERSIONS)
    return NULL;
  fn_peer *p = calloc(1, sizeof(*p));
  if (!p)
    return NULL;
  p->server = server;
  p->app = app;
  p->rng = seed;
  memcpy(p->versions, versions, nversions * sizeof(*versions));
  p->nversions = nversions;
  p->ref.get_conn = get_conn;
  p->ref.user_data = p;
  addresses(p);
  fill(p, p->secret, sizeof(p->secret));
  return p;
}

static int start_tls(fn_peer *p) {
  p->ssl = SSL_new(p->ctx);
  if (!p->ssl)
    return -1;
  if ((p->server ? ngtcp2_crypto_ossl_configure_server_session(p->ssl)
                 : ngtcp2_crypto_ossl_configure_client_session(p->ssl)))
    return -1;
  SSL_set_app_data(p->ssl, &p->ref);
  if (p->server)
    SSL_set_accept_state(p->ssl);
  else {
    SSL_set_connect_state(p->ssl);
    static const uint8_t hq[] = "\x0ahq-interop", h3[] = "\x02h3";
    if (p->app == APP_H3 ? SSL_set_alpn_protos(p->ssl, h3, 3)
                         : SSL_set_alpn_protos(p->ssl, hq, 11))
      return -1;
    if (!SSL_set_tlsext_host_name(p->ssl, "localhost") ||
        !SSL_set1_host(p->ssl, "localhost"))
      return -1;
  }
  return ngtcp2_crypto_ossl_ctx_new(&p->ossl, p->ssl);
}

void fn_free(fn_peer *p);

/* A client whose first flight is in `chosen`, preferring `versions` */
fn_peer *fn_client_new(uint32_t chosen, const uint32_t *versions,
                       size_t nversions, int app, const uint8_t *ca,
                       size_t ca_len, uint64_t seed, uint64_t now) {
  fn_peer *p = peer_new(0, app, versions, nversions, seed);
  if (!p)
    return NULL;
  p->chosen = chosen;
  p->ctx = SSL_CTX_new(TLS_client_method());
  const uint8_t *der = ca;
  X509 *root = d2i_X509(NULL, &der, (long)ca_len);
  if (!p->ctx || !root ||
      !SSL_CTX_set_min_proto_version(p->ctx, TLS1_3_VERSION) ||
      !X509_STORE_add_cert(SSL_CTX_get_cert_store(p->ctx), root)) {
    X509_free(root);
    fn_free(p);
    return NULL;
  }
  X509_free(root);
  SSL_CTX_set_verify(p->ctx, SSL_VERIFY_PEER, NULL);
  if (start_tls(p)) {
    fn_free(p);
    return NULL;
  }
  ngtcp2_cid dcid = {.datalen = 18}, scid = {.datalen = 17};
  fill(p, dcid.data, dcid.datalen);
  fill(p, scid.data, scid.datalen);
  ngtcp2_settings settings;
  ngtcp2_transport_params params;
  defaults(p, &settings, &params, now);
  ngtcp2_callbacks cb = callbacks(0);
  ngtcp2_path path = path_of(p);
  if (ngtcp2_conn_client_new(&p->conn, &dcid, &scid, &path, chosen, &cb,
                             &settings, &params, NULL, p)) {
    fn_free(p);
    return NULL;
  }
  ngtcp2_conn_set_tls_native_handle(p->conn, p->ossl);
  return p;
}

static int select_alpn(SSL *ssl, const unsigned char **out,
                       unsigned char *outlen, const unsigned char *in,
                       unsigned int inlen, void *arg) {
  (void)ssl;
  (void)arg;
  static const uint8_t ours[] = "\x0ahq-interop";
  if (SSL_select_next_proto((unsigned char **)out, outlen, ours, 11, in,
                            inlen) != OPENSSL_NPN_NEGOTIATED)
    return SSL_TLSEXT_ERR_ALERT_FATAL;
  return SSL_TLSEXT_ERR_OK;
}

/* An hq-interop server preferring `versions`; `retry` makes it validate
 * addresses with Retry first */
fn_peer *fn_server_new(const uint32_t *versions, size_t nversions,
                       const uint8_t *cert, size_t cert_len,
                       const uint8_t *key, size_t key_len, int retry,
                       uint64_t seed) {
  fn_peer *p = peer_new(1, APP_HQ, versions, nversions, seed);
  if (!p)
    return NULL;
  p->retry = retry;
  p->ctx = SSL_CTX_new(TLS_server_method());
  const uint8_t *der = key;
  EVP_PKEY *pkey = d2i_AutoPrivateKey(NULL, &der, (long)key_len);
  if (!p->ctx || !pkey ||
      !SSL_CTX_set_min_proto_version(p->ctx, TLS1_3_VERSION) ||
      !SSL_CTX_use_certificate_ASN1(p->ctx, (int)cert_len, cert) ||
      !SSL_CTX_use_PrivateKey(p->ctx, pkey)) {
    EVP_PKEY_free(pkey);
    fn_free(p);
    return NULL;
  }
  EVP_PKEY_free(pkey);
  SSL_CTX_set_alpn_select_cb(p->ctx, select_alpn, NULL);
  return p;
}

int fn_serve(fn_peer *p, const char *path, const uint8_t *data, size_t len) {
  file *f = calloc(1, sizeof(*f));
  if (!f || !(f->path = strdup(path)) || append(&f->data, data, len)) {
    if (f)
      free(f->path);
    free(f);
    return -1;
  }
  f->next = p->files;
  p->files = f;
  return 0;
}

int fn_request(fn_peer *p, const char *path) {
  if (p->nrequests == MAX_REQUESTS || strlen(path) >= 256)
    return -1;
  request *r = &p->requests[p->nrequests++];
  strcpy(r->path, path);
  return open_requests(p);
}

static int supported(fn_peer *p, uint32_t version) {
  for (size_t i = 0; i < p->nversions; i++)
    if (p->versions[i] == version)
      return 1;
  return 0;
}

/* The server's first packet: Version Negotiation, Retry, or a connection */
static int accept_first(fn_peer *p, const uint8_t *pkt, size_t len,
                        uint64_t now) {
  ngtcp2_version_cid vc;
  int rv = ngtcp2_pkt_decode_version_cid(&vc, pkt, len, 18);
  if ((rv == 0 || rv == NGTCP2_ERR_VERSION_NEGOTIATION) && vc.version &&
      !supported(p, vc.version)) {
    /* RFC 9000 section 6: list the versions this server accepts */
    ngtcp2_ssize n = ngtcp2_pkt_write_version_negotiation(
        p->pending, sizeof(p->pending), (uint8_t)next_random(p), vc.scid,
        vc.scidlen, vc.dcid, vc.dcidlen, p->versions, p->nversions);
    if (n < 0)
      return (int)n;
    p->pending_len = (size_t)n;
    return 0;
  }
  ngtcp2_pkt_hd hd;
  if (ngtcp2_accept(&hd, pkt, len) != 0)
    return 0; /* not an Initial a server can accept: dropped */
  ngtcp2_settings settings;
  ngtcp2_transport_params params;
  defaults(p, &settings, &params, now);
  params.original_dcid = hd.dcid;
  params.original_dcid_present = 1;
  if (p->retry) {
    if (hd.tokenlen == 0) {
      ngtcp2_cid scid = {.datalen = 18};
      fill(p, scid.data, scid.datalen);
      uint8_t token[NGTCP2_CRYPTO_MAX_RETRY_TOKENLEN2];
      ngtcp2_ssize tlen = ngtcp2_crypto_generate_retry_token2(
          token, p->secret, sizeof(p->secret), hd.version,
          (ngtcp2_sockaddr *)&p->remote, sizeof(p->remote), &scid, &hd.dcid,
          now);
      if (tlen < 0)
        return -1;
      ngtcp2_ssize n =
          ngtcp2_crypto_write_retry(p->pending, sizeof(p->pending), hd.version,
                                    &hd.scid, &scid, &hd.dcid, token, (size_t)tlen);
      if (n < 0)
        return -1;
      p->pending_len = (size_t)n;
      return 0;
    }
    ngtcp2_cid odcid;
    if (ngtcp2_crypto_verify_retry_token2(
            &odcid, hd.token, hd.tokenlen, p->secret, sizeof(p->secret),
            hd.version, (ngtcp2_sockaddr *)&p->remote, sizeof(p->remote),
            &hd.dcid, 10 * NGTCP2_SECONDS, now) != 0)
      return 0; /* an invalid token: dropped */
    params.original_dcid = odcid;
    params.retry_scid = hd.dcid;
    params.retry_scid_present = 1;
    settings.token = hd.token;
    settings.tokenlen = hd.tokenlen;
    settings.token_type = NGTCP2_TOKEN_TYPE_RETRY;
  }
  if (start_tls(p))
    return -1;
  ngtcp2_cid scid = {.datalen = 18};
  fill(p, scid.data, scid.datalen);
  ngtcp2_callbacks cb = callbacks(1);
  ngtcp2_path path = path_of(p);
  rv = ngtcp2_conn_server_new(&p->conn, &hd.scid, &scid, &path, hd.version,
                              &cb, &settings, &params, NULL, p);
  if (rv)
    return rv;
  ngtcp2_conn_set_tls_native_handle(p->conn, p->ossl);
  p->first_dcid = hd.dcid;
  return 1;
}

static int failed(fn_peer *p, int rv) {
  if (rv == NGTCP2_ERR_DRAINING || rv == NGTCP2_ERR_CLOSING) {
    p->closed = 1;
    const ngtcp2_ccerr *e = ngtcp2_conn_get_ccerr(p->conn);
    if (rv == NGTCP2_ERR_DRAINING) {
      p->peer_close = *e;
      p->peer_closed = 1;
    }
    return 0;
  }
  p->failed = rv;
  return rv;
}

/* A server connection that never answered was made from a first Initial
 * it could not read, such as a corrupted one. A real server would give the
 * client's next Initial, with another Destination Connection ID, its own
 * connection; this one-connection server replaces it instead. */
static void forget(fn_peer *p) {
  ngtcp2_conn_del(p->conn);
  p->conn = NULL;
  ngtcp2_crypto_ossl_ctx_del(p->ossl);
  p->ossl = NULL;
  SSL_free(p->ssl);
  p->ssl = NULL;
}

static int unanswered(fn_peer *p) { return p->server && p->conn && !p->sent; }

/* Whether `pkt` is a long header packet for another first Initial than
 * the one the connection was made from */
static int other_first(fn_peer *p, const uint8_t *pkt, size_t len) {
  ngtcp2_version_cid vc;
  if (ngtcp2_pkt_decode_version_cid(&vc, pkt, len, 18) != 0 || !vc.version)
    return 0;
  return vc.dcidlen != p->first_dcid.datalen ||
         memcmp(vc.dcid, p->first_dcid.data, vc.dcidlen) != 0;
}

/* Take one datagram. Returns 0, or a negative ngtcp2 error. */
int fn_recv(fn_peer *p, const uint8_t *pkt, size_t len, uint64_t now) {
  if (p->closed || p->failed)
    return p->failed;
  if (unanswered(p) && other_first(p, pkt, len))
    forget(p);
  if (!p->conn) {
    int rv = accept_first(p, pkt, len, now);
    if (rv <= 0)
      return rv < 0 ? failed(p, rv) : 0;
  }
  ngtcp2_path path = path_of(p);
  ngtcp2_pkt_info pi = {0};
  int rv = ngtcp2_conn_read_pkt(p->conn, &path, &pi, pkt, len, now);
  if (rv == NGTCP2_ERR_DROP_CONN && unanswered(p)) {
    forget(p);
    return 0;
  }
  if (rv == NGTCP2_ERR_DISCARD_PKT)
    return 0;
  return rv ? failed(p, rv) : 0;
}

/* Whether `pkt` is for this client: its destination connection ID is one
 * the client issued and has not retired. Client IDs are 17 bytes long. */
int fn_owns(fn_peer *p, const uint8_t *pkt, size_t len) {
  ngtcp2_version_cid vc;
  if (!p->conn || ngtcp2_pkt_decode_version_cid(&vc, pkt, len, 17) != 0)
    return 0;
  size_t n = ngtcp2_conn_get_scid2(p->conn, NULL);
  ngtcp2_cid *scids = calloc(n, sizeof(*scids));
  if (!scids)
    return 0;
  ngtcp2_conn_get_scid2(p->conn, scids);
  int owns = 0;
  for (size_t i = 0; i < n && !owns; i++)
    owns = scids[i].datalen == vc.dcidlen &&
           memcmp(scids[i].data, vc.dcid, vc.dcidlen) == 0;
  free(scids);
  return owns;
}

/* Write at most one datagram into `out`. Returns its length, 0 when there
 * is nothing to send now, or a negative ngtcp2 error. */
long fn_send(fn_peer *p, uint8_t *out, size_t cap, uint64_t now) {
  if (p->pending_len) {
    size_t n = p->pending_len < cap ? p->pending_len : cap;
    memcpy(out, p->pending, n);
    p->pending_len = 0;
    return (long)n;
  }
  if (!p->conn || p->closed || p->failed)
    return p->failed;
  ngtcp2_path path = path_of(p);
  ngtcp2_pkt_info pi;
  for (;;) {
    int64_t id = -1;
    uint32_t flags = 0;
    ngtcp2_vec vec[16];
    size_t count = 0;
    stream *s = NULL;
    if (p->app == APP_H3 && p->h3) {
      int fin = 0;
      nghttp3_ssize n = nghttp3_conn_writev_stream(p->h3, &id, &fin,
                                                   (nghttp3_vec *)vec, 16);
      if (n < 0)
        return failed(p, NGTCP2_ERR_CALLBACK_FAILURE);
      count = (size_t)n;
      if (fin)
        flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
    } else if (p->app == APP_HQ) {
      for (s = p->streams; s; s = s->next)
        if (!s->blocked && (s->sent < s->out.len || (s->fin && !s->fin_sent)))
          break;
      if (s) {
        id = s->id;
        vec[0].base = s->out.data + s->sent;
        vec[0].len = s->out.len - s->sent;
        count = 1;
        if (s->fin)
          flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
      }
    }
    ngtcp2_ssize written = -1;
    ngtcp2_ssize n = ngtcp2_conn_writev_stream(p->conn, &path, &pi, out, cap,
                                               &written, flags, id, vec, count,
                                               now);
    if (n == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
      if (p->h3)
        nghttp3_conn_block_stream(p->h3, id);
      else if (s)
        s->blocked = 1;
      continue;
    }
    if (n == NGTCP2_ERR_STREAM_SHUT_WR) {
      if (p->h3)
        nghttp3_conn_shutdown_stream_write(p->h3, id);
      else if (s)
        s->fin_sent = 1, s->sent = s->out.len;
      continue;
    }
    if (n < 0)
      return failed(p, (int)n);
    if (written >= 0 && id >= 0) {
      if (p->h3) {
        stream *capture = find_stream(p, id, 1);
        if (!capture)
          return failed(p, NGTCP2_ERR_CALLBACK_FAILURE);
        size_t left = (size_t)written;
        for (size_t i = 0; i < count && left; i++) {
          size_t take = vec[i].len < left ? vec[i].len : left;
          if (append(&capture->out, vec[i].base, take))
            return failed(p, NGTCP2_ERR_CALLBACK_FAILURE);
          left -= take;
        }
        if (nghttp3_conn_add_write_offset(p->h3, id, (size_t)written))
          return failed(p, NGTCP2_ERR_CALLBACK_FAILURE);
      } else if (s) {
        s->sent += (size_t)written;
        if (s->fin && s->sent == s->out.len)
          s->fin_sent = 1;
      }
    }
    if (n > 0) {
      ngtcp2_conn_update_pkt_tx_time(p->conn, now);
      p->sent = 1;
    }
    return (long)n;
  }
}

/* The next time the peer needs `fn_expire`, or UINT64_MAX */
uint64_t fn_expiry(fn_peer *p) {
  if (!p->conn || p->closed || p->failed)
    return UINT64_MAX;
  return ngtcp2_conn_get_expiry(p->conn);
}

int fn_expire(fn_peer *p, uint64_t now) {
  if (!p->conn || p->closed || p->failed)
    return p->failed;
  int rv = ngtcp2_conn_handle_expiry(p->conn, now);
  return rv ? failed(p, rv) : 0;
}

/* Close with no error, writing the CONNECTION_CLOSE into `out` */
long fn_close(fn_peer *p, uint8_t *out, size_t cap, uint64_t now) {
  if (!p->conn || p->closed || p->failed)
    return 0;
  ngtcp2_ccerr error;
  ngtcp2_ccerr_default(&error);
  if (p->app == APP_H3)
    ngtcp2_ccerr_set_application_error(&error, NGHTTP3_H3_NO_ERROR, NULL, 0);
  ngtcp2_path path = path_of(p);
  ngtcp2_pkt_info pi;
  ngtcp2_ssize n = ngtcp2_conn_write_connection_close(p->conn, &path, &pi, out,
                                                      cap, &error, now);
  p->closed = 1;
  return (long)n;
}

/* 1 when the peer closed the connection, with its error code and whether
 * the code is an application's */
int fn_peer_close(fn_peer *p, uint64_t *code, int *application) {
  if (!p->peer_closed)
    return 0;
  *code = p->peer_close.error_code;
  *application = p->peer_close.type == NGTCP2_CCERR_TYPE_APPLICATION;
  return 1;
}

int fn_failure(fn_peer *p) { return p->failed; }

/* The application bytes handed to or received from QUIC, without replaying
 * retransmissions. These let the tests establish which QPACK forms the
 * independent encoder actually used. */
void fn_stream_bytes(fn_peer *p, int64_t id, int sent, const uint8_t **data,
                     size_t *len) {
  stream *s = find_stream(p, id, 0);
  const buffer *b = s ? (sent ? &s->out : &s->in) : NULL;
  *data = b ? b->data : NULL;
  *len = b ? b->len : 0;
}


uint32_t fn_version(fn_peer *p) {
  return p->conn ? ngtcp2_conn_get_negotiated_version(p->conn) : 0;
}

/* Request `i`: 1 when complete, with its body and HTTP status (0 for
 * hq-interop) */
int fn_response(fn_peer *p, size_t i, const uint8_t **body, size_t *len,
                int *status) {
  if (i >= p->nrequests)
    return -1;
  request *r = &p->requests[i];
  *body = r->body.data;
  *len = r->body.len;
  *status = r->status;
  return r->done;
}

void fn_free(fn_peer *p) {
  if (!p)
    return;
  if (p->h3)
    nghttp3_conn_del(p->h3);
  if (p->conn)
    ngtcp2_conn_del(p->conn);
  if (p->ossl)
    ngtcp2_crypto_ossl_ctx_del(p->ossl);
  if (p->ssl)
    SSL_free(p->ssl);
  if (p->ctx)
    SSL_CTX_free(p->ctx);
  for (stream *s = p->streams, *next; s; s = next) {
    next = s->next;
    free(s->out.data);
    free(s->in.data);
    free(s);
  }
  for (file *f = p->files, *next; f; f = next) {
    next = f->next;
    free(f->path);
    free(f->data.data);
    free(f);
  }
  for (size_t i = 0; i < p->nrequests; i++)
    free(p->requests[i].body.data);
  free(p);
}
