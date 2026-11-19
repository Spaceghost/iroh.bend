// Bend 2.0.39 native effects. SPDX-License-Identifier: MIT OR Apache-2.0
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>

#define DIRECT_MAX_MESSAGE (1024u * 1024u)

typedef struct Direct {
  struct Direct *next;
  uint32_t id;
  int fd;
  SSL_CTX *ctx;
  SSL *listener;
  SSL *conn;
  SSL *stream;
  EVP_PKEY *expected;
  unsigned char alpn[256];
  unsigned alpn_len;
} Direct;

// Lookups and ownership transfers run on Bend's event loop. Each worker
// receives exclusive ownership and can return it to the loop on success.
static Direct *direct_handles;
static uint32_t direct_next_id = 1;

static uint32_t direct_keep(Direct *state) {
  if (direct_next_id == 0) return 0;
  state->id = direct_next_id++;
  state->next = direct_handles;
  direct_handles = state;
  return state->id;
}

static Direct *direct_take(Env e, Term handle, bool stream) {
  uint32_t id = (uint32_t)e.mem[term_peek(e.mem, handle)];
  for (Direct **slot = &direct_handles; *slot; slot = &(*slot)->next) {
    Direct *state = *slot;
    if (state->id == id && !!state->stream == stream) {
      *slot = state->next;
      return state;
    }
  }
  return NULL;
}

static void direct_free(Direct *state) {
  if (!state) return;
  SSL_free(state->stream);
  SSL_free(state->conn);
  SSL_free(state->listener);
  SSL_CTX_free(state->ctx);
  EVP_PKEY_free(state->expected);
  if (state->fd >= 0) close(state->fd);
  free(state);
}

static bool direct_bytes(Env e, Term t, size_t limit, unsigned char **out, size_t *len) {
  size_t n = 0;
  for (Term cur = t; term_aux(cur) == CID(Con);) {
    u64 item = term_peek(e.mem, cur);
    if (n == limit || e.mem[item] > 255) return false;
    ++n;
    cur = e.mem[item + 1];
  }
  u64 count;
  *out = (unsigned char *)io_cbuf(e, t, &count, CID(Con));
  *len = (size_t)count;
  return true;
}

static int direct_verify(X509_STORE_CTX *store, void *arg) {
  EVP_PKEY *key = X509_STORE_CTX_get0_rpk(store);
  bool matches = key && EVP_PKEY_eq(key, arg) == 1;
  X509_STORE_CTX_set_error(store, matches ? X509_V_OK : X509_V_ERR_APPLICATION_VERIFICATION);
  return matches;
}

static int direct_alpn(SSL *ssl, const unsigned char **chosen, unsigned char *chosen_len,
    const unsigned char *offered, unsigned offered_len, void *arg) {
  (void)ssl;
  Direct *state = arg;
  unsigned char *selected = NULL;
  if (SSL_select_next_proto(&selected, chosen_len, state->alpn, state->alpn_len,
      offered, offered_len) != OPENSSL_NPN_NEGOTIATED) return SSL_TLSEXT_ERR_ALERT_FATAL;
  *chosen = selected;
  return SSL_TLSEXT_ERR_OK;
}

static Direct *direct_new(Env e, Term *fields, bool server) {
  unsigned char *secret = NULL, *peer = NULL, *alpn = NULL;
  size_t secret_len = 0, peer_len = 0, alpn_len = 0;
  const unsigned char raw_key[] = {TLSEXT_cert_type_rpk};
  EVP_PKEY *identity = NULL;
  Direct *state = NULL;
  if (!direct_bytes(e, fields[2], 32, &secret, &secret_len) || secret_len != 32 ||
      !direct_bytes(e, fields[3], 32, &peer, &peer_len) || peer_len != 32 ||
      !direct_bytes(e, fields[4], 255, &alpn, &alpn_len) || alpn_len == 0) goto end;
  state = calloc(1, sizeof(*state));
  if (!state) goto end;
  state->fd = -1;
  identity = EVP_PKEY_new_raw_private_key_ex(NULL, "ED25519", NULL, secret, secret_len);
  state->expected = EVP_PKEY_new_raw_public_key_ex(NULL, "ED25519", NULL, peer, peer_len);
  state->ctx = SSL_CTX_new(server ? OSSL_QUIC_server_method() : OSSL_QUIC_client_method());
  if (!identity || !state->expected || !state->ctx ||
      !SSL_CTX_use_PrivateKey(state->ctx, identity) ||
      !SSL_CTX_set1_server_cert_type(state->ctx, raw_key, 1) ||
      !SSL_CTX_set1_client_cert_type(state->ctx, raw_key, 1)) {
    direct_free(state);
    state = NULL;
    goto end;
  }
  state->alpn[0] = (unsigned char)alpn_len;
  memcpy(state->alpn + 1, alpn, alpn_len);
  state->alpn_len = (unsigned)alpn_len + 1;
  SSL_CTX_set_verify(state->ctx,
    SSL_VERIFY_PEER | (server ? SSL_VERIFY_FAIL_IF_NO_PEER_CERT : 0), NULL);
  SSL_CTX_set_cert_verify_callback(state->ctx, direct_verify, state->expected);
  if (server) SSL_CTX_set_alpn_select_cb(state->ctx, direct_alpn, state);
end:
  if (secret) OPENSSL_cleanse(secret, secret_len);
  EVP_PKEY_free(identity);
  free(secret);
  free(peer);
  free(alpn);
  return state;
}

static bool direct_addr(Env e, Term host, uint32_t port, struct sockaddr_in *out) {
  if (port > UINT16_MAX) return false;
  u64 n;
  char *text = io_cstr(e, host, &n);
  out->sin_family = AF_INET;
  out->sin_port = htons((uint16_t)port);
  bool valid = !io_nul(text, n) && inet_pton(AF_INET, text, &out->sin_addr) == 1;
  free(text);
  return valid;
}

static bool direct_write(SSL *s, const unsigned char *p, size_t len) {
  while (len) {
    size_t written;
    if (!SSL_write_ex(s, p, len, &written) || !written) return false;
    p += written;
    len -= written;
  }
  return SSL_stream_conclude(s, 0) == 1;
}

typedef struct DirectJob {
  Direct *state;
  struct sockaddr_in addr;
  unsigned char *send;
  unsigned char *recv;
  size_t send_len;
  size_t recv_len;
  size_t limit;
  const char *error;
} DirectJob;

static DirectJob *direct_job(Direct *state, size_t limit) {
  DirectJob *job = io_mem(calloc(1, sizeof(*job)));
  job->state = state;
  job->limit = limit;
  return job;
}

static void direct_job_free(DirectJob *job) {
  direct_free(job->state);
  free(job->send);
  free(job->recv);
  free(job);
}

static void direct_read(DirectJob *job) {
  SSL *stream = job->state->stream;
  job->recv = malloc(job->limit + 1);
  if (!job->recv) {
    job->error = "cannot allocate QUIC receive buffer";
    return;
  }
  while (job->recv_len <= job->limit) {
    size_t got = 0;
    int ok = SSL_read_ex(stream, job->recv + job->recv_len,
      job->limit + 1 - job->recv_len, &got);
    if (!ok) {
      if (SSL_get_error(stream, ok) != SSL_ERROR_ZERO_RETURN) job->error = "QUIC read failed";
      return;
    }
    job->recv_len += got;
  }
  job->error = "QUIC message exceeds receive limit";
}

static void direct_shutdown(SSL *conn) {
  SSL_shutdown(conn);
}

#ifdef CID(bind)
static Term direct_bind_run(Env e, Term *f, IoWork *w) {
  (void)w;
  struct sockaddr_in addr = {0};
  socklen_t size = sizeof(addr);
  if (!direct_addr(e, f[0], (uint32_t)f[1], &addr))
    return io_fail(e, EINVAL, "invalid IPv4 listener address");
  Direct *state = direct_new(e, f, true);
  if (!state) return io_fail(e, EINVAL, "invalid QUIC listener identity or ALPN");
  state->fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  state->listener = SSL_new_listener(state->ctx, 0);
  if (state->fd < 0 || !state->listener ||
      bind(state->fd, (struct sockaddr *)&addr, sizeof(addr)) ||
      getsockname(state->fd, (struct sockaddr *)&addr, &size) ||
      !SSL_set_fd(state->listener, state->fd) || !SSL_listen(state->listener)) {
    direct_free(state);
    return io_fail(e, EIO, "cannot start QUIC listener");
  }
  uint32_t id = direct_keep(state);
  if (!id) {
    direct_free(state);
    return io_fail(e, EOVERFLOW, "QUIC handle space exhausted");
  }
  return io_done(e, io_tup(e, io_box(e, CID(BoundUdp), id), ntohs(addr.sin_port)));
}
#endif

#ifdef CID(accept)
static void direct_accept_call(IoWork *w) {
  DirectJob *job = (DirectJob *)w->data;
  Direct *state = job->state;
  state->conn = SSL_accept_connection(state->listener, 0);
  if (!state->conn || !SSL_set_default_stream_mode(state->conn, SSL_DEFAULT_STREAM_MODE_NONE) ||
      !(state->stream = SSL_accept_stream(state->conn, 0)) || !SSL_get0_peer_rpk(state->conn)) {
    job->error = "QUIC accept or peer authentication failed";
    return;
  }
  direct_read(job);
}
static Term direct_accept_pack(Env e, IoWork *w) {
  DirectJob *job = (DirectJob *)w->data;
  Term result;
  if (job->error) {
    result = io_fail(e, EIO, job->error);
  } else {
    uint32_t id = direct_keep(job->state);
    if (!id) {
      result = io_fail(e, EOVERFLOW, "QUIC handle space exhausted");
    } else {
      job->state = NULL;
      result = io_done(e, io_tup(e, io_box(e, CID(AcceptedStream), id),
        io_list(e, (const char *)job->recv, job->recv_len)));
    }
  }
  direct_job_free(job);
  return result;
}
static Term direct_accept_run(Env e, Term *f, IoWork *w) {
  Direct *state = direct_take(e, f[0], false);
  uint32_t limit = (uint32_t)f[1];
  if (!state || limit > DIRECT_MAX_MESSAGE) {
    direct_free(state);
    return io_fail(e, EINVAL, "invalid QUIC listener or receive limit");
  }
  w->data = (void *)direct_job(state, limit);
  return io_work(w, direct_accept_call, direct_accept_pack);
}
#endif

#if defined(CID(respond)) || defined(CID(abort))
static Term direct_finish_pack(Env e, IoWork *w) {
  DirectJob *job = (DirectJob *)w->data;
  Term result = job->error ? io_fail(e, EIO, job->error) : io_done(e, term_pak(CID(Unit), 0));
  direct_job_free(job);
  return result;
}
#endif

#ifdef CID(respond)
static void direct_respond_call(IoWork *w) {
  DirectJob *job = (DirectJob *)w->data;
  if (!direct_write(job->state->stream, job->send, job->send_len))
    job->error = "QUIC response write failed";
  else
    direct_shutdown(job->state->conn);
}
static Term direct_respond_run(Env e, Term *f, IoWork *w) {
  Direct *state = direct_take(e, f[0], true);
  if (!state) return io_fail(e, EINVAL, "invalid QUIC stream");
  DirectJob *job = direct_job(state, 0);
  if (!direct_bytes(e, f[1], DIRECT_MAX_MESSAGE, &job->send, &job->send_len)) {
    direct_job_free(job);
    return io_fail(e, EINVAL, "invalid or oversized QUIC response");
  }
  w->data = (void *)job;
  return io_work(w, direct_respond_call, direct_finish_pack);
}
#endif

#ifdef CID(close)
static Term direct_close_run(Env e, Term *f, IoWork *w) {
  (void)w;
  Direct *state = direct_take(e, f[0], false);
  if (!state) return io_fail(e, EINVAL, "invalid QUIC listener");
  direct_free(state);
  return io_done(e, term_pak(CID(Unit), 0));
}
#endif

#ifdef CID(abort)
static void direct_abort_call(IoWork *w) {
  DirectJob *job = (DirectJob *)w->data;
  const SSL_STREAM_RESET_ARGS reset = {1};
  const SSL_SHUTDOWN_EX_ARGS close_args = {1, "stream aborted"};
  if (!SSL_stream_reset(job->state->stream, &reset, sizeof(reset)) ||
      SSL_shutdown_ex(job->state->conn, 0, &close_args, sizeof(close_args)) < 0)
    job->error = "could not abort QUIC connection";
}
static Term direct_abort_run(Env e, Term *f, IoWork *w) {
  Direct *state = direct_take(e, f[0], true);
  if (!state) return io_fail(e, EINVAL, "invalid QUIC stream");
  w->data = (void *)direct_job(state, 0);
  return io_work(w, direct_abort_call, direct_finish_pack);
}
#endif

#ifdef CID(exchange)
static void direct_exchange_call(IoWork *w) {
  DirectJob *job = (DirectJob *)w->data;
  Direct *state = job->state;
  BIO_ADDR *peer = BIO_ADDR_new();
  state->conn = SSL_new(state->ctx);
  state->fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (!peer || !state->conn || state->fd < 0 ||
      !BIO_ADDR_rawmake(peer, AF_INET, &job->addr.sin_addr,
        sizeof(job->addr.sin_addr), job->addr.sin_port) ||
      !SSL_set_fd(state->conn, state->fd) || !SSL_set1_initial_peer_addr(state->conn, peer) ||
      SSL_set_alpn_protos(state->conn, state->alpn, state->alpn_len) ||
      !SSL_set_default_stream_mode(state->conn, SSL_DEFAULT_STREAM_MODE_NONE) ||
      SSL_connect(state->conn) != 1 || !SSL_get0_peer_rpk(state->conn) ||
      !(state->stream = SSL_new_stream(state->conn, 0))) {
    job->error = "QUIC dial or peer authentication failed";
  } else if (!direct_write(state->stream, job->send, job->send_len)) {
    job->error = "QUIC request write failed";
  } else {
    direct_read(job);
    direct_shutdown(state->conn);
  }
  BIO_ADDR_free(peer);
}
static Term direct_exchange_pack(Env e, IoWork *w) {
  DirectJob *job = (DirectJob *)w->data;
  Term result = job->error ? io_fail(e, EIO, job->error) :
    io_done(e, io_list(e, (const char *)job->recv, job->recv_len));
  direct_job_free(job);
  return result;
}
static Term direct_exchange_run(Env e, Term *f, IoWork *w) {
  size_t limit = (uint32_t)f[6];
  struct sockaddr_in addr = {0};
  if (limit > DIRECT_MAX_MESSAGE || (uint32_t)f[1] == 0 ||
      !direct_addr(e, f[0], (uint32_t)f[1], &addr))
    return io_fail(e, EINVAL, "invalid QUIC remote address or receive limit");
  Direct *state = direct_new(e, f, false);
  if (!state) return io_fail(e, EINVAL, "invalid QUIC client identity or ALPN");
  DirectJob *job = direct_job(state, limit);
  job->addr = addr;
  if (!direct_bytes(e, f[5], DIRECT_MAX_MESSAGE, &job->send, &job->send_len)) {
    direct_job_free(job);
    return io_fail(e, EINVAL, "invalid or oversized QUIC request");
  }
  w->data = (void *)job;
  return io_work(w, direct_exchange_call, direct_exchange_pack);
}
#endif

static void __attribute__((constructor)) direct_register(void) {
#ifdef CID(bind)
  io_eff(CID(bind), direct_bind_run);
#endif
#ifdef CID(accept)
  io_eff(CID(accept), direct_accept_run);
#endif
#ifdef CID(respond)
  io_eff(CID(respond), direct_respond_run);
#endif
#ifdef CID(close)
  io_eff(CID(close), direct_close_run);
#endif
#ifdef CID(abort)
  io_eff(CID(abort), direct_abort_run);
#endif
#ifdef CID(exchange)
  io_eff(CID(exchange), direct_exchange_run);
#endif
}
