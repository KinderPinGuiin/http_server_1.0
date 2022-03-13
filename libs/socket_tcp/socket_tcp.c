#define VERBOSE

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include "c_utils.h"
#include "adresse_internet.h"

/*
 * Types de données
 */

typedef struct socket_tcp {
  int socket;
  adresse_internet *local;
  adresse_internet *distant;
  int is_connected;
  int is_listening;
  int is_bind;
} socket_tcp;

int init_socket_tcp(socket_tcp *psocket) {
  if (psocket == NULL) return -1;
  psocket->socket = -1;
  psocket->local = NULL;
  psocket->distant = NULL;
  psocket->is_connected = 0;
  psocket->is_listening = 0;
  psocket->is_bind = 0;

  return 0;
}

size_t socket_tcp_get_size() {
  return sizeof(socket_tcp);
}

int connect_socket(socket_tcp *osocket, const char *addr, uint16_t port) {
  int r = -1;
  adresse_internet *distant = NULL;
  CHECK_NULL(osocket);
  CHECK_NULL(addr);
  CHECK_NULL(distant = adresse_internet_new(addr, port));
  osocket->distant = distant;
  struct sockaddr_in addr_in;
  CHECK_ERR_AND_FREE(
    adresse_internet_to_sockaddr(distant, (struct sockaddr *) &addr_in), -1
  );
  CHECK_ERR_AND_FREE(osocket->socket = socket(AF_INET, SOCK_STREAM, 0), -1);
  // Permet de ne pas s'occuper des sockets en TIME_WAIT
  int opt = 1;
  CHECK_ERR_AND_FREE(
    setsockopt(osocket->socket, SOL_SOCKET, SO_REUSEADDR | 15, &opt, 
      sizeof(opt)), -1
  );
  CHECK_ERR_AND_FREE(
    connect(osocket->socket, (struct sockaddr *) &addr_in, sizeof(addr_in)), -1
  );
  osocket->is_connected = 1;

  r = 0;
  goto exit;
free:
  if (distant != NULL) adresse_internet_free(osocket->distant);
  if (osocket->socket != -1) close(osocket->socket);
exit:
  return r;
}

int listen_socket(socket_tcp *isocket, const char *addr, uint16_t port, int backlog) {
  int r = -1;
  adresse_internet *local = NULL;
  CHECK_NULL(isocket);
  CHECK_NULL(addr);
  CHECK_NULL(local = adresse_internet_new(addr, port));
  isocket->local = local;
  struct sockaddr_in addr_in;
  CHECK_ERR_AND_FREE(
    adresse_internet_to_sockaddr(local, (struct sockaddr *) &addr_in), -1
  );
  CHECK_ERR_AND_FREE(isocket->socket = socket(AF_INET, SOCK_STREAM, 0), -1);
  // Permet de ne pas s'occuper des sockets en TIME_WAIT
  int opt = 1;
  CHECK_ERR_AND_FREE(
    setsockopt(isocket->socket, SOL_SOCKET, SO_REUSEADDR | 15, &opt, 
      sizeof(opt)), -1
  );
  CHECK_ERR_AND_FREE(
    bind(isocket->socket, (struct sockaddr *) &addr_in, sizeof(addr_in)), -1
  );
  CHECK_ERR_AND_FREE(listen(isocket->socket, backlog), -1);
  isocket->is_listening = 1;

  r = 0;
  goto exit;
free:
  if (local != NULL) adresse_internet_free(isocket->distant);
  if (isocket->socket != -1) close(isocket->socket);
exit:
  return r;
}

int accept_socket_tcp(socket_tcp *s_listening, socket_tcp *s_service) {
  int r = -1;
  if (!s_listening->is_listening) {
    goto free;
  }
  CHECK_NULL(s_listening);
  CHECK_NULL(s_service);
  int fd;
  struct sockaddr_in addr_in;
  socklen_t addr_len;
  memset(&addr_in, 0, sizeof(addr_in));
  memset(&addr_len, 0, sizeof(addr_len));
  CHECK_ERR_AND_FREE(
    fd = accept(s_listening->socket, (struct sockaddr*) &addr_in, &addr_len), -1
  );
  adresse_internet *addr = adresse_internet_any(0);
  CHECK_NULL(addr);
  sockaddr_to_adresse_internet((struct sockaddr *) &addr_in, addr);
  s_service->socket = fd;
  s_service->distant = addr;
  s_service->local = NULL;
  s_service->is_connected = 1;

  r = 0;
free:
  return r;
}

ssize_t write_socket_tcp(const socket_tcp *osocket, void *buffer, 
    size_t length) {
  ssize_t r = -1;
  CHECK_NULL(osocket);
  if (osocket->socket == -1) goto free;
  CHECK_NULL(buffer);
  r = send(osocket->socket, buffer, length, 0);

free:
  return r;
}

ssize_t read_socket_tcp(const socket_tcp *nsocket, void *buffer, 
    size_t length) {
  ssize_t r = -1;
  CHECK_NULL(nsocket);
  if (nsocket->socket == -1) goto free;
  CHECK_NULL(buffer);
  r = recv(nsocket->socket, buffer, length, 0);

free:
  return r;
}

int close_socket_tcp(socket_tcp *socket) {
  if (socket == NULL) return -1;
  if (socket->distant != NULL) adresse_internet_free(socket->distant);
  if (socket->local != NULL) adresse_internet_free(socket->local);
  return (socket->socket == -1) ? -1 : close(socket->socket);
}
