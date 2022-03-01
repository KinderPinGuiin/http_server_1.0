#define _POSIX_C_SOURCE 200809

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "adresse_internet.h"
#include "c_utils.h"

/*
 * Macros fonctions
 */

/**
 * Créé une structure de type sockaddr_in ayant pour nom addr et la remplit avec
 * l'adresse a et le port p.
 * 
 * @param addr La variable où stocker l'adresse.
 * @param a L'adresse à stocker.
 * @param p Le port.
 */
#define SOCKADDR_IN(addr, a, p)                                                \
    do {                                                                       \
      memset(&addr, 0, sizeof(struct sockaddr_in));                            \
      addr.sin_port = htons(p);                                                \
      addr.sin_addr.s_addr = htonl(a);                                         \
    } while(0)

/**
 * Alloue une structure de type adresse_internet et la remplit de la manière
 * suivante :
 * - Le champ storage contiendra une structure de type sockaddr_storage remplit
 *   avec l'adresse a et le port p.
 * - Le champ port sera rempli avec p.
 * - Le champ addr sera la chaine "\0".
 * 
 * @param addr La variable où stocker la structure.
 * @param a L'adresse à stocker.
 * @param p Le port.
 */
#define CREATE_ADRESSE_INTERNET(addr, a, p)                                    \
  do {                                                                         \
    addr = malloc(sizeof(*addr) + 1);                                          \
    CHECK_NULL(addr);                                                          \
    struct sockaddr_in addr_in;                                                \
    SOCKADDR_IN(addr_in, a, p);                                                \
    memcpy(&addr->storage, &addr_in, sizeof(struct sockaddr_in));              \
    addr->port = p;                                                            \
    addr->addr_len = 0;                                                        \
    addr->addr[0] = 0;                                                         \
  } while(0)

/**
 * Extrait l'adresse IP d'une structure sockaddr_storage et la convertit en 
 * chaîne de caractères puis la stock dans str de taille strlen. En cas d'erreur
 * effectue un goto free.
 * 
 * @param addr L'adresse internet associée à storage.
 * @param str La chaîne où stocker l'adresse IP
 * @param strlen La taille maximale de la chaîne str.
 */
#define SOCKADDR_STORAGE_TO_STRING(addr, str, strlen)                          \
  do {                                                                         \
    if (addr->addr_type == AF_INET) {                                          \
      struct sockaddr_in addr_in;                                              \
      memcpy(&addr_in, &addr->storage, sizeof(struct sockaddr_in));            \
      CHECK_NULL(                                                              \
        inet_ntop(AF_INET, &addr_in.sin_addr.s_addr, str, (socklen_t) strlen)  \
      );                                                                       \
    } else {                                                                   \
      struct sockaddr_in6 addr_in;                                             \
      memcpy(&addr_in, &addr->storage, sizeof(struct sockaddr_in6));           \
      CHECK_NULL(                                                              \
        inet_ntop(AF_INET6, &addr_in.sin6_addr.s6_addr, str,                   \
            (socklen_t) strlen)                                                \
      );                                                                       \
    }                                                                          \
  } while(0)

/*
 * Types
 */

typedef struct adresse_internet {
  struct sockaddr_storage storage;
  int is_resolved; // 1 si l'adresse a déjà été résolue, 0 sinon
  sa_family_t addr_type;
  uint16_t port;
  size_t addr_len;
  char addr[]; // Nom de l'adresse
} adresse_internet;

/*
 * Entêtes
 */

/**
 * Applique getaddrinfo sur adresse->addr si celui-ci a une longueur non nulle.
 * Stock le résultat dans adresse->storage.
 * 
 * @param adresse L'adresse à résoudre.
 * 
 * @return 1 en cas de succès et -1 sinon, 0 si l'adresse est invalide.
 */
static int resolve_adresse(adresse_internet *adresse, const char *port);

/*
 * Fonctions
 */

adresse_internet *adresse_internet_new(const char *adresse, uint16_t port) {
  adresse_internet *addr = malloc(sizeof(*addr) + strlen(adresse) + 1);
  CHECK_NULL(addr);
  addr->port = port;
  memcpy(addr->addr, adresse, strlen(adresse) + 1);
  memset(&addr->storage, 0, sizeof(struct sockaddr_storage));
  // Détermine le type d'adresse
  sa_family_t type = AF_INET;
  for (size_t i = 0; adresse[i] != '\0'; ++i) {
    if (adresse[i] == ':' && strlen(adresse) <= INET6_ADDRSTRLEN) {
      type = AF_INET6;
      break;
    }
  }
  addr->addr_type = type;
  addr->is_resolved = 0;
  addr->addr_len = strlen(adresse);

free:
  return addr;
}

adresse_internet *adresse_internet_any(uint16_t port) {
  adresse_internet *addr;
  CREATE_ADRESSE_INTERNET(addr, INADDR_ANY, port);

free:
  return addr;
}

adresse_internet *adresse_internet_loopback(uint16_t port) {
  adresse_internet *addr;
  CREATE_ADRESSE_INTERNET(addr, INADDR_LOOPBACK, port);

free:
  return addr;
}

int adresse_internet_get_info(adresse_internet *adresse, char *nom_dns, 
    int taille_dns, char *nom_port, int taille_port) {
  int r = -1;
  if (nom_dns == NULL && nom_port == NULL) {
    goto free;
  }

  // Remplissage du port
  if (nom_port != NULL) {
    snprintf(nom_port, (size_t) taille_port, "%hu", adresse->port);
  }

  // Remplissage du nom de l'adresse
  if (nom_dns != NULL) {
    if (strlen(adresse->addr) > 0) {
      // Si une adresse a été fournie au départ on la convertie
      strncpy(nom_dns, adresse->addr, (size_t) taille_dns);

      if (!adresse->is_resolved) {
        char port[PORT_MAX_STRLEN + 1];
        snprintf(port, (size_t) PORT_MAX_STRLEN + 1, "%hu", htons(adresse->port));
        CHECK_ERR_AND_FREE(resolve_adresse(adresse, port), -1);
      }
    } else {
      // Sinon on récupère l'adresse IP
      SOCKADDR_STORAGE_TO_STRING(adresse, nom_dns, taille_dns);
    }
  }

  r = 0;
free:
  return r;
}

int adresse_internet_get_ip(const adresse_internet *adresse, char *ip, 
    int taille_ip) {
  int r = -1;
  CHECK_NULL(adresse);
  CHECK_NULL(ip);
  // Si l'adresse n'a pas été résolue on la résout
  if (!adresse->is_resolved) {
    char port[PORT_MAX_STRLEN + 1];
    snprintf(port, (size_t) PORT_MAX_STRLEN + 1, "%hu", adresse->port);
    int r;
    CHECK_ERR_AND_FREE(r = resolve_adresse((adresse_internet *) adresse, port), 
				-1);
		if (r == 0) {
			goto free;
		}
  }
  // Convertit l'adresse en chaîne
  SOCKADDR_STORAGE_TO_STRING(adresse, ip, taille_ip);

  r = 0;
free:
  return r;
}

uint16_t adresse_internet_get_port(const adresse_internet *adresse) {
  return adresse == NULL ? 0 : adresse->port;
}

int adresse_internet_get_domain(const adresse_internet *adresse) {
  return adresse == NULL ? -1 : adresse->addr_type;
}

int sockaddr_to_adresse_internet(const struct sockaddr *addr, 
    adresse_internet *adresse) {
  int r = -1;
  CHECK_NULL(addr);
  CHECK_NULL(adresse);

  // Remplis adresse
  memcpy(&adresse->storage, addr, sizeof(struct sockaddr));
  adresse->addr_type = addr->sa_family;
  adresse->addr[0] = 0;
  adresse->is_resolved = 1;

  // Remplissage différent de storage selon le type d'adresse
  if (adresse->addr_type == AF_INET) {
    struct sockaddr_in *addr_in = (struct sockaddr_in *) addr;
    adresse->port = addr_in->sin_port;
    memcpy(&adresse->storage, addr_in, sizeof(struct sockaddr_in));
  } else if (adresse->addr_type == AF_INET6) {
    struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *) addr;
    adresse->port = addr_in6->sin6_port;
    memcpy(&adresse->storage, addr_in6, sizeof(struct sockaddr_in6));
  } else {
    goto free;
  }

  r = 0;
free:
  return r;
}

int adresse_internet_to_sockaddr(adresse_internet *adresse, 
    struct sockaddr *addr) {
  int r = -1;
  CHECK_NULL(adresse);
  CHECK_NULL(addr);

  if (!adresse->is_resolved) {
    char port[PORT_MAX_STRLEN + 1];
    snprintf(port, (size_t) PORT_MAX_STRLEN + 1, "%hu", htons(adresse->port));
    CHECK_ERR_AND_FREE(resolve_adresse(adresse, port), -1);
  }

  if (adresse->addr_type == AF_INET) {
    struct sockaddr_in *addr_in = (struct sockaddr_in *) addr;
    struct sockaddr_in *addr_in_storage = (struct sockaddr_in *) &adresse->storage;
    addr_in->sin_family = addr_in_storage->sin_family;
    addr_in->sin_addr = addr_in_storage->sin_addr;
    addr_in->sin_port = addr_in_storage->sin_port;
  } else {
    struct sockaddr_in6 *addr_in = (struct sockaddr_in6 *) addr;
    struct sockaddr_in6 *addr_in_storage = (struct sockaddr_in6 *) &adresse->storage;
    addr_in->sin6_family = addr_in_storage->sin6_family;
    addr_in->sin6_addr = addr_in_storage->sin6_addr;
    addr_in->sin6_port = addr_in_storage->sin6_port;
  }

  r = 0;
free:
  return r;
}

int adresse_internet_compare(const adresse_internet *addr1, 
    const adresse_internet *addr2) {
  int r = -1;
  CHECK_NULL(addr1);
  CHECK_NULL(addr2);

  if (addr1->is_resolved && addr2->is_resolved) {
    if (addr1->addr_type == AF_INET6 && addr2->addr_type == AF_INET6) {
      struct sockaddr_in6 *addr_in1 = (struct sockaddr_in6 *) &addr1->storage;
      struct sockaddr_in6 *addr_in2 = (struct sockaddr_in6 *) &addr2->storage;
      r = addr_in1->sin6_port == addr_in2->sin6_port 
          && addr_in1->sin6_addr.__in6_u.__u6_addr32 
              == addr_in2->sin6_addr.__in6_u.__u6_addr32;
    } else if (addr1->addr_type == AF_INET && addr2->addr_type == AF_INET) {
      struct sockaddr_in *addr_in1 = (struct sockaddr_in *) &addr1->storage;
      struct sockaddr_in *addr_in2 = (struct sockaddr_in *) &addr2->storage;
      r = addr_in1->sin_port == addr_in2->sin_port 
          && addr_in1->sin_addr.s_addr == addr_in2->sin_addr.s_addr;
    } else {
      r = 0;
    }
  } else {
    r = strcmp(addr1->addr, addr2->addr) == 0 && addr1->port == addr2->port;
  }

free:
  return r;
}

int adresse_internet_copy(adresse_internet *dest, const adresse_internet *src) {
  int r = -1;
  CHECK_NULL(dest);
  CHECK_NULL(src);

  memcpy(dest, src, sizeof(adresse_internet) + dest->addr_len);

free:
  return r;
}

void adresse_internet_free(adresse_internet *addr) {
  SAFE_FREE(addr);
}

int print_addr(FILE* out, adresse_internet *addr) {
  int r = 0;
  CHECK_NULL(out);
  CHECK_NULL(addr);
  char dns[DNS_MAX_STRLEN + 1];
  char port[PORT_MAX_STRLEN + 1];
  CHECK_ERR_AND_FREE(
    adresse_internet_get_info(addr, dns, DNS_MAX_STRLEN + 1, 
      port, PORT_MAX_STRLEN + 1), -1
  );
  fprintf(out, "%s:%s\n", dns, port);

free:
  return r;
}

/*
 * Fonctions utiles
 */

static int resolve_adresse(adresse_internet *adresse, const char *port) {
  struct addrinfo hints;
  struct addrinfo *result = NULL;
  int r = -1;

  CHECK_NULL(adresse);
  if (strlen(adresse->addr) == 0) {
    r = 1;
    goto free;
  }

  // Récupère les infos du DNS
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_family = adresse->addr_type;
  r = getaddrinfo(adresse->addr, port, &hints, &result);
  if (result == NULL) {
		r = 0;
		goto free;
	}
  // Stock ces infos dans adresse->storage
  if (adresse->addr_type == AF_INET) {
    struct sockaddr_in addr_in;
    memset(&addr_in, 0, sizeof(struct sockaddr_in));
    memcpy(&adresse->storage, result->ai_addr, sizeof(struct sockaddr_in));
  } else {
    struct sockaddr_in6 addr_in;
    memset(&addr_in, 0, sizeof(struct sockaddr_in6));
    memcpy(&adresse->storage, &result->ai_addr, sizeof(struct sockaddr_in6));
  }
  adresse->is_resolved = 1;

	r = 1;
free:
  if (result != NULL) {
    freeaddrinfo(result);
  }
  return r;
}
