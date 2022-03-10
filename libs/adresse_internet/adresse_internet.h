/**
 * Bibliothèque permettant la manipulation de l'adressage pour des sockets
 * internet.
 */

#ifndef ADRESSE_INTERNET_H
#define ADRESSE_INTERNET_H

#include <stdint.h>
#include <sys/socket.h>

/**
 * Le port maximum est 65535 (2^16 - 1).
 */
#define PORT_MAX_STRLEN 5

/**
 * @see https://datatracker.ietf.org/doc/html/rfc1035
 */
#define DNS_MAX_STRLEN 255

/**
 * Type permettant de manipuler les adresses internet.
 */
typedef struct adresse_internet adresse_internet;

/**
 * Alloue et renvoie un pointeur vers une structure adresse_internet.
 * 
 * @param adresse L'adresse qui sera stockée dans la structure, celle-ci 
 *                peut-être fournie au format DNS ou IP.
 * 
 * @param port    Le port qui sera stocké dans la strucutre.
 * 
 * @return        Un pointeur vers la structure adresse_internet remplie par les
 *                informations données. Renvoie NULL en cas de problème 
 *                d'allocation.
 */
adresse_internet *adresse_internet_new(const char *adresse, uint16_t port);

/**
 * Construit et renvoie la référence d'une adresse internet correspondant à 
 * toutes les interfaces réseau à partir d'un numéro de port donné.
 * 
 * @param port Le port sur lequel construire l'adresse internet.
 * 
 * @return     Un pointeur vers l'adresse internet construite ou NULL en cas 
 *             d'erreur mémoire
 */
adresse_internet *adresse_internet_any(uint16_t port);

/**
 * Construit et renvoie la référence d'une adresse internet correspondant à 
 * l'interface loopback à partir d'un numéro de port donné.
 * 
 * @param port Le port sur lequel construire l'adresse internet.
 * 
 * @return     Un pointeur vers l'adresse internet construite ou NULL en cas 
 *             d'erreur mémoire
 */
adresse_internet *adresse_internet_loopback(uint16_t port);

/**
 * Extrait de l'adresse internet adresse : 
 * - Le nom de l'adresse et le stock dans nom_dsn qui sera de taille taille_dns.
 * - Le port de l'adresse qui sera stocké dans nom_port qui sera de taille
 *   taille_port.
 * 
 * @note adresse sera mis à jour si nécessaire (Résolution DNS).
 * @note nom_dns OU (exclusif) nom_port peuvent être nuls, le cas écheant, ils 
 *       ne seront pas remplis.
 * 
 * @param adresse     L'adresse où l'on souhaite extraire les informations.
 * @param nom_dns     La chaîne où stocker le nom de l'adresse.
 * @param taille_dns  La taille maximale de la chaîne nom_dns.
 * @param nom_port    La chaîne où stocker le port de l'adresse.
 * @param taille_port La taille maximale de la chaîne nom_port.
 * 
 * @return 0 en cas de succès et -1 en cas d'erreur ou si nom_dns ET nom_port
 *         sont nuls.
 */
int adresse_internet_get_info(adresse_internet *adresse, char *nom_dns, 
    int taille_dns, char *nom_port, int taille_port);

/**
 * Extrait l'adresse IP de l'adresse internet pointée par adresse et la stock 
 * dans ip, si cela n'a pas déjà été fais, le nom DNS de l'adresse sera résolu.
 * tailleIP donne la taille maximale de la chaîne ip.
 * 
 * @param adresse   L'adresse où l'on souhaite extraire l'IP.
 * @param ip        La chaîne où stocker l'adresse IP.
 * @param taille_ip La taille maximale de la chaîne ip.
 * 
 * @return          0 en cas de succès et -1 en cas d'erreur.
 */
int adresse_internet_get_ip(const adresse_internet *adresse, char *ip, 
    int taille_ip);

/**
 * Renvoie le port associée à l'adresse pointée par adresse.
 * 
 * @param adresse L'adresse dont on souhaite récupérer le port.
 * 
 * @return        Le port ou 0 si adresse vaut NULL.
 */
uint16_t adresse_internet_get_port(const adresse_internet *adresse);

/**
 * Renvoie le domaine de l'adresse pointée par adresse (AF_INET ou AF_INET6).
 * 
 * @param adresse L'adresse dont on souhaite récupérer le domaine.
 * 
 * @return        AF_INET ou AF_INET6 selon le domaine. -1 si adresse vaut NULL.
 */
int adresse_internet_get_domain(const adresse_internet *adresse);

/**
 * Convertit addr en adresse_internet adresse qui sera préalablement allouée.
 * 
 * @param addr    La structure sockaddr à convertir.
 * @param adresse L'adresse à remplir avec les informations de addr.
 * 
 * @return        0 en cas de succès et -1 en cas d'échec.
 */
int sockaddr_to_adresse_internet(const struct sockaddr *addr, 
    adresse_internet *adresse);

/**
 * Convertit adresse qui sera préalablement alloué en sockaddr addr.
 * 
 * @param adresse L'adresse à remplir à convertir.
 * @param addr    La structure sockaddr avec les informations de adresse.
 * 
 * @return        0 en cas de succès et -1 en cas d'échec.
 */
int adresse_internet_to_sockaddr(adresse_internet *adresse, 
    struct sockaddr *addr);

/**
 * Fonctions de comparaison d'adresses internet.
 * 
 * @param addr1
 * @param addr2
 * 
 * @return 1 si addr1 et addr2 ont la même IP et le même port, 0 sinon. -1 si
 *         addr1 ou addr2 est NULL.
 */
int adresse_internet_compare(const adresse_internet *addr1, 
    const adresse_internet *addr2);

/**
 * Copie l'adresse internet src dans dest.
 * 
 * @param dest L'adresse de destination.
 * @param src L'adresse source.
 * 
 * @return 0 en cas de succès et -1 si src ou dest vaut NULL.
 */
int adresse_internet_copy(adresse_internet *dest, const adresse_internet *src);

/**
 * Libère les ressources allouées par l'adresse internet pointée par addr.
 * Si addr est nul, alors rien n'est fais.
 * 
 * @param addr L'adresse internet à libérer.
 */
void adresse_internet_free(adresse_internet *addr);

/**
 * Affiche l'adresse internet pointée par addr au format ip:port sur out. 
 * N'affiche rien si addr ou out vaut NULL.
 * 
 * @param out  La sortie sur laquelle afficher l'adresse.
 * @param addr L'adresse à afficher.
 * 
 * @return     -1 en cas d'erreur et 0 sinon.
 */
int print_addr(FILE* out, adresse_internet *addr);

#endif