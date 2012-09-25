/*
 * PingPong
 * Copyright (C) 2012  Matthew Finkel <Matthew.Finkel@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/select.h>
#include <stdarg.h>

#define PORT "7464"
#define BACKLOG 7
#define BUFSIZE 4
#define DATEFMT "%F %H:%M:%S"

#define get_max(a,b) ((a) > (b) ? (a) : (b))

int ping(char *, char *, char *, char *);


struct node_t {
  int fd;
  char buf[BUFSIZE];
  int buf_used;
  void * next;
  char addr[INET6_ADDRSTRLEN];
} * node;

struct socks5_socket_t {
  char * bindaddr;
  char bindport[2];
};

char remote[INET6_ADDRSTRLEN];
int loglevel;
char * logfile;

inline void logit(FILE * fd, char * str, ...) {
  FILE * file;
  char * s, * ss;
  int size = 40, ret;

  time_t now;
  now = time(NULL);
  char nowstr[20];
  char * datefmt = "%F %T";
  struct tm * snow;
  snow = localtime(&now);
  strftime(nowstr, 20, datefmt, snow);

  va_list va;
  va_start(va, str);

  switch(loglevel) {
    case 0:
      fprintf(fd, "%s: ", nowstr);
      vfprintf(fd, str, va);
      break;
    case 1:
      s = (char *)malloc(size * sizeof(char));
      ret = snprintf(s, size, "%s: ", nowstr);
      if(ret > size) {
        size = ret + 1;
        ss = (char *)realloc(s, size * sizeof(char));
        if(ss == NULL) {
          fprintf(stderr, "%s: we had trouble printing the following message to file\n", nowstr);
          vfprintf(stderr, str, va);
	  free(s);
	  return;
        } else
          ret = snprintf(ss, size, "%s: ", nowstr);
	  s = ss;
      } else
        ss = s;

      file = fopen(logfile, "w+");
      fwrite(ss, sizeof(char), ret, file);
      if(fd == stderr)
        fwrite("ERROR: ", 8, sizeof(char), file);
      free(s);
      s = (char *)malloc(size * sizeof(char));
      ret = vsnprintf(s, size, str, va);
      if(ret > size) {
        size = ret + 1;
        ss = (char *)realloc(s, size * sizeof(char));
        if(ss == NULL) {
          fprintf(stderr, "%s: we had trouble printing the following message to file\n", nowstr);
          vfprintf(stderr, str, va);
	  free(s);
	  fclose(file);
	  return;
        } else
          ret = vsnprintf(ss, size, str, va);
	  s = ss;
      } else
        ss = s;
      fwrite(ss, ret, sizeof(char), file);
      fclose(file);
      break;
    default:
      break;
  }
}

void * get_in_addr(struct sockaddr * sa){
  if(sa->sa_family == AF_INET)
  {
    return &(((struct sockaddr_in*)sa)->sin_addr);
  }
  return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

void sig_handle_pipe(int sig) {
  if(sig == SIGPIPE) {
    logit(stdout, "We've lost connection with the peer!\n");
    ping(remote, PORT, "192.168.2.6", "9100");
  }

}

void remove_and_close(struct node_t * rem) {
  struct node_t * cur;
  for(cur = node; cur != NULL; cur = cur->next) {
    if(cur != NULL && cur == node && cur == rem) {
      logit(stdout, "Removing connection from %s, closed by peer\n", cur->addr);
      node = cur->next;
      free(cur);
    } else if(cur->next != NULL && cur->next == rem) {
      void * tmp = cur->next;
      logit(stdout, "Removing connection from %s, closed by peer\n", ((struct node_t *)tmp)->addr);
      cur->next = ((struct node_t *)cur->next)->next;
      free(tmp);
      break;
    }
  }
}


int socket_bind_list() {
  int fdsock;
  struct addrinfo hints, servinfo, *pservinfo, *piterator;
  int retval, i = 0, yes = 1;
  memset(&hints, 0, sizeof hints);

  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  pservinfo = &servinfo;

  if((retval = getaddrinfo(NULL, PORT, &hints, &pservinfo)) != 0)
  {
    logit(stderr, "ERROR: getaddrinfo: %s\n", gai_strerror(retval));
    return retval;
  }

  for(piterator = pservinfo; piterator != NULL; piterator = piterator->ai_next)
  {
    i++;
    if ((fdsock= socket(piterator->ai_family, piterator->ai_socktype, 
      piterator->ai_protocol)) == -1) 
    {
      logit(stderr, "ERROR: server: socket\n");
      continue;
    }

    if(setsockopt(fdsock, 
                  SOL_SOCKET, 
		  SO_REUSEADDR, 
		  &yes, 
		  sizeof yes) == -1)
    {
      logit(stderr,"ERROR: setsockopt\n");
      exit(1);
    }

    if(bind(fdsock, piterator->ai_addr, piterator->ai_addrlen) == -1)
    { 
      logit(stderr, "ERROR: server: bind: %d\n", fdsock);
      logit(stderr, "\t %s %d\n", piterator->ai_addr->sa_data, piterator->ai_addrlen);
      close(fdsock);
      continue;
    }

    break;
  }

  if(piterator == NULL)
  {
    logit(stderr, "ERROR: server: Failed to bind for unknown reason\n"
        "\tIterated through loop %d times\n", i);

    freeaddrinfo(pservinfo);
    exit(-2);
    return -2;
  }

  if(pservinfo)
    freeaddrinfo(pservinfo);

  if (listen(fdsock, BACKLOG) == -1)
  { 
    logit(stderr, "listen: failed to mark as passive\n");
    exit(1);
  }
  return fdsock;
}
 
int pong(){
  int fdsock;
  int retval;

  int acceptedfd = 0;
  struct sockaddr_storage client_addr;
  char addr[INET6_ADDRSTRLEN] = "";
  struct node_t * cur;
  socklen_t sin_size;

  sin_size = sizeof client_addr;

  fdsock = socket_bind_list();
  
  node = (struct node_t *)malloc(sizeof(struct node_t));
  node->next = NULL;
  node->fd = fdsock;

  int max;
  max = fdsock;
  fd_set forreading;
  while(1){
    FD_ZERO(&forreading);
    cur = node;
    max = 0;
    for(; cur != NULL; cur = cur->next) {
      FD_SET(cur->fd, &forreading);
      max = get_max(max, cur->fd);
    }
    if((retval = select(max + 1, &forreading, NULL, NULL, NULL))){
      if(retval == -1){
        if(errno == EBADF){
	  logit(stderr, "An invalid file descriptor was given in one of"
	                  " the sets\n");
	  continue;
	}else if(errno == EINTR){
	  logit(stderr, "A signal was caught.\n");
	  continue;
	}else if(errno == EINVAL){
	  logit(stderr, "nfds is negative or the value contained within timeout is invalid\n");
	  continue;
	}else if(errno == ENOMEM){
	  logit(stderr, "unable to allocate memory for internal tables.\n");
	  continue;
	}
      } else if(retval){
        cur = node;
        for(; cur != NULL; cur = cur->next) {
	  if(cur->fd > 0 && FD_ISSET(cur->fd, &forreading)) {
	    if(cur->fd == fdsock) {
              acceptedfd = accept(fdsock, (struct sockaddr *)&client_addr, &sin_size);
              inet_ntop(client_addr.ss_family, 
                        get_in_addr((struct sockaddr *)&client_addr), 
                                     addr, sizeof addr);

              if ( addr == NULL ) {
                logit(stderr, "ERROR: Failed to convert the client IP Address!\n");
                logit(stderr, " Error: %s\n", strerror(errno));
                logit(stderr, "ERROR: Closing connection...\n");
                close(acceptedfd);
                continue;
              }
              logit(stdout, "Accepting Connection from: %s\n", addr);

	      struct node_t * new;
              new = (struct node_t *)malloc(sizeof(struct node_t));
              new->next = node;
              new->buf_used = 0;
              node = new;
              node->fd = acceptedfd;
	      strncpy(node->addr, addr, sizeof(addr));
              FD_SET(acceptedfd, &forreading);
              if(!(retval = read(node->fd, node->buf + node->buf_used,
	           BUFSIZE - node->buf_used)) && BUFSIZE - cur->buf_used == 0) {
	        logit(stdout, "Buffer is full. Contains: %s, %d bytes \n Emptying now.\n",
	               node->buf, node->buf_used);
                node->buf_used = 0;
              } else if(retval == -1){
	        logit(stderr, "Read returned an error: %s\n", strerror(errno));
	      } else {
	        node->buf_used += retval;
                logit(stdout, "Read in %d bytes, %s\n", retval, node->buf);
	        if(!strncmp(node->buf, "ping", 4))
		  write(node->fd, "pong", 4);
		if(node->buf_used == BUFSIZE)
		  node->buf_used = 0;
	      }
	    } else if(!(retval = read(cur->fd, cur->buf + cur->buf_used,
	                              BUFSIZE - cur->buf_used))) {
                if(BUFSIZE - cur->buf_used == 0) {
	          logit(stdout, "Buffer is full. Contains: %s, %d bytes\n Emptying now.\n",
	               cur->buf, cur->buf_used);
                  cur->buf_used = 0;
		} else {
                  remove_and_close(cur);
		}
	    } else if(retval == -1){
	      logit(stderr, "Read returned an error: %s\n", strerror(errno));
	      switch(errno) {
	        case EBADF:
		case EFAULT:
		case EINVAL:
		case EIO:
		case EISDIR:
                  remove_and_close(cur);
		  break;
		default:
		  break;
              }
	    } else {	      
	      cur->buf_used += retval;
              logit(stdout, "Read in %d bytes, %s\n", retval, cur->buf);
	      if(retval == 0)
	        remove_and_close(cur);
              else {
	        if(!strncmp(cur->buf, "ping", 4))
		  write(cur->fd, "pong", 4);
              if(node->buf_used == BUFSIZE)
	        node->buf_used = 0;
              }
	    }
	  }
	}
      }
    }
  }
  return 0;
}

int pp_connect(char * hostaddr, char * port) {
  struct sigaction sa;

  sa.sa_handler = sig_handle_pipe;
  sigaction(SIGPIPE, &sa, NULL);

  int sfd, s;
  struct sockaddr_in addr;
  char * address;
  struct addrinfo hints;
  struct addrinfo *result, *rp;
  if(strcmp(hostaddr, ""))
    address = hostaddr;
  else
    address = "127.0.0.1";

  int size = strlen(address);
  strncpy(remote, hostaddr, size);

  memset(&addr, 0, sizeof addr);

  hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
  hints.ai_socktype = SOCK_STREAM; /* Datagram socket */
  hints.ai_flags = 0;
  hints.ai_protocol = 0;          /* Any protocol */

  s = getaddrinfo(address, port, &hints, &result);
  if (s != 0) {
    logit(stderr, "getaddrinfo: %s\n", gai_strerror(s));
    exit(EXIT_FAILURE);
  }

  for (rp = result; rp != NULL; rp = rp->ai_next) {
    sfd = socket(rp->ai_family, rp->ai_socktype,
                 rp->ai_protocol);
    if (sfd == -1)
      continue;

    if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1)
      break;                  /* Success */

    close(sfd);
  }

  if (rp == NULL) {               /* No address succeeded */
    logit(stderr, "Could not connect to %s:%s\n", address, port);
    exit(EXIT_FAILURE);
  }

  freeaddrinfo(result);           /* No longer needed */
  return sfd;
}
  
struct socks5_socket_t *
socks5_connect(char * socksaddr, char * socksport, char * addr,
               char * port, int nmethods, char method) {
  int sfd = pp_connect(socksaddr, socksport);
  char * cims;
  int ret;
  int size = 1 + nmethods + /*strlen(method)*/ 1 + 1;
  cims = (char *)malloc(size * sizeof(char));
  /*snprintf(cims, size, "%x%x%s", 0x05, nmethods, method);*/
  snprintf(cims, size, "%c%c%c", 0x05, 0x01, 0x00);
  printf("%s %d\n", cims, size);
  ret = write(sfd, cims, size);
  if(ret != size)
    write(sfd, cims + ret, size - ret);
  ret = read(sfd, cims, size);
  cims[ret + 1] = '\0';
  if(ret != 2)
    logit(stderr, "The response from the SOCKS 5 was invalid. Failing.\n");

  int i = 0, ver = 0, meth = 0;
  ver = cims[0];
  meth = cims[1];
  if(ver != 5){
    logit(stderr, "The SOCKS 5 server does not support SOCKS 5, we can"
                  " not continue. Version %d returned.\nRequest sent: \n", ver);
    exit(0);
  }
  for(i = 0; i < nmethods; i++) {
    if(method == meth)
      break;
  }
  if(i == nmethods) {
    logit(stderr, "The SOCKS 5 server does not support the chosen"
                  " authentication method, we can not continue."
		  " Returned %x instead of %s\n", meth, method);
    exit(0);
  }
  free(cims);
  logit(stdout, "Server supports SOCKS 5 without authentication,"
                " establishing connection\n");

  char * request;
  int addrlen;
  addrlen = strlen(addr);
  char buffer[] = { 0x05, 0x01, 0x00, 0x05, addrlen };
  request = (char *)malloc(size * sizeof(char));

  size = sizeof(buffer);
  memcpy(request, buffer, size);
  memcpy(&request[size], addr, addrlen);
  size += addrlen;
  uint16_t nsport = htons(atoi(port));
  memcpy(&request[size], &nsport, sizeof(nsport));
  size += sizeof(nsport);
  ret = write(sfd, request, size);
  if(ret != size)
    write(sfd, request + ret, size - ret);
  ret = write(sfd, request, size);
  free(request);
  
  char * reply;
  size = 4 + addrlen + 2 + 1;
  reply = (char *)malloc(size * sizeof(char));
  ret = read(sfd, reply, size);
  size = read(sfd, reply + ret, size - ret);
  int atyp;
  char bindaddr[4];
  uint16_t bindport;
  ver = reply[0];
  switch(reply[1]) {
    case 0x00:
      logit(stdout, "We successfully connected with the SOCKS 5 server.\n");
      break;
    case 0x01:
      fprintf(stderr, "We encountered a general SOCKS server failure. Sorry.\n");
      exit(EXIT_FAILURE);
    case 0x02:
      fprintf(stderr, "This connection is not allowed by the server's ruleset. Sorry.\n");
      exit(EXIT_FAILURE);
    case 0x03:
      fprintf(stderr, "The network is unreachable. Sorry.\n");
      exit(EXIT_FAILURE);
    case 0x04:
      fprintf(stderr, "The host is unreachable. Sorry.\n");
      exit(EXIT_FAILURE);
    case 0x05:
      fprintf(stderr, "The connection was refused. Sorry.\n");
      exit(EXIT_FAILURE);
    case 0x06:
      fprintf(stderr, "TTL expired while attempting to make the connection. Sorry.\n");
      exit(EXIT_FAILURE);
    case 0x07:
      fprintf(stderr, "The command you specified is not supported. Sorry.\n");
      exit(EXIT_FAILURE);
    case 0x08:
      fprintf(stderr, "The address type is not supported. Sorry.\n");
      exit(EXIT_FAILURE);
    default:
      fprintf(stderr, "The address type is not supported. Sorry.\n");
      exit(EXIT_FAILURE);
  }
  atyp = reply[3];
  if(atyp == 0x02) {
    fprintf(stderr, "The server selected domain name as the address type."
                    " This is currently unimplemented\n");
    exit(EXIT_FAILURE);
  } else if(atyp == 0x03) {
    fprintf(stderr, "The server selected domain name as the address type."
                    " This is currently unimplemented.\n");
    exit(EXIT_FAILURE);
  }
  int addr_offset = 4, addr_size = 4, port_offset_from_rear = 2;
  /*bindaddr = (char *)malloc(addr_size * sizeof(char));*/
  memcpy(bindaddr, reply + addr_offset, size - addr_size - port_offset_from_rear);
  bindport = reply[addr_offset + addr_size];
  /*logit(stderr, "BUG: We seem to have parsed the reply incorrectly."
                  " The reply was %s and we are at index %d\n", reply, i);*/
  struct socks5_socket_t * bindsock;
  bindsock = (struct socks5_socket_t *)malloc(sizeof(bindsock));
  size = strlen(addr);
  bindsock->bindaddr = (char *)malloc(size * sizeof(addr));
  strncpy(bindsock->bindaddr, bindaddr, size);
  bindsock->bindport[0] = bindport & 0xFF;
  bindsock->bindport[1] = (bindport >> 8) & 0xFF;
  logit(stdout, "SOCKS 5 server returned bind address %s:%s\n", bindsock->bindaddr, bindsock->bindport);
  logit(stdout, "%s\n", reply);
  return bindsock;
}

int ping(char * hostaddr, char * port, char * socksaddr, char * socksport){
  struct socks5_socket_t * sockssock;
  char buf[BUFSIZE + 1];
  buf[BUFSIZE] = '\0';
  sockssock = socks5_connect(socksaddr, socksport, hostaddr, port, 1, 0x00);
  int sfd = pp_connect(sockssock->bindaddr, sockssock->bindport);
  for(;;){
    write(sfd, "ping", 4);
    read(sfd, buf, 4);
    logit(stdout, "Received: %s\n", buf);
    sleep(5);
  }
  return 0;
}

int main(int argc, char * argv[]) {
  loglevel =  0;
  if(argc > 1) {
    if(!strncmp(argv[1], "-s", 2)) {
      logit(stdout, "Starting pong server\n");
      pong();
    } else if(argc > 1 && argc < 7) {
      if(!strncmp(argv[1], "-c", 2)) {
        logit(stdout, "Starting ping client to %s:%s via %s:%s\n",
	      argv[2], argv[3], argv[4], argv[5]);
        if(argc == 6)
	  ping(argv[2], argv[3], argv[4], argv[5]);
	else
	  ping("", "7464", "127.0.0.1", "9100");
      }
    }
  }
  return 0;
}
