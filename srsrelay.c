/* srsrelay.c -- Apply/Remove SRS when SMTP passes through
 *
 * This reads and writes lines, and processes MAIL FROM:<...@...>
 * for outward-bound traffic, and RCPT TO:<...@...> for bounces,
 * where it checks the part last ... to be a local domain, and if
 * not it will make it so, using libsrs2 to pack or unpack ...@...
 *
 * Since this behaves like an SMTP, ESMTP or LMTP server, it can
 * easily be configured as the next hop in any MTA.  Both packed
 * and unpacked (and even unmodified) traffic pass through to yet
 * another hop in the mail infrastructure.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdlib.h>
#include <stdio.h>
#include <netdb.h>
#include <string.h>
void *memrchr (void*,int,int);

#include <unistd.h>
#include <errno.h>
#include <libgen.h>
#include <syslog.h>
#include <poll.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <srs2.h>


#define MAXLEN_BUF 1024

#define WRAP_MAGIC "MAIL FROM:<"
#define WRAP_MAGIC_LEN ((sizeof(WRAP_MAGIC)-1))

#define UNWRAP_MAGIC "RCPT TO:<"
#define UNWRAP_MAGIC_LEN ((sizeof(UNWRAP_MAGIC)-1))


#define logperror(s) syslog (LOG_ERR, "%s: %s", strerror(errno), (s))


typedef struct {
	srs_t *srs;
	char **domv;
	int domc;
	int wrapper;
	char *magic;
	int magic_len;
	int (*srs_fun) (srs_t *, char *, int, const char *, const char *);
} srs_info;

int srs_reverse_unified (srs_t *srs,
				char *buf, int buflen,
				const char *address,
				const char *_) {
	return srs_reverse (srs, buf, buflen, address);
}

void rewrite (srs_info *srsi, char *buf, int *buflen) {
	char *closer;
	int closer_ofs, closer_len;
	char *address, *domain;
	int address_len, domain_len;
	char newbuf [1024];
	int srsout, srslen;
	int domi;

	closer = memchr (buf, '>', *buflen);
	if (closer == NULL) {
		syslog (LOG_ERR, "Unbalanced <...> around envelope address");
		exit (1);
	}
	closer_ofs = closer - buf;
	closer_len = *buflen - closer_ofs;

	address = buf + srsi->magic_len;
	address_len = closer_ofs - srsi->magic_len;
	if (address_len == 0) {
		syslog (LOG_INFO, "Accepting empty address without change");
		return;
	}

	domain = memrchr (address, '@', address_len);
	if (domain == NULL) {
		syslog (LOG_ERR, "Envelope address without ...@... separator");
		exit (1);
	}
	domain++;
	domain_len = &address [address_len] - domain;

	domi = srsi->wrapper? srsi->domc: 0;
	while (domi-- > 0) {
#ifdef DEBUG
printf ("DEBUG: Comparing #%d len %d so \"%.*s\" plus 0x%02x to \"%.*s\"\n", domi, domain_len, domain_len, srsi->domv [domi], domain_len, srsi->domv [domi] [domain_len], domain);
#endif
		if ((strncasecmp (srsi->domv [domi], domain, domain_len) == 0)
					&& (srsi->domv [domi] [domain_len] == '\0')) {
			syslog (LOG_DEBUG, "Not wrapping MAIL FROM:<...@%.*s> for SRS", domain_len, domain);
			return;
		}
	}

	*closer = '\0';
	memcpy (newbuf, srsi->magic, srsi->magic_len);
	srsout = srsi->srs_fun (srsi->srs,
			newbuf + srsi->magic_len,
			MAXLEN_BUF - srsi->magic_len - closer_len,
			address,
			srsi->domv [0]);
#ifdef DEBUG
printf ("DEBUG: buf = \"%.*s\"\n", buflen, buf);
printf ("DEBUG: address = \"%s\"\n", address);
printf ("DEBUG: newbuf = \"%s...\"\n", newbuf);
printf ("srsout = %d\n", srsout);
#endif
	if (srsout != SRS_SUCCESS) {
		if (srsout == SRS_ENOTSRSADDRESS) {
			syslog (LOG_ERR, "That was not an SRS address");
		} else {
			syslog (LOG_ERR, "Failure in SRS rewrite operation");
		}
		exit (1);
	}
	srslen = strlen (newbuf + srsi->magic_len);
	*closer = '>';
	memcpy (newbuf + srsi->magic_len + srslen, closer, closer_len);
#ifdef DEBUG
printf ("New buffer is \"%.*s\"\n", srsi->magic_len + srslen + closer_len, newbuf);
#endif

#if 0
	//TODO// LOG_DEBUG output is *rather* hairy, better split?
	if (srsi->wrapper) {
		syslog (LOG_DEBUG, "Wrapped %s...@%.*s> into %sSRS...@%s>", srsi->magic, domain_len, domain, srsi->magic, srsi->domv [0]);
	} else {
		syslog (LOG_DEBUG, "Unwrapped %sSRS...@%.*s> back to %s...@%s>", srsi->magic, domain_len, domain, srsi->magic, srsi->domv [0]);
	}
#endif
	*buflen = srsi->magic_len + srslen + closer_len;
	memcpy (buf, newbuf, *buflen);
}


void filter_smtp (srs_info *srsi, int cli, int rly) {
	struct pollfd polls [2];
	int pollres;
	char buf [MAXLEN_BUF];
	int buflen, outlen;
	int eof = 0;

	polls [0].fd = cli;
	polls [1].fd = rly;
	polls [0].events = POLLIN | POLLHUP | POLLERR;
	polls [1].events = POLLIN | POLLHUP | POLLERR;

	while (eof != 3) {

		pollres = poll (polls, 2, 60000);
		if (pollres == 0) {
			syslog (LOG_ERR, "Terminating after 60 quiet seconds");
			exit (1);
		}
		if (pollres == -1) {
			logperror ("Error from socket polls");
			exit (1);
		}

		if (polls [0].revents == POLLIN) {
			buflen = read (cli, buf, MAXLEN_BUF);
			if (buflen < 0) {
				logperror ("Client receive error");
				exit (1);
			}
			if (buflen == 0) {
				polls [0].events &= ~POLLIN;
				eof |= 1;
				shutdown (cli, SHUT_RD);
			}
#ifdef DEBUG
printf ("DEBUG: Client input of %d bytes: %.*s\n", buflen, buflen, buf);
#endif
			if (buflen > srsi->magic_len) {
				if (strncasecmp (buf, srsi->magic, srsi->magic_len) == 0) {
					rewrite (srsi, buf, &buflen);
				}
			}
			outlen = write (rly, buf, buflen);
			if (outlen < 0) {
				logperror ("Server send error");
				exit (1);
			}
			if (outlen < buflen) {
				syslog (LOG_ERR, "Only %d out of %d bytes accepted by server", outlen, buflen);
				exit (1);
			}
		}

		if (polls [1].revents == POLLIN) {
			buflen = read (rly, buf, MAXLEN_BUF);
			if (buflen < 0) {
				logperror ("Server receive error");
				exit (1);
			}
			if (buflen == 0) {
				polls [1].events &= ~POLLIN;
				eof |= 2;
				shutdown (rly, SHUT_RD);
			}
#ifdef DEBUG
printf ("DEBUG: Relay sent %d bytes: %.*s\n", buflen, buflen, buf);
#endif
			outlen = write (cli, buf, buflen);
			if (outlen < 0) {
				logperror ("Client send error");
				exit (1);
			}
			if (outlen < buflen) {
				syslog (LOG_ERR, "Only %d out of %d bytes accepted by client", outlen, buflen);
				exit (1);
			}
		}

		if ((polls [0].revents | polls [1].revents)
					& (POLLHUP | POLLERR)) {
			if (eof != 3) {
				syslog (LOG_ERR, "Connection terminated prematurely");
				exit (1);
			} else {
				exit (0);
			}
		}

	}
}


int named_socket (int locally, char *listenhost, char *svcport) {
	struct addrinfo *adr, *adrptr;
	int adrerr;
	int sox;
	struct sockaddr_in6 sin;

	adrerr = getaddrinfo (listenhost, svcport, NULL, &adr);
	if (adrerr != 0) {
		syslog (LOG_ERR, "Failed to locate listen host: %s",
				gai_strerror (adrerr));
		exit (1);
	}

	adrptr = adr;
	while (adrptr != NULL) {

		sox = socket (adrptr->ai_family, SOCK_STREAM, 0);
		if (sox == -1) {
			logperror ("Failed to create listening socket");
			exit (1);
		}

		if ((locally? bind: connect)
			(sox, adrptr->ai_addr, adrptr->ai_addrlen) == 0) {
			break;
		}

		close (sox);
		sox = -1;
		adrptr = adrptr->ai_next;
	}

	freeaddrinfo (adr);

	if (sox == -1) {
		syslog (LOG_ERR, "Failed to bind to listening port %s", svcport);
		exit (1);
	}

	if (locally) {
		if (listen (sox, 10) == -1) {
			logperror ("Failed to listen to socket");
			exit (1);
		}
	}

	return sox;
}


int input_socket (char *listenhost, char *svcport) {
	struct addrinfo *adr, *adrptr;
	int adrerr;
	int sox;
	struct sockaddr_in6 sin;

	adrerr = getaddrinfo (listenhost, svcport, NULL, &adr);
	if (adrerr != 0) {
		syslog (LOG_ERR, "Failed to locate listen host: %s",
				gai_strerror (adrerr));
		exit (1);
	}

	adrptr = adr;
	while (adrptr != NULL) {

		sox = socket (adrptr->ai_family, SOCK_STREAM, 0);
		if (sox == -1) {
			logperror ("Failed to create listening socket");
			exit (1);
		}

		if (bind (sox, adrptr->ai_addr, adrptr->ai_addrlen) == 0) {
			break;
		}

		close (sox);
		sox = -1;
		adrptr = adrptr->ai_next;
	}

	freeaddrinfo (adr);

	if (sox == -1) {
		syslog (LOG_ERR, "Failed to bind to listening port %s", svcport);
		exit (1);
	}

	if (listen (sox, 10) == -1) {
		logperror ("Failed to listen to socket");
		exit (1);
	}

	return sox;
}


int output_socket (char *relayhost, char *svcport) {
	struct addrinfo *adr, *adrptr;
	int adrerr;
	int sox;
	struct sockaddr_in6 sin;

	adrerr = getaddrinfo (relayhost, svcport, NULL, &adr);
	if (adrerr != 0) {
		syslog (LOG_ERR, "Failed to locate relay host: %s",
				gai_strerror (adrerr));
		exit (1);
	}

	adrptr = adr;
	while (adrptr != NULL) {

		sox = socket (adrptr->ai_family, SOCK_STREAM, 0);
		if (sox == -1) {
			logperror ("Failed to create relayhost socket");
			exit (1);
		}

		if (connect (sox, adrptr->ai_addr, adrptr->ai_addrlen) == 0) {
			break;
		}

		close (sox);
		sox = -1;
		adrptr = adrptr->ai_next;
	}

	freeaddrinfo (adr);

	if (sox == -1) {
		syslog (LOG_ERR, "Failed to connect to relayhost");
		exit (1);
	}

	return sox;
}


int partner = 0;

void handle_sigchld (int sig) {
	int saved_errno = errno;
	pid_t ended;
	do {
		ended = waitpid ((pid_t) -1, 0, WNOHANG);
		if (ended == partner) {
			syslog (LOG_CRIT, "My major other one terminated, so I shall go too");
			exit (1);
		}
	} while (ended > 0);
	errno = saved_errno;
}

void kill_parent (void) {
	if (partner == getppid ()) {
		kill (partner, SIGINT);
		syslog (LOG_CRIT, "I am exiting, taking my major other one down with me");
	}
}


int main (int argc, char *argv []) {
	int sox, cli, rly;
	int argi;
	struct sigaction sa;
	srs_info srsinfo;
	FILE *keyf;
	char key [130];
	int keylen;
	int keyctr;
	int keyline;

	openlog (basename (argv [0]), LOG_PERROR, LOG_MAIL);

	if (argc < 7) {
		syslog (LOG_ERR, "Usage: %s inaddr wrapport unwrapport outaddr outport localdomain...", argv [0]);
		exit (1);
	}

	syslog (LOG_INFO, "SRS relay deamon started from %s:%s+%s to %s:%s", argv [1], argv [2], argv [3], argv [4], argv [5]);
	for (argi = 6; argi < argc; argi++) {
		syslog (LOG_INFO, "SRS relay daemon local domain %s", argv [argi]);
	}

	sa.sa_handler = &handle_sigchld;
	sigemptyset (&sa.sa_mask);
	sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
	if (sigaction (SIGCHLD, &sa, 0) == -1) {
		logperror ("Failed to register zombie cleanup handler");
		exit (1);
	}

	memset (&srsinfo, 0, sizeof (srsinfo));
	srsinfo.srs = srs_new ();
	if (srsinfo.srs == NULL) {
		syslog (LOG_ERR, "Failed to allocate SRS context");
		exit (1);
	}

	keyf = fopen ("/etc/postfix/srs-keys", "r");
	if (keyf == NULL) {
		logperror ("Failed to open SRS keyfile");
		exit (1);
	}
	keyctr = 0;
	keyline = 0;
	while (!feof (keyf)) {
		if (fgets (key, sizeof (key) - 1, keyf) == NULL) {
			continue;
		}
		keyline++;
		if (key [0] == '\0') {
			continue;
		}
		if (key [0] == '\n') {
			continue;
		}
		if (key [0] == '#') {
			continue;
		}
		keylen = strlen (key);
		if (keylen > 128) {
			syslog (LOG_CRIT, "Key of length > 128 is too confusing on line %d", keylen, keyline);
			exit (1);
		}
		if (keylen < 16) {
			syslog (LOG_CRIT, "Key of length %d < 16 disapproved on line %d", keylen, keyline);
			exit (1);
		}
		if (key [keylen - 1] != '\n') {
			syslog (LOG_CRIT, "Key not followed by newline on line %d", keyline);
			exit (1);
		}
		key [keylen - 1] = '\0';
		srs_add_secret (srsinfo.srs, key);
		keyctr++;
	}
	fclose (keyf);
	syslog (LOG_INFO, "Loaded %d keys from %d lines into SRS Relay", keyctr, keyline);
	if (keyctr == 0) {
		syslog (LOG_CRIT, "You need to setup at least one key");
		exit (1);
	}
	if (keyctr == 2) {
		syslog (LOG_WARNING, "Temporarily running with 2 keys (double guessing opportunity for crackers)");
	}
	if (keyctr > 2) {
		syslog (LOG_CRIT, "You should try to use as few SRS keys as possible, 1 is ideal and 2 bearable");
	}

	switch (partner = fork ()) {
	case -1:
		logperror ("Failed to split my brain");
		exit (1);
	case 0:
		// The parent wraps email into SRS format
		partner = getppid ();
		atexit (kill_parent);
		srsinfo.wrapper = 1;
		srsinfo.magic = WRAP_MAGIC;
		srsinfo.magic_len = WRAP_MAGIC_LEN;
		srsinfo.srs_fun = srs_forward;
		break;
	default:
		// The child unwraps email from SRS format
		srsinfo.wrapper = 0;
		srsinfo.magic = UNWRAP_MAGIC;
		srsinfo.magic_len = UNWRAP_MAGIC_LEN;
		srsinfo.srs_fun = srs_reverse_unified;
		break;
	}
	srsinfo.domv = argv + 6;
	srsinfo.domc = argc - 6;

	// sox = input_socket (argv [1], srsinfo.wrapper? argv [2]: argv [3]);
	sox = named_socket (1, argv [1], srsinfo.wrapper? argv [2]: argv [3]);
#ifdef DEBUG
printf ("DEBUG: Listening to input socket %d\n", sox);
#endif
	while (cli = accept (sox, NULL, NULL), cli != -1) {
#ifdef DEBUG
printf ("DEBUG: Accepted on input socket %d\n", cli);
#endif
		// rly = output_socket (argv [4], argv [5]);
		rly = named_socket (0, argv [4], argv [5]);
#ifdef DEBUG
printf ("DEBUG: Connected to output socket %d\n", rly);
#endif
		switch (fork ()) {
		case -1:
			logperror ("Failed to fork for client connection");
			exit (1);
		case 0:
			// child was forked
			filter_smtp (&srsinfo, cli, rly);
			exit (0);
		default:
			// parent succeeded at forking the child
			close (cli);
			close (rly);
			continue;
		}
	}

}
