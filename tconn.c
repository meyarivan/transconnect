/* TransConnect : A function imposter to allow transparent connection to the
 * internet over HTTPS proxy like squid.
 * 
 * Copyright (C) 2001, Dwivedi Ajay kumar <adwiv at yahoo dot com>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 * or visit http://www.gnu.org/copyleft/gpl.html
 * 
 * Credits:
 *    Raja Subramanian : for pointing me to the imposter method.
 *    
 *    Linux India Mailing List : A place where all your questions get 
 *         answered within no time.
 *    
 *    Jared D. McNeil  : for helping me with port to NetBSD
 *    
 *    Harald Fielker and Sebastian Stark : for providing patches for
 *    					                   OpenBSD.
 *         
 *         
 */


/* Set this to 1 if you want to TCONN_DEBUG your connection */
#ifdef TCONN_DEBUG
#undef TCONN_DEBUG
#endif 
#define TCONN_DEBUG 0

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<strings.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<netdb.h>
#include<unistd.h>
#include<errno.h>
#include<dlfcn.h>
#include<pwd.h>
#include<signal.h>
#include<fcntl.h>
#include<resolv.h>

#define barrier()              __asm__ __volatile__("":::"memory")

/* Maximum no of local networks you can have in config file */
#define MAX_LOCAL_NETS 20

/* Maximum length of config file pathname */
#define CONFIG_FILE_MAX 1024

/* Default Config File in home directory */
/* This path is appended to the Home Direcroty */
#define CONFIG_FILE_DEFAULT  "/.tconn/tconn.conf"

/* True and False */
#ifdef TCONN_FALSE
#undef TCONN_FALSE
#endif 
#define TCONN_FALSE 0

#ifdef TCONN_TRUE
#undef TCONN_TRUE
#endif 
#define TCONN_TRUE 1

/* Some people using RH7 and Suse7.1 are having problems without this */
#ifndef RTLD_NEXT
#define RTLD_NEXT       ((void *) -1l)
#endif /* !RTLD_NEXT */

/* Comptibility with BSD */
#ifdef _BSD_HACK_
#include "libcpath.h"
#endif /* _BSD_HACK_ */

 /* This TCONN_MATCH is taken directly from glibc resolver. */

#ifdef TCONN_MATCH
#undef TCONN_MATCH
#endif /* TCONN_MATCH */
#define TCONN_MATCH(line, name) \
      (!strncmp(line, name, sizeof(name) - 1) && \
       (line[sizeof(name) - 1] == ' ' || \
       line[sizeof(name) - 1] == '\t'))


/* This structure represents a subnet */
struct my_network
{
  int valid;
  struct in_addr subnetwork;
  struct in_addr subnetmask;
};


/* Function to encode the user passwd into base64 . It has a wierd name 
 * Just to make sure this never conflicts with any function call */
void ajayd_tconn_base64_encode (const char *s, char * p);


/* The connect function we are overriding. The function signature 
 * must be the same as the original function. */
int connect (int sockfd, const struct sockaddr *serv_addr, socklen_t addrlen)
{

  char 	proxyserv[20];			/* The proxyserver to use. */
  int  	proxyport;			/* The proxyport on proxy server */
  char 	proxyauth[90];			/* Some proxies need authorisation */
  char 	proxyuser[20];			/* Proxy User name */
  char 	proxypass[40];			/* Proxy Password */
  char 	useragent[100];			/* User-Agent String */
  int 	proxyservset = TCONN_FALSE;	/* Proxy Server is set or not */
  int 	proxyportset = TCONN_FALSE;	/* Proxy Port is set or not */
  int 	proxyuserset = TCONN_FALSE;	/* Proxy Username is set or not*/
  int 	proxypassset = TCONN_FALSE;	/* Proxy Password is set or not*/
  int 	useragentset = TCONN_FALSE;	/* User Agent is set or not*/
  int 	localnetset = TCONN_FALSE;	/* Local Network is set or not */
  int 	isonlocalnet = TCONN_FALSE;	/* This IP is on local network or not*/

  
  struct my_network localnet[MAX_LOCAL_NETS];	/* Array of subnets on the local */
						/* network : ie accessible directly */
  int lnnum = 0;			/* A number to count valid localnetworks. */

  char buf[100], *cp;			/* Some Buffers */

    // FIXUP: configfile[CONFIG_FILE_MAX] will be accessed several times
  char configfile[CONFIG_FILE_MAX+1];	/* Name of the configuration file */
  char *tconn_env;			/* Environment Variable path for Config File */
  FILE *fp;				/* For opening config file */
  
  static int (*func) ();		/* The function we are overriding :-) */
					/* It has been made static to avoid lookup of libc repeatedly */

  int uid;				/* User id */
  struct passwd *pwent;			/* Needed for reading the password file to extract home directory */
  
  int optval;				/* Options for socket */
    // FIXUP: avoid compiler warning about bad signess
  socklen_t optlen;

#ifdef _BSD_HACK_
  static void *handle;			/* On BSD we can't use RTLD_NEXT. So we need a handle to libc */
#endif /* _BSD_HACK_ */



/* We get a pointer to the original connect function we are overriding. */
  if (!func)
  {
#ifdef _BSD_HACK_
    /* On BSD we open the libc and retrive the pointer to connect function from it */
    handle = dlopen(TCONN_LIBC_PATH, RTLD_LAZY);
    func = (int (*)()) dlsym (handle, "connect");
#else
    /* On linux/Sun we can set func to next instance of connect, which is the original connect*/
    func = (int (*)()) dlsym (RTLD_NEXT, "connect");
#endif
  }

   optlen = sizeof (int);

  /* We want only Internet TCP sockets to use our method. Proxies can't be used
   * for UDP and file sockets. */

  getsockopt (sockfd, SOL_SOCKET, SO_TYPE, &optval, &optlen);

  if (optval != SOCK_STREAM || serv_addr->sa_family != AF_INET)
  {
      if (TCONN_DEBUG) 
	 fprintf (stderr, "Wrong socket type for routing\n"
	       "optval == %d sa_family == %d optlen == %d \n"
	       "whereas \n"
	       "stream == %d AF_INET == %d optlen ==%zu \n ",
	       optval, serv_addr->sa_family, optlen,
	       SOCK_STREAM, AF_INET, sizeof (optval));
      /* This was not a TCP stream socket so we connect using the original function */
      goto directconnect;
  }


  /* Extract the Environment Variable, and see if the config file path is set */
  tconn_env = getenv("TCONN");
    // FIXUP: ignore empty $TCONN env
  if (tconn_env != NULL && *tconn_env) 
  {
      /* use config file name from environment variable */
      strncpy (configfile, tconn_env, CONFIG_FILE_MAX);
      configfile[CONFIG_FILE_MAX] = '\0';
  }
  else
  {
          // FIXUP: variables needed for getpwuid_r; the variable array-size is
          //        valid standard C...
	long const	sz = sysconf(_SC_GETPW_R_SIZE_MAX);
        struct passwd	pwent_buf;
        char		tmp[sz==-1 ? 1024 : sz];
      	/* no environment variable set up - default to ~/.tconn/tconn.conf */
      	/* We Extract the users home directory from password file */

	/* Add the default file path to home directory to get the absolute path */
        uid = getuid ();

	  // FIXUP: getpwuid(3) is not thread-safe
	if (getpwuid_r(uid, &pwent_buf, tmp, sizeof tmp, &pwent)!=-1)
  	{
	     strncpy (configfile, pwent->pw_dir, CONFIG_FILE_MAX -
			     (sizeof(CONFIG_FILE_DEFAULT) + 1));
             configfile[CONFIG_FILE_MAX - (sizeof(CONFIG_FILE_DEFAULT) + 1)] = '\0';

	     strncat (configfile, CONFIG_FILE_DEFAULT,
			     (sizeof(CONFIG_FILE_DEFAULT) + 1));
	     configfile[CONFIG_FILE_MAX] = '\0';
  	}
  	else
  	{
            /* Ok Ok.. Goto's are bad, But is just a bit easy here. May change Later. */
      	    fprintf (stderr, "You do not exist\n");
      	    goto directconnect;
  	}
  }

  if (TCONN_DEBUG) fprintf (stderr, "Configfile is %s\n", configfile);
  /* We now open the config file */
  if ((fp = fopen (configfile, "r")) != NULL)
  {
      if (TCONN_DEBUG) fprintf (stderr, "reading %s\n", configfile);
  }
  else
  {
      fprintf(stderr,"Transconnect: Could not open the config file %s\n",configfile);
      goto directconnect;
  }

  /* Now we read the config file and extract parameters from it */
  /* It might look a bit cryptic but it works :) */
  while (fgets (buf, 100, fp) != NULL)
  {
      if (*buf == '#')		/* Leave the comments */
	continue;

      if (TCONN_MATCH (buf, "proxyserv")) /* Extract the server name*/
      {
	  cp = buf + sizeof ("proxyserv") - 1;
	  while (*cp == ' ' || *cp == '\t')
	    cp++;
	  if ((*cp == '\0') || (*cp == '\n'))
	    continue;
	  if (index (cp, '\n') != NULL)
	    *index (cp, '\n') = '\0';

	  if (inet_addr (cp) != -1)	/* this can return -1 for 255.255.255.255 too */
	  {				/* But its impossible address for a proxy server */
	      struct in_addr proxy_addr;
	      proxyservset = TCONN_TRUE;
	      proxy_addr.s_addr = inet_addr (cp);
	      strncpy (proxyserv, inet_ntoa (proxy_addr), 16);
	      if (TCONN_DEBUG) fprintf (stderr, "proxyserver is %s\n", proxyserv);
	  }
	  else
	    fprintf (stderr, "%s: proxyserv: "
		     "Only IP addresses are allowed\n", configfile);
      }

      if (TCONN_MATCH (buf, "proxyport")) /* Extract the port number */
      {
	  cp = buf + sizeof ("proxyport") - 1;
	  while (*cp == ' ' || *cp == '\t')
	    cp++;
	  if ((*cp == '\0') || (*cp == '\n'))
	    continue;
	  if (index (cp, '\n') != NULL)
	    *index (cp, '\n') = '\0';

	  if ((proxyport = atoi (cp)) != 0)
	  {
	      proxyportset = TCONN_TRUE;
	      if (TCONN_DEBUG) fprintf (stderr, "proxyport is %d\n", proxyport);
	  }
      }

      if (TCONN_MATCH (buf, "proxyuser"))
      {
	  cp = buf + sizeof ("proxyuser") - 1;
	  while (*cp == ' ' || *cp == '\t')
	    cp++;
	  if ((*cp == '\0') || (*cp == '\n'))
	    continue;
	  if (index (cp, '\n') != NULL)
	    *index (cp, '\n') = '\0';
	  /* The proxyuser is in quotes */
	  if (*cp != '\"')
	  {
	      fprintf (stderr,
		       "%s : proxyuser does not start with double quote \n",
		       configfile);
	      continue;
	  }
	  cp++;
	  if (rindex (cp, '\"') != NULL)
	    *rindex (cp, '\"') = '\0';
	  else
	  {
	      fprintf (stderr,
		       "%s : proxyuser does not end with double quote \n",
		       configfile); continue;
	  }
	  proxyuserset = 1;
	  strncpy (proxyuser, cp, 19);
	  /* Prevent possible buffer overflow */
	  proxyuser[19] = '\0';
	  if (TCONN_DEBUG) fprintf (stderr, "proxyuser is \"%s\"\n", proxyuser);
      }

      if (TCONN_MATCH (buf, "proxypass"))
      {
	  cp = buf + sizeof ("proxypass") - 1;

	  while (*cp == ' ' || *cp == '\t')
	    cp++;
	  if ((*cp == '\0') || (*cp == '\n'))
	    continue;
	  if (index (cp, '\n') != NULL)
	    *index (cp, '\n') = '\0';
	  /* The proxypass is in quotes */
	  if (*cp != '\"')
	  {
	      fprintf (stderr,
		       "%s : proxypass does not start with double quote \n",
		       configfile); continue;
	  }
	  cp++;
	  if (rindex (cp, '\"') != NULL)
	    *rindex (cp, '\"') = '\0';
	  else
	  {
	      fprintf (stderr,
		       "%s : proxypass does not end with double quote",
		       configfile);
	      continue;
	  }
	  proxypassset = 1;
	  strncpy (proxypass, cp, 39);
	  /* Prevent possible buffer overflow */
	  proxypass[39] = '\0';
	  if (TCONN_DEBUG) fprintf (stderr, "proxypass is \"%s\"\n", proxypass);
      }
      if (TCONN_MATCH (buf, "useragent"))
      {
          cp = buf + sizeof ("useragent") - 1;
          while (*cp == ' ' || *cp == '\t')
                cp++;
          if ((*cp == '\0') || (*cp == '\n'))
                continue;
          if (index (cp, '\n') != NULL)
                *index (cp, '\n') = '\0';

          useragentset = TCONN_TRUE;
	  strncpy(useragent , cp, 99);
	  useragent[99] = '\0';
          if (TCONN_DEBUG) fprintf (stderr, "useragent is %s\n", useragent);
      }

	// FIXUP: localnet[0].valid might be used uninitialized else
      localnet[0].valid = TCONN_FALSE;
	// FIXUP: localnet[lnnum+1] will be accessed below
      if (TCONN_MATCH (buf, "localnet") && lnnum+1 < MAX_LOCAL_NETS)
      {
	  cp = buf + sizeof ("localnet") - 1;
	  while (*cp == ' ' || *cp == '\t')
	    cp++;
	  if ((*cp == '\0') || (*cp == '\n'))
	    continue;
	  if (index (cp, '\n') != NULL)
	    *index (cp, '\n') = '\0';
	  if (index (cp, '/') != NULL)
	  {
	      localnetset = TCONN_TRUE;
	      /* If error inet_ntoa return is same as for  255.255.255.255 */
	      localnet[lnnum].subnetmask.s_addr = inet_addr (index (cp, '/') + 1);

	      if (TCONN_DEBUG) fprintf (stderr, "Subnetmask is %s\n",
			   inet_ntoa (localnet[lnnum].subnetmask));

	      *index (cp, '/') = '\0';
	      localnet[lnnum].subnetwork.s_addr = inet_addr (cp);

	      if (TCONN_DEBUG) fprintf (stderr, "Subnetwork is %s\n",
			   inet_ntoa (localnet[lnnum].subnetwork));

	      localnet[lnnum].valid = TCONN_TRUE;
	      localnet[lnnum + 1].valid = TCONN_FALSE;
	      lnnum++;
	  }
      }
  } 

    // FIXUP: 'buf' might still contain password data
  memset(buf, 0, sizeof buf);
  barrier();
  
  /* Close the config file now */
  fclose(fp);

  /* Now we check if the IP we have to connect to is on local network */
  for (lnnum = 0; localnet[lnnum].valid == TCONN_TRUE; lnnum++)
  {
    if ((((struct sockaddr_in *) serv_addr)->sin_addr.s_addr &
	   inet_addr (inet_ntoa (localnet [lnnum].subnetmask)))
	  == inet_addr (inet_ntoa (localnet[lnnum].subnetwork)))
    {
	  /* So it is on local network. Set the flag */
	  isonlocalnet = TCONN_TRUE;
	  break;
    }
  }

  if(TCONN_DEBUG) fprintf(stderr,"Connecting to %s\n"
		"isonlocalnet == %d\n"
		"proxyservset == %d\n"
		"proxyportset == %d\n"
		"localnetset  == %d\n",inet_ntoa(((struct sockaddr_in *)
		serv_addr)->sin_addr),isonlocalnet,proxyservset,
		proxyportset,localnetset);

  /* Check if the connection should be through proxy. For this we
   * must make sure that the host is not on localnet, proxyserver
   * and proxyport are set and localnet is set */
  if (!isonlocalnet && proxyservset && proxyportset && localnetset)
  {
      struct sockaddr_in proxyaddr;	/* proxy address */
      char  connectbuf[100];		/* Buffer */
      int   connectbuflen;		/* length */
      char  authbuf[120];		/* Buffer */
      int   authbuflen;			/* length */
	// FIXUP: added space for HTTP header
      char  useragentbuf[120];		/* Buffer */
      int   useragentbuflen;		/* length */
      char  headerbuf[1000];		/* Buffer */
      int   hbuflen;			/* length */

      char  recvchar;			/* Character buffer */
      void  (*oldpipehandler)(int);	/* SIGPIPE Handler function */
      void  (*oldtimehandler)(int);	/* Timeout Handler function */
      int   flags;			/* Flags for socket */

      /* Ignore the signals for SIGPIPE and SIGALRM */
      /* We will reset these signals when we return */
      oldpipehandler = signal (SIGPIPE, SIG_IGN);
      oldtimehandler = signal (SIGALRM, SIG_IGN);

      /* Make the socket Blocking */
      flags = fcntl(sockfd, F_GETFL);
      fcntl(sockfd,F_SETFL,!O_NONBLOCK);

      /* Set up the proxy address structre */
      proxyaddr.sin_family = AF_INET;
      proxyaddr.sin_port = htons (proxyport);
      proxyaddr.sin_addr.s_addr = inet_addr (proxyserv);
      bzero (&(proxyaddr.sin_zero), 8);

      /* Connect to the proxy:port . Here we are using the original connect
       * function to connect to the proxy*/
      if (func (sockfd, (struct sockaddr *) &proxyaddr, sizeof (struct sockaddr)) != 0)
      {
	  signal(SIGPIPE,oldpipehandler);
	  signal(SIGALRM,oldtimehandler);
          fcntl(sockfd,F_SETFL,flags);
          fprintf(stderr,"Can't connect to proxy, See that your "
		"proxy settings are correct.\n");
	  errno = ECONNREFUSED;
	  return -1;
      }

      if (TCONN_DEBUG) fprintf (stderr, "Through proxy\n");

      /* We are now connected to the proxy. Now send the CONNECT request */
      connectbuflen = snprintf (connectbuf, 100, "CONNECT %s:%d HTTP/1.0\r\n",
				inet_ntoa (((struct sockaddr_in *)serv_addr)->sin_addr),
				ntohs (((struct sockaddr_in *)serv_addr)->sin_port));

      /* Reset the signals and return if there is an error */
      if (send (sockfd, connectbuf, connectbuflen, 0) != connectbuflen)
      {
	  signal(SIGPIPE,oldpipehandler);
	  signal(SIGALRM,oldtimehandler);
          fcntl(sockfd,F_SETFL,flags);
	  errno = ECONNREFUSED;
	  return -1;
      }

      if (TCONN_DEBUG) fprintf (stderr, "%s", connectbuf);
      
      /* If proxypasswd and proxyuser are set we are using authentication*/
      /* Only Basic Base-64 is supported now. If you need any, send me details */
      if (proxypassset && proxyuserset)
      {
           char authstring[60];
           strncpy(authstring,proxyuser,19);
	   strncat(authstring,":",2);
	   strncat(authstring,proxypass,39);

	     // FIXUP: override authorization information as not needed anymore
	   memset(proxyuser, 0, sizeof proxyuser);
	   memset(proxypass, 0, sizeof proxypass);
	   barrier();
	   
	   if (TCONN_DEBUG) fprintf (stderr, " authstring is %s\n", authstring);
	   /* Encode the uasername and password */
       	   ajayd_tconn_base64_encode(authstring,proxyauth);
	   
	     // FIXUP: override authorization information as not needed anymore
	   memset(authstring, 0, sizeof authstring);
	   barrier();

	   authbuflen = snprintf (authbuf, 120,
		      "Proxy-Authorization: Basic %s\r\n", proxyauth);

	     // FIXUP: override authorization information as not needed anymore
	   memset(proxyauth, 0, sizeof proxyauth);
	   barrier();
	   
      	   /* Reset the signals and return if there is an error */
	   if (send (sockfd, authbuf, authbuflen, 0) != authbuflen)
	   {
	        // FIXUP: override authorization information
	      memset(authbuf, 0, sizeof authbuf);
	      barrier();
	      signal(SIGPIPE,oldpipehandler);
	      signal(SIGALRM,oldtimehandler);
              fcntl(sockfd,F_SETFL,flags);
	      errno = ECONNREFUSED;
	      return -1;
	   }
	   
	   if (TCONN_DEBUG) fprintf (stderr, "%s", authbuf);

	     // FIXUP: override authorization information as not needed anymore
	   memset(authbuf, 0, sizeof authbuf);
	   barrier();
      }	

      /* Send the User-Agent String if set */
      if (useragentset)
      {
	  // FIXUP: use 'sizeof ...' instead of numeric size
	  useragentbuflen = snprintf (useragentbuf, sizeof useragentbuf,
		      "User-Agent: %s\r\n", useragent);
          /* Reset the signals and return if there is an error */  
	  if (send (sockfd, useragentbuf, useragentbuflen, 0) != useragentbuflen)
	  {
	      signal(SIGPIPE,oldpipehandler);
	      signal(SIGALRM,oldtimehandler);
              fcntl(sockfd,F_SETFL,flags);
	      errno = ECONNREFUSED;
	      return -1;
	  }

	  if (TCONN_DEBUG) fprintf (stderr, "%s", useragentbuf);
      }

      /* Send the Keep-Alive and No-Cache headers. Just to meke sure */
      /* Reset the signals and return if there is an error */
      if (send (sockfd, "Proxy-Connection: Keep-Alive\r\n", 30, 0) != 30)
      {
	  signal(SIGPIPE,oldpipehandler);
	  signal(SIGALRM,oldtimehandler);
          fcntl(sockfd,F_SETFL,flags);
	  errno = ECONNREFUSED;
	  return -1;
      }
      if (TCONN_DEBUG) fprintf (stderr, "%s", "Proxy-Connection: Keep-Alive\r\n");

      if (send (sockfd, "Pragma: no-cache\r\n", 18, 0) != 18)
      {
	  signal(SIGPIPE,oldpipehandler);
	  signal(SIGALRM,oldtimehandler);
          fcntl(sockfd,F_SETFL,flags);
	  errno = ECONNREFUSED;
	  return -1;
      }
      if (TCONN_DEBUG) fprintf (stderr, "Pragma: no-cache\r\n");

      /* All Necessary headers have been sent. So we send a blank newline */
      /* to tell the server we are done */
      if (send (sockfd, "\r\n", 2, 0) != 2)
      {
	  signal(SIGPIPE,oldpipehandler);
	  signal(SIGALRM,oldtimehandler);
          fcntl(sockfd,F_SETFL,flags);
	  errno = ECONNREFUSED;
	  return -1;
      }

      if (TCONN_DEBUG) fprintf (stderr, "\r\n");

      /* Now we will start reading the headers from the proxy */
      /* These headers will indicate if the connection was established */
      hbuflen = 0;

      while (1)
      {
	  /* Receive one character */
	  if (recv (sockfd, &recvchar, 1, 0) != 1)
	  {
	      signal(SIGPIPE,oldpipehandler);
	      signal(SIGALRM,oldtimehandler);
              fcntl(sockfd,F_SETFL,flags);
	      errno = ETIMEDOUT;
	      return -1;
	  }
	  /* We don;t expect proxy to send so many headers */
	    // FIXUP: [buflen+2] will be accessed below, so use 'sizeof ...' 
	    //        and avoid numeric sizes
	  if (hbuflen+2 == sizeof(headerbuf))	/* This means only junk is coming. */
	  {
	      signal(SIGPIPE,oldpipehandler);
	      signal(SIGALRM,oldtimehandler);
              fcntl(sockfd,F_SETFL,flags);
	      errno = ETIMEDOUT;
	      return -1;
	  }

	  /* Copy the character into the header */
	  headerbuf[hbuflen] = recvchar;

	  /* If the proxy sends two linefeed-carriagereturns */
	  /* It means it has sent all the headers */
	  if (hbuflen > 1 && (headerbuf[hbuflen] == '\n'
		  && headerbuf[hbuflen - 2] == '\n'))
	    break;
	  hbuflen++;
      }

	
      /* We now have the complete header */
      /* Reset the signals on the socket */
      signal(SIGPIPE,oldpipehandler);
      signal(SIGALRM,oldtimehandler);
      fcntl(sockfd,F_SETFL,flags);

      /* I don't know why but the header was not getting printed with only one '\0' */
      headerbuf[hbuflen + 1] = headerbuf[hbuflen + 2] = '\0';

      if (TCONN_DEBUG) fprintf (stderr, "\nHeaders are:\n%s", headerbuf);

      /* Check the proxy's return status */
      if(index (headerbuf, '\n') != NULL)
      {
          *index (headerbuf, '\n') = '\0'; 
	   
	  if(strstr(headerbuf, "200") != NULL)
          {
	  	if (TCONN_DEBUG) fprintf (stderr, "Received 200 OK from proxy\n");
	  	errno = 0;
	  	return 0;
      	  }
          else if (strstr(headerbuf, "407") != NULL)
          {
	  	fprintf (stderr, "Hey, Your proxy Authentication is not Working.\n");
	  	errno = ECONNREFUSED;
	  	return -1;
      	  }
          else
          {
	  	fprintf (stderr, "Connection Refused: %s\n", headerbuf+13);
	  	errno = ECONNREFUSED;
	  	return -1;
          }
      } 
      else
      {
	 fprintf (stderr, "Invalid return from Proxy: %s\n", headerbuf);
	 errno = ECONNREFUSED;
	 return -1;
      }
  }

  /* The label for direct connection. We use goto to reach here from many places */

directconnect:

  if (TCONN_DEBUG) fprintf (stderr, "Direct connection\n");
	/* Check if the dynamic linking is working */
	/* If it is not working func may be either NULL */
	/* or same as connect itself when it would go into */
	/* an infinite loop and cause segmentation fault */
	if(func != NULL  && func != connect )
    	return func (sockfd, serv_addr, addrlen);
	else
	{
		fprintf(stderr,"Dynamic Linking is not working\n If you are on BSD"
		"Did you specify the correct libc file during installation\n");
		errno = ENETUNREACH;
		return -1;
	}
}


/* Function to create a base 64 encoded string */
/* Just to make sure that the name does not interfere with any other function */

void ajayd_tconn_base64_encode (const char *s, char * p)
{
        char tbl[64] = {
                'A','B','C','D','E','F','G','H',
                'I','J','K','L','M','N','O','P',
                'Q','R','S','T','U','V','W','X',
                'Y','Z','a','b','c','d','e','f',
                'g','h','i','j','k','l','m','n',
                'o','p','q','r','s','t','u','v',
                'w','x','y','z','0','1','2','3',
                '4','5','6','7','8','9','+','/'
        };
        int i,length;
        
        length = strlen(s);

        for (i = 0; i < length; i += 3)
        {
                *p++ = tbl[s[0] >> 2];
                *p++ = tbl[((s[0] & 3) << 4) + (s[1] >> 4)];
                *p++ = tbl[((s[1] & 0xf) << 2) + (s[2] >> 6)];
                *p++ = tbl[s[2] & 0x3f];
                s += 3;
        }
        if (i == length + 1)
                *(p - 1) = '=';
        else if (i == length + 2)
                *(p - 1) = *(p - 2) = '=';
        *p = '\0';
}

#ifdef  USE_LOCAL_RESOLV_CONF
/* Use local resolv.conf instead of the global one.
 * Useful only if you don't have root access and 
 * Your sysadmin won't budge */

FILE *fopen (const char *path, const char *mode)
{
	static FILE*(*fopenfunc)() = NULL;
	if(!fopenfunc)
		fopenfunc = (FILE* (*)()) dlsym (RTLD_NEXT, "fopen");

	/* Call to open /etc/resolv.conf 
	 * We try to open the local resolv.conf instead
	 * If it does not exit, fallback to global one */
	if(strcmp(_PATH_RESCONF,path)==0)
	{
		char * home = getenv("HOME");
		char * conf = "/.tconn/resolv.conf";
		if(home!=NULL)
		{
			int len = strlen(home) + strlen(conf) + 1;
			char * localconf = (char*)calloc(len,sizeof(char));
			FILE * fp;
			strcpy(localconf,home);
			strcat(localconf,conf);
			fp = fopenfunc(localconf,mode);
			if(fp != NULL)
			{
				free(localconf);
				return fp;
			}
			perror(localconf);
			fprintf(stderr,"Unable to open %s, trying %s instead\n",localconf, path);
			free(localconf);
		}
	}


	return fopenfunc(path,mode);	
}
#endif

#ifdef USE_TCP_FOR_DNS
/* Use TCP for dns queries *
 * Used with connect() can be used to
 * Query DNS records over the proxy */
int res_init()
{
	static int (*res_init_func)() = NULL;
	int retval;
	
	if (TCONN_DEBUG) fprintf(stderr,"\n\nres_init called\n\n");
	if(!res_init_func)
		res_init_func = (int (*)()) dlsym (RTLD_NEXT,"res_init");
	if(!res_init_func)
		return -1;
	retval = res_init_func();
	_res.options |= RES_USEVC;
	return retval;
}

struct hostent *gethostbyname(const char *name)
{
	static struct hostent* (*gethostbyname_func)() = NULL;
	//struct hostent *retval;

	if (TCONN_DEBUG) fprintf(stderr,"gethostbyname called\n");
	if(!gethostbyname_func)
		gethostbyname_func = (struct hostent* (*)()) dlsym (RTLD_NEXT,"gethostbyname");

	res_init();

	_res.options |= RES_USEVC;

	if(!gethostbyname_func)
	{
		fprintf(stderr,"Could not find the original gethostbyname function\n");
		return NULL;
	}
	else
		return gethostbyname_func(name);
}

struct hostent *gethostbyaddr(const void *addr, socklen_t len, int type)
{
	static struct hostent * (*gethostbyaddr_func)() = NULL;
	if (TCONN_DEBUG) fprintf(stderr,"gethostbyaddr called\n");
	if(!gethostbyaddr_func)
		gethostbyaddr_func = (struct hostent* (*)()) dlsym(RTLD_NEXT,"gethostbyaddr");

	res_init();
	_res.options |= RES_USEVC;

	if(!gethostbyaddr_func)
	{
		fprintf(stderr,"Could not find the original gethostbyaddr function\n");
		errno = NO_RECOVERY;
		return NULL;
	}
	else
		return gethostbyaddr_func(addr,len,type);
}
#endif
