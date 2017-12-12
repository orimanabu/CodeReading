# Forward先のupstream DNSサーバが複数のときの挙動

- RHEL7.4
- OCP3.6
- dnsmasq-2.76-2.el7_4.2.src.rpm

# ログ

- log_query有効化

```
[ori@ocp36-master1 ~]$ dig ocp36-lb.example.com

; <<>> DiG 9.9.4-RedHat-9.9.4-51.el7 <<>> ocp36-lb.example.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 49646
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 2

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;ocp36-lb.example.com.          IN      A

;; ANSWER SECTION:
ocp36-lb.example.com.   60      IN      A       172.16.99.20

;; AUTHORITY SECTION:
example.com.            60      IN      NS      ns.example.com.

;; ADDITIONAL SECTION:
ns.example.com.         60      IN      A       172.16.99.11

;; Query time: 1 msec
;; SERVER: 172.16.99.21#53(172.16.99.21)
;; WHEN: Tue Dec 12 10:25:22 JST 2017
;; MSG SIZE  rcvd: 98

[ori@ocp36-master1 ~]$
```

```
Dec 12 10:25:22 ocp36-master1.osetest.local dnsmasq[77783]: query[A] ocp36-lb.example.com from 172.16.99.21
Dec 12 10:25:22 ocp36-master1.osetest.local dnsmasq[77783]: forwarded ocp36-lb.example.com to 172.16.99.11
Dec 12 10:25:22 ocp36-master1.osetest.local dnsmasq[77783]: reply ocp36-lb.example.com is 172.16.99.20
```

# ログを出しているところ

- log\_query() @src/cache.c

```
void log_query(unsigned int flags, char *name, struct all_addr *addr, char *arg)
{
  char *source, *dest = daemon->addrbuff;
  char *verb = "is";

(snip)

  else if (flags & F_SERVER)
    {
      source = "forwarded";
      verb = "to";
    }

(snip)

  if (option_bool(OPT_EXTRALOG))
    {
      int port = prettyprint_addr(daemon->log_source_addr, daemon->addrbuff2);
      if (flags & F_NOEXTRA)
        my_syslog(LOG_INFO, "* %s/%u %s %s %s %s", daemon->addrbuff2, port, source, name, verb, dest);
      else
        my_syslog(LOG_INFO, "%u %s/%u %s %s %s %s", daemon->log_display_id, daemon->addrbuff2, port, source, name, verb, dest);
    }
  else
    my_syslog(LOG_INFO, "%s %s %s %s", source, name, verb, dest);
}
```

- F\_SERVERでlog\_query()を呼んでいるところ

  - tcp\_request() @src/forward.c

```c
                      /* get query name again for logging - may have been overwritten */
                      if (!(gotname = extract_request(header, (unsigned int)size, daemon->namebuff, &qtype)))
                        strcpy(daemon->namebuff, "query");

(snip)

                      if (last_server->addr.sa.sa_family == AF_INET)
                        log_query(F_SERVER | F_IPV4 | F_FORWARD, daemon->namebuff,
                                  (struct all_addr *)&last_server->addr.in.sin_addr, NULL);
```

  - forward\_query() @src/forward.c

```c
                  if (!gotname)
                    strcpy(daemon->namebuff, "query");
                  if (start->addr.sa.sa_family == AF_INET)
                    log_query(F_SERVER | F_IPV4 | F_FORWARD, daemon->namebuff,
                              (struct all_addr *)&start->addr.in.sin_addr, NULL);
```

# tcp\_request()

tcp\_request()が呼ばれるのは下記2通りのパス。

- main() → check\_dns\_listeners() → tcp\_request()
- address\_allocate() → icmp\_ping() → check\_dns\_listeners() → tcp\_request()

## main() → check\_dns\_listeners() → tcp\_request()

```c
#ifdef HAVE_DBUS
      /* if we didn't create a DBus connection, retry now. */
     if (option_bool(OPT_DBUS) && !daemon->dbus)
        {
          char *err;
          if ((err = dbus_init()))
            my_syslog(LOG_WARNING, _("DBus error: %s"), err);
          if (daemon->dbus)
            my_syslog(LOG_INFO, _("connected to system DBus"));
        }
      check_dbus_listeners();
#endif

      check_dns_listeners(now);

#ifdef HAVE_TFTP
      check_tftp_listeners(now);
#endif
```

## address\_allocate() → icmp\_ping() → check\_dns\_listeners() → tcp\_request()

- address\_allocate() @src/dhcp.c

```c
                if (!r)
                  {
                    if ((count < max) && !option_bool(OPT_NO_PING) && icmp_ping(addr))
                      {
                        /* address in use: perturb address selection so that we are
                           less likely to try this address again. */
                        if (!option_bool(OPT_CONSEC_ADDR))
                          c->addr_epoch++;
                      }
                    else
                      {
                        /* at this point victim may hold an expired record */
                        if (!victim)
                          {
                            if ((victim = whine_malloc(sizeof(struct ping_result))))
                              {
                                victim->next = daemon->ping_results;
                                daemon->ping_results = victim;
                              }
                          }

                        /* record that this address is OK for 30s
                           without more ping checks */
                        if (victim)
                          {
                            victim->addr = addr;
                            victim->time = now;
                            victim->hash = j;
                          }
                        return 1;
                      }
                  }
```

- icmp\_ping() @src/dnsmasq.c

```c
      rc = do_poll(250);

      if (rc < 0)
        continue;
      else if (rc == 0)
        timeout_count++;

      now = dnsmasq_time();

      check_log_writer(0);
      check_dns_listeners(now);
```

- check\_dns\_listeners() @src/dnsmasq.c

```c
              /* start with no upstream connections. */
              for (s = daemon->servers; s; s = s->next)
                 s->tcpfd = -1;

              /* The connected socket inherits non-blocking
                 attribute from the listening socket.
                 Reset that here. */
              if ((flags = fcntl(confd, F_GETFL, 0)) != -1)
                fcntl(confd, F_SETFL, flags & ~O_NONBLOCK);

              buff = tcp_request(confd, now, &tcp_addr, netmask, auth_dns);

              shutdown(confd, SHUT_RDWR);
              while (retry_send(close(confd)));
```

# forward\_query()

tcp\_request()が呼ばれるのは下記2通りのパス。

- reply\_query() → forward\_query()
- receive\_query() → forward\_query()

## reply\_query() → forward\_query()

- reply\_query() @src/forward.c

```c
    /* for broken servers, attempt to send to another one. */
    {
      unsigned char *pheader;
      size_t plen;
      int is_sign;

      /* recreate query from reply */
      pheader = find_pseudoheader(header, (size_t)n, &plen, NULL, &is_sign, NULL);
      if (!is_sign)
        {
          header->ancount = htons(0);
          header->nscount = htons(0);
          header->arcount = htons(0);
          if ((nn = resize_packet(header, (size_t)n, pheader, plen)))
            {
              header->hb3 &= ~(HB3_QR | HB3_AA | HB3_TC);
              header->hb4 &= ~(HB4_RA | HB4_RCODE | HB4_CD | HB4_AD);
              if (forward->flags & FREC_CHECKING_DISABLED)
                header->hb4 |= HB4_CD;
              if (forward->flags & FREC_AD_QUESTION)
                header->hb4 |= HB4_AD;
              if (forward->flags & FREC_DO_QUESTION)
                add_do_bit(header, nn,  (unsigned char *)pheader + plen);
              forward_query(-1, NULL, NULL, 0, header, nn, now, forward, forward->flags & FREC_AD_QUESTION, forward->flags & FREC_DO_QUESTION);
              return;
            }
        }
    }
```

- forward\_query() @src/forward.c

```c
              if (errno == 0)
                {
                  /* Keep info in case we want to re-send this packet */
                  daemon->srv_save = start;
                  daemon->packet_len = plen;

                  if (!gotname)
                    strcpy(daemon->namebuff, "query");
                  if (start->addr.sa.sa_family == AF_INET)
                    log_query(F_SERVER | F_IPV4 | F_FORWARD, daemon->namebuff,
                              (struct all_addr *)&start->addr.in.sin_addr, NULL);
#ifdef HAVE_IPV6
                  else
                    log_query(F_SERVER | F_IPV6 | F_FORWARD, daemon->namebuff,
                              (struct all_addr *)&start->addr.in6.sin6_addr, NULL);
#endif
                  start->queries++;
                  forwarded = 1;
                  forward->sentto = start;
                  if (!forward->forwardall)
                    break;
                  forward->forwardall++;
                }
```

## receive\_query() → forward\_query()

- receive\_query() @src/forward.c

```c
    {
      int ad_reqd = do_bit;
       /* RFC 6840 5.7 */
      if (header->hb4 & HB4_AD)
        ad_reqd = 1;

      m = answer_request(header, ((char *) header) + udp_size, (size_t)n,
                         dst_addr_4, netmask, now, ad_reqd, do_bit, have_pseudoheader);

      if (m >= 1)
        {
          send_from(listen->fd, option_bool(OPT_NOWILD) || option_bool(OPT_CLEVERBIND),
                    (char *)header, m, &source_addr, &dst_addr, if_index);
          daemon->local_answer++;
        }
      else if (forward_query(listen->fd, &source_addr, &dst_addr, if_index,
                             header, (size_t)n, now, NULL, ad_reqd, do_bit))
        daemon->queries_forwarded++;
      else
        daemon->local_answer++;
    }
```
