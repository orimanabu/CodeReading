# nova volume-updateのクライアント側の流れ

## 概要

"nova volume-update"コマンドを実行してからREST APIを呼ぶまで。

とりあえず知ってるライブラリ(urllib3とか)が表れるまで追いかけてみる。

## 詳細

"nova volume-update" を実行したら、novaclientのdo\_volume\_update()が呼ばれる。

- do\_volume\_update() @v2/shell.py [novaclient]

```python
def do_volume_update(cs, args):
    """Update volume attachment."""
    cs.volumes.update_server_volume(_find_server(cs, args.server).id,
                                    args.attachment_id,
                                    args.new_volume)
```

- VolumeManager.update\_server\_volume() @v2/volumes.py [novaclient]

```python
    def update_server_volume(self, server_id, attachment_id, new_volume_id):
        """
        Update the volume identified by the attachment ID, that is attached to
        the given server ID

        :param server_id: The ID of the server
		:param attachment_id: The ID of the attachment
        :param new_volume_id: The ID of the new volume to attach
        :rtype: :class:`Volume`
        """
        body = {'volumeAttachment': {'volumeId': new_volume_id}}
        return self._update("/servers/%s/os-volume_attachments/%s" %
                            (server_id, attachment_id,),
                            body, "volumeAttachment")
```

- Manager._update() @base.py [novaclient]

```python
    def _update(self, url, body, response_key=None, **kwargs):
        self.run_hooks('modify_body_for_update', body, **kwargs)
        resp, body = self.api.client.put(url, body=body)
        if body:
            if response_key:
                return self.resource_class(self, body[response_key], resp=resp)
            else:
                return self.resource_class(self, body, resp=resp)
        else:
            return StrWithMeta(body, resp)
```

- HTTPClient.put() @client.py [novaclient]

```python
    def put(self, url, **kwargs):
        return self._cs_request(url, 'PUT', **kwargs)
```

```python
    def _cs_request(self, url, method, **kwargs):
        if not self.management_url:
            self.authenticate()
        if url is None:
            # To get API version information, it is necessary to GET
            # a nova endpoint directly without "v2/<tenant-id>".
            magic_tuple = parse.urlsplit(self.management_url)
            scheme, netloc, path, query, frag = magic_tuple
            path = re.sub(r'v[1-9](\.[1-9][0-9]*)?/[a-z0-9]+$', '', path)
            url = parse.urlunsplit((scheme, netloc, path, None, None))
        else:
            if self.service_catalog and not self.bypass_url:
                url = self.get_service_url(self.service_type) + url
            else:
                url = self.management_url + url

        # Perform the request once. If we get a 401 back then it
        # might be because the auth token expired, so try to
        # re-authenticate and try again. If it still fails, bail.
        try:
            kwargs.setdefault('headers', {})['X-Auth-Token'] = self.auth_token
            if self.projectid:
                kwargs['headers']['X-Auth-Project-Id'] = self.projectid

            resp, body = self._time_request(url, method, **kwargs)
            return resp, body
        except exceptions.Unauthorized as e:
            try:
                # first discard auth token, to avoid the possibly expired
                # token being re-used in the re-authentication attempt
                self.unauthenticate()
                # overwrite bad token
                self.keyring_saved = False
                self.authenticate()
                kwargs['headers']['X-Auth-Token'] = self.auth_token
                resp, body = self._time_request(url, method, **kwargs)
                return resp, body
            except exceptions.Unauthorized:
                raise e
```

```python
    def _time_request(self, url, method, **kwargs):
        with utils.record_time(self.times, self.timings, method, url):
            resp, body = self.request(url, method, **kwargs)
        return resp, body
```

```python
    def request(self, url, method, **kwargs):
        kwargs.setdefault('headers', kwargs.get('headers', {}))
        kwargs['headers']['User-Agent'] = self.USER_AGENT
        kwargs['headers']['Accept'] = 'application/json'
        if 'body' in kwargs:
            kwargs['headers']['Content-Type'] = 'application/json'
            kwargs['data'] = json.dumps(kwargs['body'])
            del kwargs['body']
        api_versions.update_headers(kwargs["headers"], self.api_version)
        if self.timeout is not None:
            kwargs.setdefault('timeout', self.timeout)
        kwargs['verify'] = self.verify_cert

        self.http_log_req(method, url, kwargs)

        request_func = requests.request
        session = self._get_session(url)
        if session:
            request_func = session.request

        resp = request_func(
            method,
            url,
            **kwargs)

        # TODO(andreykurilin): uncomment this line, when we will be able to
        #   check only nova-related calls
        # api_versions.check_headers(resp, self.api_version)

        self.http_log_resp(resp)

        if resp.text:
            # TODO(dtroyer): verify the note below in a requests context
            # NOTE(alaski): Because force_exceptions_to_status_code=True
            # httplib2 returns a connection refused event as a 400 response.
            # To determine if it is a bad request or refused connection we need
            # to check the body.  httplib2 tests check for 'Connection refused'
            # or 'actively refused' in the body, so that's what we'll do.
            if resp.status_code == 400:
                if ('Connection refused' in resp.text or
                        'actively refused' in resp.text):
                    raise exceptions.ConnectionRefused(resp.text)
            try:
                body = json.loads(resp.text)
            except ValueError:
                body = None
        else:
            body = None

        self.last_request_id = (resp.headers.get('x-openstack-request-id')
                                if resp.headers else None)
        if resp.status_code >= 400:
            raise exceptions.from_response(resp, body, url, method)

        return resp, body
```

```python
    def _get_session(self, url):
        if self._connection_pool:
            magic_tuple = parse.urlsplit(url)
            scheme, netloc, path, query, frag = magic_tuple
            service_url = '%s://%s' % (scheme, netloc)
            if self._current_url != service_url:
                # Invalidate Session object in case the url is somehow changed
                if self._session:
                    self._session.close()
                self._current_url = service_url
                self._logger.debug(
                    "New session created for: (%s)" % service_url)
                self._session = requests.Session()
                self._session.mount(service_url,
                                    self._connection_pool.get(service_url))
            return self._session
        elif self._session:
            return self._session
```

- Session.request() @sessions.py [requests]

```python
    def request(self, method, url,
        params=None,
        data=None,
        headers=None,
        cookies=None,
        files=None,
        auth=None,
        timeout=None,
        allow_redirects=True,
        proxies=None,
        hooks=None,
        stream=None,
        verify=None,
        cert=None,
        json=None):
        """Constructs a :class:`Request <Request>`, prepares it and sends it.
        Returns :class:`Response <Response>` object.

        :param method: method for the new :class:`Request` object.
        :param url: URL for the new :class:`Request` object.
        :param params: (optional) Dictionary or bytes to be sent in the query
            string for the :class:`Request`.
        :param data: (optional) Dictionary, bytes, or file-like object to send
            in the body of the :class:`Request`.
        :param json: (optional) json to send in the body of the
            :class:`Request`.
        :param headers: (optional) Dictionary of HTTP Headers to send with the
            :class:`Request`.
        :param cookies: (optional) Dict or CookieJar object to send with the
            :class:`Request`.
        :param files: (optional) Dictionary of ``'filename': file-like-objects``
            for multipart encoding upload.
        :param auth: (optional) Auth tuple or callable to enable
            Basic/Digest/Custom HTTP Auth.
        :param timeout: (optional) How long to wait for the server to send
            data before giving up, as a float, or a :ref:`(connect timeout,
            read timeout) <timeouts>` tuple.
        :type timeout: float or tuple
        :param allow_redirects: (optional) Set to True by default.
        :type allow_redirects: bool
        :param proxies: (optional) Dictionary mapping protocol or protocol and
            hostname to the URL of the proxy.
        :param stream: (optional) whether to immediately download the response
            content. Defaults to ``False``.
        :param verify: (optional) whether the SSL cert will be verified.
            A CA_BUNDLE path can also be provided. Defaults to ``True``.
        :param cert: (optional) if String, path to ssl client cert file (.pem).
            If Tuple, ('cert', 'key') pair.
        :rtype: requests.Response
    """
        # Create the Request.
        req = Request(
            method = method.upper(),
            url = url,
            headers = headers,
            files = files,
            data = data or {},
            json = json,
            params = params or {},
            auth = auth,
            cookies = cookies,
            hooks = hooks,
        )
        prep = self.prepare_request(req)

        proxies = proxies or {}

        settings = self.merge_environment_settings(
            prep.url, proxies, stream, verify, cert
        )

        # Send the request.
        send_kwargs = {
            'timeout': timeout,
            'allow_redirects': allow_redirects,
        }
        send_kwargs.update(settings)
        resp = self.send(prep, **send_kwargs)

        return resp
```

```python
    def send(self, request, **kwargs):
        """Send a given PreparedRequest."""
        # Set defaults that the hooks can utilize to ensure they always have
        # the correct parameters to reproduce the previous request.
        kwargs.setdefault('stream', self.stream)
        kwargs.setdefault('verify', self.verify)
        kwargs.setdefault('cert', self.cert)
        kwargs.setdefault('proxies', self.proxies)

        # It's possible that users might accidentally send a Request object.
        # Guard against that specific failure case.
        if isinstance(request, Request):
            raise ValueError('You can only send PreparedRequests.')

        # Set up variables needed for resolve_redirects and dispatching of hooks
        allow_redirects = kwargs.pop('allow_redirects', True)
        stream = kwargs.get('stream')
        hooks = request.hooks

        # Resolve URL in redirect cache, if available.
        if allow_redirects:
            checked_urls = set()
            while request.url in self.redirect_cache:
                checked_urls.add(request.url)
                new_url = self.redirect_cache.get(request.url)
                if new_url in checked_urls:
                    break
                request.url = new_url

        # Get the appropriate adapter to use
        adapter = self.get_adapter(url=request.url)

        # Start time (approximately) of the request
        start = datetime.utcnow()

        # Send the request
        r = adapter.send(request, **kwargs)

        # Total elapsed time of the request (approximately)
        r.elapsed = datetime.utcnow() - start

        # Response manipulation hooks
        r = dispatch_hook('response', hooks, r, **kwargs)

        # Persist cookies
        if r.history:

            # If the hooks create history then we want those cookies too
            for resp in r.history:
                extract_cookies_to_jar(self.cookies, resp.request, resp.raw)

        extract_cookies_to_jar(self.cookies, request, r.raw)

        # Redirect resolving generator.
        gen = self.resolve_redirects(r, request, **kwargs)

        # Resolve redirects if allowed.
        history = [resp for resp in gen] if allow_redirects else []

        # Shuffle things around if there's history.
        if history:
            # Insert the first (original) request at the start
            history.insert(0, r)
            # Get the last request made
            r = history.pop()
            r.history = history

        if not stream:
            r.content

        return r
```

- HTTPAdapter.send() @adapters.py [requests]

```python
    def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
        """Sends PreparedRequest object. Returns Response object.

        :param request: The :class:`PreparedRequest <PreparedRequest>` being sent.
        :param stream: (optional) Whether to stream the request content.
        :param timeout: (optional) How long to wait for the server to send
            data before giving up, as a float, or a :ref:`(connect timeout,
            read timeout) <timeouts>` tuple.
        :type timeout: float or tuple
        :param verify: (optional) Whether to verify SSL certificates.
        :param cert: (optional) Any user-provided SSL certificate to be trusted.
        :param proxies: (optional) The proxies dictionary to apply to the request.
        """

        conn = self.get_connection(request.url, proxies)

        self.cert_verify(conn, request.url, verify, cert)
        url = self.request_url(request, proxies)
        self.add_headers(request)

        chunked = not (request.body is None or 'Content-Length' in request.headers)

        if isinstance(timeout, tuple):
            try:
                connect, read = timeout
                timeout = TimeoutSauce(connect=connect, read=read)
            except ValueError as e:
                # this may raise a string formatting error.
                err = ("Invalid timeout {0}. Pass a (connect, read) "
                       "timeout tuple, or a single float to set "
                       "both timeouts to the same value".format(timeout))
                raise ValueError(err)
        else:
            timeout = TimeoutSauce(connect=timeout, read=timeout)

        try:
            if not chunked:
                resp = conn.urlopen(
                    method=request.method,
                    url=url,
                    body=request.body,
                    headers=request.headers,
                    redirect=False,
                    assert_same_host=False,
                    preload_content=False,
                    decode_content=False,
                    retries=self.max_retries,
                    timeout=timeout
                )

            # Send the request.
            else:
                if hasattr(conn, 'proxy_pool'):
                    conn = conn.proxy_pool

                low_conn = conn._get_conn(timeout=DEFAULT_POOL_TIMEOUT)

                try:
                    low_conn.putrequest(request.method,
                                        url,
                                        skip_accept_encoding=True)

                    for header, value in request.headers.items():
                        low_conn.putheader(header, value)

                    low_conn.endheaders()

                    for i in request.body:
                        low_conn.send(hex(len(i))[2:].encode('utf-8'))
                        low_conn.send(b'\r\n')
                        low_conn.send(i)
                        low_conn.send(b'\r\n')
                    low_conn.send(b'0\r\n\r\n')

                    # Receive the response from the server
                    try:
                        # For Python 2.7+ versions, use buffering of HTTP
                        # responses
                        r = low_conn.getresponse(buffering=True)
                    except TypeError:
                        # For compatibility with Python 2.6 versions and back
                        r = low_conn.getresponse()

                    resp = HTTPResponse.from_httplib(
                        r,
                        pool=conn,
                        connection=low_conn,
                        preload_content=False,
                        decode_content=False
                    )
                except:
                    # If we hit any problems here, clean up the connection.
                    # Then, reraise so that we can handle the actual exception.
                    low_conn.close()
                    raise

        except (ProtocolError, socket.error) as err:
            raise ConnectionError(err, request=request)

        except MaxRetryError as e:
            if isinstance(e.reason, ConnectTimeoutError):
                # TODO: Remove this in 3.0.0: see #2811
                if not isinstance(e.reason, NewConnectionError):
                    raise ConnectTimeout(e, request=request)

            if isinstance(e.reason, ResponseError):
                raise RetryError(e, request=request)

            if isinstance(e.reason, _ProxyError):
                raise ProxyError(e, request=request)

            raise ConnectionError(e, request=request)

        except ClosedPoolError as e:
            raise ConnectionError(e, request=request)

        except _ProxyError as e:
            raise ProxyError(e)

        except (_SSLError, _HTTPError) as e:
            if isinstance(e, _SSLError):
                raise SSLError(e, request=request)
            elif isinstance(e, ReadTimeoutError):
                raise ReadTimeout(e, request=request)
            else:
                raise

        return self.build_response(request, resp)
```

- HTTPAdapter.get_connection() @adapters.py [requests]

```python3
    def get_connection(self, url, proxies=None):
        """Returns a urllib3 connection for the given URL. This should not be
        called from user code, and is only exposed for use when subclassing the
        :class:`HTTPAdapter <requests.adapters.HTTPAdapter>`.

        :param url: The URL to connect to.
        :param proxies: (optional) A Requests-style dictionary of proxies used on this request.
        """
        proxy = select_proxy(url, proxies)

        if proxy:
            proxy = prepend_scheme_if_needed(proxy, 'http')
            proxy_manager = self.proxy_manager_for(proxy)
            conn = proxy_manager.connection_from_url(url)
        else:
            # Only scheme should be lower case
            parsed = urlparse(url)
            url = parsed.geturl()
            conn = self.poolmanager.connection_from_url(url)

        return conn
```

- HTTPConnectionPool.\_get\_conn() @packages/urllib3/connectionpool.py [requests]

```python3
    def _get_conn(self, timeout=None):
        """
        Get a connection. Will return a pooled connection if one is available.

        If no connections are available and :prop:`.block` is ``False``, then a
        fresh connection is returned.

        :param timeout:
            Seconds to wait before giving up and raising
            :class:`urllib3.exceptions.EmptyPoolError` if the pool is empty and
            :prop:`.block` is ``True``.
        """
        conn = None
        try:
            conn = self.pool.get(block=self.block, timeout=timeout)

        except AttributeError:  # self.pool is None
            raise ClosedPoolError(self, "Pool is closed.")

        except Empty:
            if self.block:
                raise EmptyPoolError(self,
                                     "Pool reached maximum size and no more "
                                     "connections are allowed.")
            pass  # Oh well, we'll create a new connection then

        # If this is a persistent connection, check if it got disconnected
        if conn and is_connection_dropped(conn):
            log.info("Resetting dropped connection: %s", self.host)
            conn.close()
            if getattr(conn, 'auto_open', 1) == 0:
                # This is a proxied connection that has been mutated by
                # httplib._tunnel() and cannot be reused (since it would
                # attempt to bypass the proxy)
                conn = None

        return conn or self._new_conn()
```

