# nova volume-updateを追う

バージョン

- RHOSP9 (Mitaka)
- RHEL7.3

## 動機

nova volume-update が何をしているかを追う。

最終的にはqemuのdrive-mirrorを呼んでいる。

## ソースコード抜粋の判例:

- CLASS\_NAME.METHOD\_NAME() @RELATIVE_PATH [MODULE]

  - CLASS\_NAME: クラス名
  - METHOD\_NAME: メソッド名
  - RELATIVE_PATH: モジュールごとに特定のパスを起点とした相対パス
  - MODULE: 見ているパッケージ

- 登場するパッケージ (カッコ内はソースコードを例示する際のトップディレクトリ)

  - python-novaclient-3.3.2-1.el7ost.noarch (/usr/lib/python2.7/site-packages/novaclient)
  - python-requests-2.10.0-1.el7ost.noarch (/usr/lib/python2.7/site-packages/requests)
  - python-nova-13.1.2-9.el7ost.noarch (/usr/lib/python2.7/site-packages/nova)
  - libvirt-python-2.0.0-2.el7.x86_64 (/usr/lib64/python2.7/site-packages)
  - libvirt-2.0.0-10.el7.x86_64
  - qemu-kvm-rhev-2.6.0-27.el7.x86_64

## さっそく読む

## まずnovaclient

"nova volume-update" を実行したら、novaclientのdo\_volume\_update()が呼ばれる。

- do\_volume\_update() @v2/shell.py [novaclient]

```python
def do_volume_update(cs, args):
    """Update volume attachment."""
    cs.volumes.update_server_volume(_find_server(cs, args.server).id,
                                    args.attachment_id,
                                    args.new_volume)
```

- VolumeManager.update\_server\_volume() @novaclient.v2/volumes.py

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

- HTTPAdapter.get_connection() @adapters.py

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

- HTTPConnectionPool.\_get\_conn() @packages/urllib3/connectionpool.py

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


# 次にコントローラ側

- Volumes.get\_resources() @api/openstack/compute/volumes.py

```python
    def get_resources(self):
        resources = []

        res = extensions.ResourceExtension(
            ALIAS, VolumeController(), collection_actions={'detail': 'GET'})
        resources.append(res)

        res = extensions.ResourceExtension('os-volumes_boot',
                                           inherits='servers')
        resources.append(res)

        res = extensions.ResourceExtension('os-volume_attachments',
                                           VolumeAttachmentController(),
                                           parent=dict(
                                                member_name='server',
                                                collection_name='servers'))
        resources.append(res)

        res = extensions.ResourceExtension(
            'os-snapshots', SnapshotController(),
            collection_actions={'detail': 'GET'})
        resources.append(res)

        return resources
```

- Volumes.get\_resources() @api/openstack/compute/legacy\_v2/contrib/volumes.py

```python
    def get_resources(self):
        resources = []

        # NOTE(justinsb): No way to provide singular name ('volume')
        # Does this matter?
        res = extensions.ResourceExtension('os-volumes',
                                        VolumeController(),
                                        collection_actions={'detail': 'GET'})
        resources.append(res)

        attachment_controller = VolumeAttachmentController(self.ext_mgr)
        res = extensions.ResourceExtension('os-volume_attachments',
                                           attachment_controller,
                                           parent=dict(
                                                member_name='server',
                                                collection_name='servers'))
        resources.append(res)

        res = extensions.ResourceExtension('os-volumes_boot',
                                           inherits='servers')
        resources.append(res)

        res = extensions.ResourceExtension('os-snapshots',
                                        SnapshotController(),
                                        collection_actions={'detail': 'GET'})
        resources.append(res)

        return resources
```


os-volume-attachment-update

VolumeAttachmentController.update() @api/openstack/compute/volumes.py

```python
    def update(self, req, server_id, id, body):
        context = req.environ['nova.context']
        authorize(context)
        authorize_attach(context, action='update')

        old_volume_id = id
        try:
            old_volume = self.volume_api.get(context, old_volume_id)

            new_volume_id = body['volumeAttachment']['volumeId']
            new_volume = self.volume_api.get(context, new_volume_id)
        except exception.VolumeNotFound as e:
            raise exc.HTTPNotFound(explanation=e.format_message())

        instance = common.get_instance(self.compute_api, context, server_id)

        bdms = objects.BlockDeviceMappingList.get_by_instance_uuid(
                context, instance.uuid)
        found = False
        try:
            for bdm in bdms:
                if bdm.volume_id != old_volume_id:
                    continue
                try:
                    self.compute_api.swap_volume(context, instance, old_volume,
                                                 new_volume)
                    found = True
                    break
                except exception.VolumeUnattached:
                    # The volume is not attached.  Treat it as NotFound
                    # by falling through.
                    pass
                except exception.InvalidVolume as e:
                    raise exc.HTTPBadRequest(explanation=e.format_message())
        except exception.InstanceIsLocked as e:
            raise exc.HTTPConflict(explanation=e.format_message())
        except exception.InstanceInvalidState as state_error:
            common.raise_http_conflict_for_instance_invalid_state(state_error,
                    'swap_volume', server_id)

        if not found:
            msg = _("The volume was either invalid or not attached to the "
                    "instance.")
            raise exc.HTTPNotFound(explanation=msg)
```

VolumeAttachmentController.update() @api/openstack/compute/legacy_v2/contrib/volumes.py

```python
    def update(self, req, server_id, id, body):
        if (not self.ext_mgr or
                not self.ext_mgr.is_loaded('os-volume-attachment-update')):
            raise exc.HTTPBadRequest()
        context = req.environ['nova.context']
        authorize(context)
        authorize_attach(context, action='update')

        if not self.is_valid_body(body, 'volumeAttachment'):
            msg = _("volumeAttachment not specified")
            raise exc.HTTPBadRequest(explanation=msg)

        old_volume_id = id
        old_volume = self.volume_api.get(context, old_volume_id)

        try:
            new_volume_id = body['volumeAttachment']['volumeId']
        except KeyError:
            msg = _("volumeId must be specified.")
            raise exc.HTTPBadRequest(explanation=msg)
        self._validate_volume_id(new_volume_id)
        new_volume = self.volume_api.get(context, new_volume_id)

        instance = common.get_instance(self.compute_api, context, server_id)

        bdms = objects.BlockDeviceMappingList.get_by_instance_uuid(
                context, instance.uuid)
        found = False
        try:
            for bdm in bdms:
                if bdm.volume_id != old_volume_id:
                    continue
                try:
                    self.compute_api.swap_volume(context, instance, old_volume,
                                                 new_volume)
                    found = True
                    break
                except exception.VolumeUnattached:
                    # The volume is not attached.  Treat it as NotFound
                    # by falling through.
                    pass
        except exception.InstanceIsLocked as e:
            raise exc.HTTPConflict(explanation=e.format_message())
        except exception.InstanceInvalidState as state_error:
            common.raise_http_conflict_for_instance_invalid_state(state_error,
                    'swap_volume', server_id)

        if not found:
            msg = _("volume_id not found: %s") % old_volume_id
            raise exc.HTTPNotFound(explanation=msg)
        else:
            return webob.Response(status_int=202)
```

Volume\_attachment\_update @api/openstack/compute/legacy\_v2/contrib/volume\_attachment\_update.py

```python
class Volume_attachment_update(extensions.ExtensionDescriptor):
    """Support for updating a volume attachment."""

    name = "VolumeAttachmentUpdate"
    alias = "os-volume-attachment-update"
    namespace = ("http://docs.openstack.org/compute/ext/"
                "os-volume-attachment-update/api/v2")
    updated = "2013-06-20T00:00:00Z"
```


API.swap_volume() @compute/api.py

```python
    def swap_volume(self, context, instance, old_volume, new_volume):
        """Swap volume attached to an instance."""
        if old_volume['attach_status'] == 'detached':
            raise exception.VolumeUnattached(volume_id=old_volume['id'])
        # The caller likely got the instance from volume['attachments']
        # in the first place, but let's sanity check.
        if not old_volume.get('attachments', {}).get(instance.uuid):
            msg = _("Old volume is attached to a different instance.")
            raise exception.InvalidVolume(reason=msg)
        if new_volume['attach_status'] == 'attached':
            msg = _("New volume must be detached in order to swap.")
            raise exception.InvalidVolume(reason=msg)
        if int(new_volume['size']) < int(old_volume['size']):
            msg = _("New volume must be the same size or larger.")
            raise exception.InvalidVolume(reason=msg)
        self.volume_api.check_detach(context, old_volume)
        self.volume_api.check_attach(context, new_volume, instance=instance)
        self.volume_api.begin_detaching(context, old_volume['id'])
        self.volume_api.reserve_volume(context, new_volume['id'])
        try:
            self.compute_rpcapi.swap_volume(
                    context, instance=instance,
                    old_volume_id=old_volume['id'],
                    new_volume_id=new_volume['id'])
        except Exception:
            with excutils.save_and_reraise_exception():
                self.volume_api.roll_detaching(context, old_volume['id'])
                self.volume_api.unreserve_volume(context, new_volume['id'])
```

- ComputeAPI.swap_volume() @compute/rpcapi.py

```python
    def swap_volume(self, ctxt, instance, old_volume_id, new_volume_id):
        version = '4.0'
        cctxt = self.client.prepare(server=_compute_host(None, instance),
                version=version)
        cctxt.cast(ctxt, 'swap_volume',
                   instance=instance, old_volume_id=old_volume_id,
                   new_volume_id=new_volume_id)
```

- ComputeManager.swap_volume() @compute/manager.py

```python
    def swap_volume(self, context, old_volume_id, new_volume_id, instance):
        """Swap volume for an instance."""
        context = context.elevated()

        bdm = objects.BlockDeviceMapping.get_by_volume_and_instance(
                context, old_volume_id, instance.uuid)
        connector = self.driver.get_volume_connector(instance)

        resize_to = 0
        old_vol_size = self.volume_api.get(context, old_volume_id)['size']
        new_vol_size = self.volume_api.get(context, new_volume_id)['size']
        if new_vol_size > old_vol_size:
            resize_to = new_vol_size

        LOG.info(_LI('Swapping volume %(old_volume)s for %(new_volume)s'),
                  {'old_volume': old_volume_id, 'new_volume': new_volume_id},
                  context=context, instance=instance)
        comp_ret, new_cinfo = self._swap_volume(context, instance,
                                                         bdm,
                                                         connector,
                                                         old_volume_id,
                                                         new_volume_id,
                                                         resize_to)

        save_volume_id = comp_ret['save_volume_id']

        # Update bdm
        values = {
            'connection_info': jsonutils.dumps(new_cinfo),
            'delete_on_termination': False,
            'source_type': 'volume',
            'destination_type': 'volume',
            'snapshot_id': None,
            'volume_id': save_volume_id,
            'no_device': None}

        if resize_to:
            values['volume_size'] = resize_to

        LOG.debug("swap_volume: Updating volume %(volume_id)s BDM record with "
                  "%(updates)s", {'volume_id': bdm.volume_id,
                                  'updates': values},
                  context=context, instance=instance)
        bdm.update(values)
        bdm.save()
```

- ComputeManager.\_swap\_volume() @compute/manager.py

```python
    def _swap_volume(self, context, instance, bdm, connector,
                     old_volume_id, new_volume_id, resize_to):
        mountpoint = bdm['device_name']
        failed = False
        new_cinfo = None
        try:
            old_cinfo, new_cinfo = self._init_volume_connection(context,
                                                                new_volume_id,
                                                                old_volume_id,
                                                                connector,
                                                                instance,
                                                                bdm)
            LOG.debug("swap_volume: Calling driver volume swap with "
                      "connection infos: new: %(new_cinfo)s; "
                      "old: %(old_cinfo)s",
                      {'new_cinfo': new_cinfo, 'old_cinfo': old_cinfo},
                      contex=context, instance=instance)
            self.driver.swap_volume(old_cinfo, new_cinfo, instance, mountpoint,
                                    resize_to)
        except Exception:
            failed = True
            with excutils.save_and_reraise_exception():
                if new_cinfo:
                    msg = _LE("Failed to swap volume %(old_volume_id)s "
                              "for %(new_volume_id)s")
                    LOG.exception(msg, {'old_volume_id': old_volume_id,
                                        'new_volume_id': new_volume_id},
                                  context=context,
                                  instance=instance)
                else:
                    msg = _LE("Failed to connect to volume %(volume_id)s "
                              "with volume at %(mountpoint)s")
                    LOG.exception(msg, {'volume_id': new_volume_id,
                                        'mountpoint': bdm['device_name']},
                                  context=context,
                                  instance=instance)
                self.volume_api.roll_detaching(context, old_volume_id)
                self.volume_api.unreserve_volume(context, new_volume_id)
        finally:
            conn_volume = new_volume_id if failed else old_volume_id
            if new_cinfo:
                LOG.debug("swap_volume: calling Cinder terminate_connection "
                          "for %(volume)s", {'volume': conn_volume},
                          context=context, instance=instance)
                self.volume_api.terminate_connection(context,
                                                     conn_volume,
                                                     connector)
            # If Cinder initiated the swap, it will keep
            # the original ID
            comp_ret = self.volume_api.migrate_volume_completion(
                                                      context,
                                                      old_volume_id,
                                                      new_volume_id,
                                                      error=failed)
            LOG.debug("swap_volume: Cinder migrate_volume_completion "
                      "returned: %(comp_ret)s", {'comp_ret': comp_ret},
                      context=context, instance=instance)

        return (comp_ret, new_cinfo)
```

- LibvirtDriver.swap_volume() @virt/libvirt/driver.py

```python
    def swap_volume(self, old_connection_info,
                    new_connection_info, instance, mountpoint, resize_to):

        guest = self._host.get_guest(instance)

        disk_dev = mountpoint.rpartition("/")[2]
        if not guest.get_disk(disk_dev):
            raise exception.DiskNotFound(location=disk_dev)
        disk_info = {
            'dev': disk_dev,
            'bus': blockinfo.get_disk_bus_for_disk_dev(
                CONF.libvirt.virt_type, disk_dev),
            'type': 'disk',
            }
        self._connect_volume(new_connection_info, disk_info)
        conf = self._get_volume_config(new_connection_info, disk_info)
        if not conf.source_path:
            self._disconnect_volume(new_connection_info, disk_dev)
            raise NotImplementedError(_("Swap only supports host devices"))

        # Save updates made in connection_info when connect_volume was called
        volume_id = new_connection_info.get('serial')
        bdm = objects.BlockDeviceMapping.get_by_volume_and_instance(
            nova_context.get_admin_context(), volume_id, instance.uuid)
        driver_bdm = driver_block_device.DriverVolumeBlockDevice(bdm)
        driver_bdm['connection_info'] = new_connection_info
        driver_bdm.save()

        self._swap_volume(guest, disk_dev, conf.source_path, resize_to)
        self._disconnect_volume(old_connection_info, disk_dev)
```

- LibvirtDriver.\_swap\_volume() @virt/libvirt/driver.py

```python
    def _swap_volume(self, guest, disk_path, new_path, resize_to):
        """Swap existing disk with a new block device."""
        dev = guest.get_block_device(disk_path)

        # Save a copy of the domain's persistent XML file
        xml = guest.get_xml_desc(dump_inactive=True, dump_sensitive=True)

        # Abort is an idempotent operation, so make sure any block
        # jobs which may have failed are ended.
        try:
            dev.abort_job()
        except Exception:
            pass

        try:
            # NOTE (rmk): blockRebase cannot be executed on persistent
            #             domains, so we need to temporarily undefine it.
            #             If any part of this block fails, the domain is
            #             re-defined regardless.
            if guest.has_persistent_configuration():
                guest.delete_configuration()

            # Start copy with VIR_DOMAIN_REBASE_REUSE_EXT flag to
            # allow writing to existing external volume file
            dev.rebase(new_path, copy=True, reuse_ext=True)

            while dev.wait_for_job():
                time.sleep(0.5)

            dev.abort_job(pivot=True)
            if resize_to:
                # NOTE(alex_xu): domain.blockJobAbort isn't sync call. This
                # is bug in libvirt. So we need waiting for the pivot is
                # finished. libvirt bug #1119173
                while dev.wait_for_job(wait_for_job_clean=True):
                    time.sleep(0.5)
                dev.resize(resize_to * units.Gi / units.Ki)
        finally:
            self._host.write_instance_config(xml)
```

- BlockDevice.rebase() @virt/libvirt/guest.py

```python
    def rebase(self, base, shallow=False, reuse_ext=False,
               copy=False, relative=False):
        """Rebases block to new base

        :param shallow: Limit copy to top of source backing chain
        :param reuse_ext: Reuse existing external file of a copy
        :param copy: Start a copy job
        :param relative: Keep backing chain referenced using relative names
        """
        flags = shallow and libvirt.VIR_DOMAIN_BLOCK_REBASE_SHALLOW or 0
        flags |= reuse_ext and libvirt.VIR_DOMAIN_BLOCK_REBASE_REUSE_EXT or 0
        flags |= copy and libvirt.VIR_DOMAIN_BLOCK_REBASE_COPY or 0
        flags |= relative and libvirt.VIR_DOMAIN_BLOCK_REBASE_RELATIVE or 0
        return self._guest._domain.blockRebase(
            self._disk, base, self.REBASE_DEFAULT_BANDWIDTH, flags=flags)
```

- virDomain.blockRebase() @/usr/lib64/python2.7/site-packages/libvirt.py

```python
    def blockRebase(self, disk, base, bandwidth=0, flags=0):
        """Populate a disk image with data from its backing image chain, and
        setting the backing image to @base, or alternatively copy an entire
        backing chain to a new file @base.

        When @flags is 0, this starts a pull, where @base must be the absolute
        path of one of the backing images further up the chain, or None to
        convert the disk image so that it has no backing image.  Once all
        data from its backing image chain has been pulled, the disk no
        longer depends on those intermediate backing images.  This function
        pulls data for the entire device in the background.  Progress of
        the operation can be checked with virDomainGetBlockJobInfo() with a
        job type of VIR_DOMAIN_BLOCK_JOB_TYPE_PULL, and the operation can be
        aborted with virDomainBlockJobAbort().  When finished, an asynchronous
        event is raised to indicate the final status, and the job no longer
        exists.  If the job is aborted, a new one can be started later to
        resume from the same point.

        If @flags contains VIR_DOMAIN_BLOCK_REBASE_RELATIVE, the name recorded
        into the active disk as the location for @base will be kept relative.
        The operation will fail if libvirt can't infer the name.

        When @flags includes VIR_DOMAIN_BLOCK_REBASE_COPY, this starts a copy,
        where @base must be the name of a new file to copy the chain to.  By
        default, the copy will pull the entire source chain into the destination
        file, but if @flags also contains VIR_DOMAIN_BLOCK_REBASE_SHALLOW, then
        only the top of the source chain will be copied (the source and
        destination have a common backing file).  By default, @base will be
        created with the same file format as the source, but this can be altered
        by adding VIR_DOMAIN_BLOCK_REBASE_COPY_RAW to force the copy to be raw
        (does not make sense with the shallow flag unless the source is also raw),
        or by using VIR_DOMAIN_BLOCK_REBASE_REUSE_EXT to reuse an existing file
        which was pre-created with the correct format and metadata and sufficient
        size to hold the copy. In case the VIR_DOMAIN_BLOCK_REBASE_SHALLOW flag
        is used the pre-created file has to exhibit the same guest visible contents
        as the backing file of the original image. This allows a management app to
        pre-create files with relative backing file names, rather than the default
        of absolute backing file names; as a security precaution, you should
        generally only use reuse_ext with the shallow flag and a non-raw
        destination file.  By default, the copy destination will be treated as
        type='file', but using VIR_DOMAIN_BLOCK_REBASE_COPY_DEV treats the
        destination as type='block' (affecting how virDomainGetBlockInfo() will
        report allocation after pivoting).

        A copy job has two parts; in the first phase, the @bandwidth parameter
        affects how fast the source is pulled into the destination, and the job
        can only be canceled by reverting to the source file; progress in this
        phase can be tracked via the virDomainBlockJobInfo() command, with a
        job type of VIR_DOMAIN_BLOCK_JOB_TYPE_COPY.  The job transitions to the
        second phase when the job info states cur == end, and remains alive to
        mirror all further changes to both source and destination.  The user
        must call virDomainBlockJobAbort() to end the mirroring while choosing
        whether to revert to source or pivot to the destination.  An event is
        issued when the job ends, and depending on the hypervisor, an event may
        also be issued when the job transitions from pulling to mirroring.  If
        the job is aborted, a new job will have to start over from the beginning
        of the first phase.

        Some hypervisors will restrict certain actions, such as virDomainSave()
        or virDomainDetachDevice(), while a copy job is active; they may
        also restrict a copy job to transient domains.

        The @disk parameter is either an unambiguous source name of the
        block device (the <source file='...'/> sub-element, such as
        "/path/to/image"), or the device target shorthand (the
        <target dev='...'/> sub-element, such as "vda").  Valid names
        can be found by calling virDomainGetXMLDesc() and inspecting
        elements within //domain/devices/disk.

        The @base parameter can be either a path to a file within the backing
        chain, or the device target shorthand (the <target dev='...'/>
        sub-element, such as "vda") followed by an index to the backing chain
        enclosed in square brackets. Backing chain indexes can be found by
        inspecting //disk//backingStore/@index in the domain XML. Thus, for
        example, "vda[3]" refers to the backing store with index equal to "3"
        in the chain of disk "vda".

        The maximum bandwidth that will be used to do the copy can be
        specified with the @bandwidth parameter.  If set to 0, there is no
        limit.  If @flags includes VIR_DOMAIN_BLOCK_REBASE_BANDWIDTH_BYTES,
        @bandwidth is in bytes/second; otherwise, it is in MiB/second.
        Values larger than 2^52 bytes/sec may be rejected due to overflow
        considerations based on the word size of both client and server,
        and values larger than 2^31 bytes/sec may cause overflow problems
        if later queried by virDomainGetBlockJobInfo() without scaling.
        Hypervisors may further restrict the range of valid bandwidth
        values.  Some hypervisors do not support this feature and will
        return an error if bandwidth is not 0; in this case, it might still
        be possible for a later call to virDomainBlockJobSetSpeed() to
        succeed.  The actual speed can be determined with
        virDomainGetBlockJobInfo().

        When @base is None and @flags is 0, this is identical to
        virDomainBlockPull().  When @flags contains VIR_DOMAIN_BLOCK_REBASE_COPY,
        this command is shorthand for virDomainBlockCopy() where the destination
        XML encodes @base as a <disk type='file'>, @bandwidth is properly scaled
        and passed as a typed parameter, the shallow and reuse external flags
        are preserved, and remaining flags control whether the XML encodes a
        destination format of raw instead of leaving the destination identical
        to the source format or probed from the reused file. """
        ret = libvirtmod.virDomainBlockRebase(self._o, disk, base, bandwidth, flags)
        if ret == -1: raise libvirtError ('virDomainBlockRebase() failed', dom=self)
        return ret
```

- src/libvirt-domain.c

```c
int
virDomainBlockRebase(virDomainPtr dom, const char *disk,
                     const char *base, unsigned long bandwidth,
                     unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(dom, "disk=%s, base=%s, bandwidth=%lu, flags=%x",
                     disk, NULLSTR(base), bandwidth, flags);

    virResetLastError();

    virCheckDomainReturn(dom, -1);
    conn = dom->conn;

    virCheckReadOnlyGoto(conn->flags, error);
    virCheckNonNullArgGoto(disk, error);

    if (flags & VIR_DOMAIN_BLOCK_REBASE_COPY) {
        virCheckNonNullArgGoto(base, error);
    } else if (flags & (VIR_DOMAIN_BLOCK_REBASE_SHALLOW |
                        VIR_DOMAIN_BLOCK_REBASE_REUSE_EXT |
                        VIR_DOMAIN_BLOCK_REBASE_COPY_RAW |
                        VIR_DOMAIN_BLOCK_REBASE_COPY_DEV)) {
        virReportInvalidArg(flags, "%s",
                            _("use of flags requires a copy job"));
        goto error;
    }

    if (conn->driver->domainBlockRebase) {
        int ret;
        ret = conn->driver->domainBlockRebase(dom, disk, base, bandwidth,
                                              flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(dom->conn);
    return -1;
}
```

- src/qemu/qemu_driver.c

```c
static virHypervisorDriver qemuHypervisorDriver = {
(snip)
    .domainBlockRebase = qemuDomainBlockRebase, /* 0.9.10 */
(snip)
}
```

```c
static int
qemuDomainBlockRebase(virDomainPtr dom, const char *path, const char *base,
                      unsigned long bandwidth, unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;
    unsigned long long speed = bandwidth;
    virStorageSourcePtr dest = NULL;

    virCheckFlags(VIR_DOMAIN_BLOCK_REBASE_SHALLOW |
                  VIR_DOMAIN_BLOCK_REBASE_REUSE_EXT |
                  VIR_DOMAIN_BLOCK_REBASE_COPY |
                  VIR_DOMAIN_BLOCK_REBASE_COPY_RAW |
                  VIR_DOMAIN_BLOCK_REBASE_RELATIVE |
                  VIR_DOMAIN_BLOCK_REBASE_COPY_DEV |
                  VIR_DOMAIN_BLOCK_REBASE_BANDWIDTH_BYTES, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        return -1;

    if (virDomainBlockRebaseEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    /* For normal rebase (enhanced blockpull), the common code handles
     * everything, including vm cleanup. */
    if (!(flags & VIR_DOMAIN_BLOCK_REBASE_COPY))
        return qemuDomainBlockPullCommon(driver, vm, path, base, bandwidth, flags);

    /* If we got here, we are doing a block copy rebase. */
    if (VIR_ALLOC(dest) < 0)
        goto cleanup;
    dest->type = (flags & VIR_DOMAIN_BLOCK_REBASE_COPY_DEV) ?
        VIR_STORAGE_TYPE_BLOCK : VIR_STORAGE_TYPE_FILE;
    if (VIR_STRDUP(dest->path, base) < 0)
        goto cleanup;
    if (flags & VIR_DOMAIN_BLOCK_REBASE_COPY_RAW)
        dest->format = VIR_STORAGE_FILE_RAW;

    /* Convert bandwidth MiB to bytes, if necessary */
    if (!(flags & VIR_DOMAIN_BLOCK_REBASE_BANDWIDTH_BYTES)) {
        if (speed > LLONG_MAX >> 20) {
            virReportError(VIR_ERR_OVERFLOW,
                           _("bandwidth must be less than %llu"),
                           LLONG_MAX >> 20);
            goto cleanup;
        }
        speed <<= 20;
    }

    /* XXX: If we are doing a shallow copy but not reusing an external
     * file, we should attempt to pre-create the destination with a
     * relative backing chain instead of qemu's default of absolute */
    if (flags & VIR_DOMAIN_BLOCK_REBASE_RELATIVE) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("Relative backing during copy not supported yet"));
        goto cleanup;
    }

    /* We rely on the fact that VIR_DOMAIN_BLOCK_REBASE_SHALLOW
     * and VIR_DOMAIN_BLOCK_REBASE_REUSE_EXT map to the same values
     * as for block copy. */
    flags &= (VIR_DOMAIN_BLOCK_REBASE_SHALLOW |
              VIR_DOMAIN_BLOCK_REBASE_REUSE_EXT);
    ret = qemuDomainBlockCopyCommon(vm, dom->conn, path, dest,
                                    speed, 0, 0, flags, true);
    dest = NULL;

 cleanup:
    virDomainObjEndAPI(&vm);
    virStorageSourceFree(dest);
    return ret;
}
```

```c
/* bandwidth in bytes/s.  Caller must lock vm beforehand, and not
 * access mirror afterwards.  */
static int
qemuDomainBlockCopyCommon(virDomainObjPtr vm,
                          virConnectPtr conn,
                          const char *path,
                          virStorageSourcePtr mirror,
                          unsigned long long bandwidth,
                          unsigned int granularity,
                          unsigned long long buf_size,
                          unsigned int flags,
                          bool keepParentLabel)
{
    virQEMUDriverPtr driver = conn->privateData;
    qemuDomainObjPrivatePtr priv;
    char *device = NULL;
    virDomainDiskDefPtr disk = NULL;
    int ret = -1;
    struct stat st;
    bool need_unlink = false;
    virQEMUDriverConfigPtr cfg = NULL;
    const char *format = NULL;
    int desttype = virStorageSourceGetActualType(mirror);

    /* Preliminaries: find the disk we are editing, sanity checks */
    virCheckFlags(VIR_DOMAIN_BLOCK_COPY_SHALLOW |
                  VIR_DOMAIN_BLOCK_COPY_REUSE_EXT, -1);

    priv = vm->privateData;
    cfg = virQEMUDriverGetConfig(driver);

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("domain is not running"));
        goto endjob;
    }

    if (!(disk = qemuDomainDiskByName(vm->def, path)))
        goto endjob;

    if (!(device = qemuAliasFromDisk(disk)))
        goto endjob;

    if (qemuDomainDiskBlockJobIsActive(disk))
        goto endjob;

    if (disk->device == VIR_DOMAIN_DISK_DEVICE_LUN &&
        qemuDomainDefValidateDiskLunSource(mirror) < 0)
        goto endjob;

    if (!(virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DRIVE_MIRROR) &&
          virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_BLOCKJOB_ASYNC))) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("block copy is not supported with this QEMU binary"));
        goto endjob;
    }
    if (vm->persistent) {
        /* XXX if qemu ever lets us start a new domain with mirroring
         * already active, we can relax this; but for now, the risk of
         * 'managedsave' due to libvirt-guests means we can't risk
         * this on persistent domains.  */
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("domain is not transient"));
        goto endjob;
    }

    if (qemuDomainDetermineDiskChain(driver, vm, disk, false, true) < 0)
        goto endjob;

    /* clear the _SHALLOW flag if there is only one layer */
    if (!disk->src->backingStore)
        flags &= ~VIR_DOMAIN_BLOCK_COPY_SHALLOW;

    /* unless the user provides a pre-created file, shallow copy into a raw
     * file is not possible */
    if ((flags & VIR_DOMAIN_BLOCK_COPY_SHALLOW) &&
        !(flags & VIR_DOMAIN_BLOCK_COPY_REUSE_EXT) &&
        mirror->format == VIR_STORAGE_FILE_RAW) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("shallow copy of disk '%s' into a raw file "
                         "is not possible"),
                       disk->dst);
        goto endjob;
    }

    /* Prepare the destination file.  */
    /* XXX Allow non-file mirror destinations */
    if (!virStorageSourceIsLocalStorage(mirror)) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("non-file destination not supported yet"));
        goto endjob;
    }
    if (stat(mirror->path, &st) < 0) {
        if (errno != ENOENT) {
            virReportSystemError(errno, _("unable to stat for disk %s: %s"),
                                 disk->dst, mirror->path);
            goto endjob;
        } else if (flags & VIR_DOMAIN_BLOCK_COPY_REUSE_EXT ||
                   desttype == VIR_STORAGE_TYPE_BLOCK) {
            virReportSystemError(errno,
                                 _("missing destination file for disk %s: %s"),
                                 disk->dst, mirror->path);
            goto endjob;
        }
    } else if (!S_ISBLK(st.st_mode)) {
        if (st.st_size && !(flags & VIR_DOMAIN_BLOCK_COPY_REUSE_EXT)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("external destination file for disk %s already "
                             "exists and is not a block device: %s"),
                           disk->dst, mirror->path);
            goto endjob;
        }
        if (desttype == VIR_STORAGE_TYPE_BLOCK) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("blockdev flag requested for disk %s, but file "
                             "'%s' is not a block device"),
                           disk->dst, mirror->path);
            goto endjob;
        }
    }

    if (!mirror->format) {
        if (!(flags & VIR_DOMAIN_BLOCK_COPY_REUSE_EXT)) {
            mirror->format = disk->src->format;
        } else {
            /* If the user passed the REUSE_EXT flag, then either they
             * can also pass the RAW flag or use XML to tell us the format.
             * So if we get here, we assume it is safe for us to probe the
             * format from the file that we will be using.  */
            mirror->format = virStorageFileProbeFormat(mirror->path, cfg->user,
                                                       cfg->group);
        }
    }

    /* pre-create the image file */
    if (!(flags & VIR_DOMAIN_BLOCK_COPY_REUSE_EXT)) {
        int fd = qemuOpenFile(driver, vm, mirror->path,
                              O_WRONLY | O_TRUNC | O_CREAT,
                              &need_unlink, NULL);
        if (fd < 0)
            goto endjob;
        VIR_FORCE_CLOSE(fd);
    }

    if (mirror->format > 0)
        format = virStorageFileFormatTypeToString(mirror->format);

    if (virStorageSourceInitChainElement(mirror, disk->src,
                                         keepParentLabel) < 0)
        goto endjob;

    if (qemuDomainDiskChainElementPrepare(driver, vm, mirror, false) < 0) {
        qemuDomainDiskChainElementRevoke(driver, vm, mirror);
        goto endjob;
    }

    /* Actually start the mirroring */
    qemuDomainObjEnterMonitor(driver, vm);
    ret = qemuMonitorDriveMirror(priv->mon, device, mirror->path, format,
                                 bandwidth, granularity, buf_size, flags);
    virDomainAuditDisk(vm, NULL, mirror, "mirror", ret >= 0);
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        ret = -1;
    if (ret < 0) {
        qemuDomainDiskChainElementRevoke(driver, vm, mirror);
        goto endjob;
    }

    /* Update vm in place to match changes.  */
    need_unlink = false;
    disk->mirror = mirror;
    mirror = NULL;
    disk->mirrorJob = VIR_DOMAIN_BLOCK_JOB_TYPE_COPY;
    QEMU_DOMAIN_DISK_PRIVATE(disk)->blockjob = true;

    if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm, driver->caps) < 0)
        VIR_WARN("Unable to save status on vm %s after state change",
                 vm->def->name);

 endjob:
    if (need_unlink && unlink(mirror->path))
        VIR_WARN("unable to unlink just-created %s", mirror->path);
    virStorageSourceFree(mirror);
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    VIR_FREE(device);
    virObjectUnref(cfg);
    return ret;
}
```

- src/qemu/qemu_monitor.c

```c
/* Start a drive-mirror block job.  bandwidth is in bytes/sec.  */
int
qemuMonitorDriveMirror(qemuMonitorPtr mon,
                       const char *device, const char *file,
                       const char *format, unsigned long long bandwidth,
                       unsigned int granularity, unsigned long long buf_size,
                       unsigned int flags)
{
    VIR_DEBUG("device=%s, file=%s, format=%s, bandwidth=%lld, "
              "granularity=%#x, buf_size=%lld, flags=%x",
              device, file, NULLSTR(format), bandwidth, granularity,
              buf_size, flags);

    QEMU_CHECK_MONITOR_JSON(mon);

    return qemuMonitorJSONDriveMirror(mon, device, file, format, bandwidth,
                                      granularity, buf_size, flags);
}
```

- src/qemu/qemu\_monitor\_json.c

```c
/* speed is in bytes/sec */
int
qemuMonitorJSONDriveMirror(qemuMonitorPtr mon,
                           const char *device, const char *file,
                           const char *format, unsigned long long speed,
                           unsigned int granularity,
                           unsigned long long buf_size,
                           unsigned int flags)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;
    bool shallow = (flags & VIR_DOMAIN_BLOCK_REBASE_SHALLOW) != 0;
    bool reuse = (flags & VIR_DOMAIN_BLOCK_REBASE_REUSE_EXT) != 0;

    cmd = qemuMonitorJSONMakeCommand("drive-mirror",
                                     "s:device", device,
                                     "s:target", file,
                                     "Y:speed", speed,
                                     "z:granularity", granularity,
                                     "P:buf-size", buf_size,
                                     "s:sync", shallow ? "top" : "full",
                                     "s:mode", reuse ? "existing" : "absolute-paths",
                                     "S:format", format,
                                     NULL);
    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}
```

- src/qemu/qemu\_monitor\_json.c

```c
#define qemuMonitorJSONMakeCommand(cmdname, ...) \
    qemuMonitorJSONMakeCommandRaw(false, cmdname, __VA_ARGS__)
```

```c
/* Top-level commands and nested transaction list elements share a
 * common structure for everything except the dictionary names.  */
static virJSONValuePtr ATTRIBUTE_SENTINEL
qemuMonitorJSONMakeCommandRaw(bool wrap, const char *cmdname, ...)
{
    virJSONValuePtr obj;
    virJSONValuePtr jargs = NULL;
    va_list args;

    va_start(args, cmdname);

    if (!(obj = virJSONValueNewObject()))
        goto error;

    if (virJSONValueObjectAppendString(obj, wrap ? "type" : "execute",
                                       cmdname) < 0)
        goto error;

    if (virJSONValueObjectCreateVArgs(&jargs, args) < 0)
        goto error;

    if (jargs &&
        virJSONValueObjectAppend(obj, wrap ? "data" : "arguments", jargs) < 0)
        goto error;

    va_end(args);

    return obj;

 error:
    virJSONValueFree(obj);
    virJSONValueFree(jargs);
    va_end(args);
    return NULL;
}
```

```c
static int
qemuMonitorJSONCommand(qemuMonitorPtr mon,
                       virJSONValuePtr cmd,
                       virJSONValuePtr *reply)
{
    return qemuMonitorJSONCommandWithFd(mon, cmd, -1, reply);
}
```

```c
static int
qemuMonitorJSONCommandWithFd(qemuMonitorPtr mon,
                             virJSONValuePtr cmd,
                             int scm_fd,
                             virJSONValuePtr *reply)
{
    int ret = -1;
    qemuMonitorMessage msg;
    char *cmdstr = NULL;
    char *id = NULL;

    *reply = NULL;

    memset(&msg, 0, sizeof(msg));

    if (virJSONValueObjectHasKey(cmd, "execute") == 1) {
        if (!(id = qemuMonitorNextCommandID(mon)))
            goto cleanup;
        if (virJSONValueObjectAppendString(cmd, "id", id) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Unable to append command 'id' string"));
            goto cleanup;
        }
    }

    if (!(cmdstr = virJSONValueToString(cmd, false)))
        goto cleanup;
    if (virAsprintf(&msg.txBuffer, "%s\r\n", cmdstr) < 0)
        goto cleanup;
    msg.txLength = strlen(msg.txBuffer);
    msg.txFD = scm_fd;

    VIR_DEBUG("Send command '%s' for write with FD %d", cmdstr, scm_fd);

    ret = qemuMonitorSend(mon, &msg);

    VIR_DEBUG("Receive command reply ret=%d rxObject=%p",
              ret, msg.rxObject);


    if (ret == 0) {
        if (!msg.rxObject) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Missing monitor reply object"));
            ret = -1;
        } else {
            *reply = msg.rxObject;
        }
    }

 cleanup:
    VIR_FREE(id);
    VIR_FREE(cmdstr);
    VIR_FREE(msg.txBuffer);

    return ret;
}
```

```c
int
qemuMonitorSend(qemuMonitorPtr mon,
                qemuMonitorMessagePtr msg)
{
    int ret = -1;

    /* Check whether qemu quit unexpectedly */
    if (mon->lastError.code != VIR_ERR_OK) {
        VIR_DEBUG("Attempt to send command while error is set %s",
                  NULLSTR(mon->lastError.message));
        virSetError(&mon->lastError);
        return -1;
    }

    mon->msg = msg;
    qemuMonitorUpdateWatch(mon);

    PROBE(QEMU_MONITOR_SEND_MSG,
          "mon=%p msg=%s fd=%d",
          mon, mon->msg->txBuffer, mon->msg->txFD);

    while (!mon->msg->finished) {
        if (virCondWait(&mon->notify, &mon->parent.lock) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Unable to wait on monitor condition"));
            goto cleanup;
        }
    }

    if (mon->lastError.code != VIR_ERR_OK) {
        VIR_DEBUG("Send command resulted in error %s",
                  NULLSTR(mon->lastError.message));
        virSetError(&mon->lastError);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    mon->msg = NULL;
    qemuMonitorUpdateWatch(mon);

    return ret;
}
```

# ここからqemuの世界

- QMP (Qemu Machine Protocol)

qemuインスタンスを外から制御するためのjsonベースのプロトコル

## 'drive-mirror' QMP

- qmp-commands.hx

```
    {
        .name       = "drive-mirror",
        .args_type  = "sync:s,device:B,target:s,speed:i?,mode:s?,format:s?,"
                      "node-name:s?,replaces:s?,"
                      "on-source-error:s?,on-target-error:s?,"
                      "unmap:b?,"
                      "granularity:i?,buf-size:i?",
        .mhandler.cmd_new = qmp_marshal_drive_mirror,
    },
```

```
drive-mirror
------------

Start mirroring a block device's writes to a new destination. target
specifies the target of the new image. If the file exists, or if it is
a device, it will be used as the new destination for writes. If it does not
exist, a new file will be created. format specifies the format of the
mirror image, default is to probe if mode='existing', else the format
of the source.

Arguments:

- "device": device name to operate on (json-string)
- "target": name of new image file (json-string)
- "format": format of new image (json-string, optional)
- "node-name": the name of the new block driver state in the node graph
               (json-string, optional)
- "replaces": the block driver node name to replace when finished
              (json-string, optional)
- "mode": how an image file should be created into the target
  file/device (NewImageMode, optional, default 'absolute-paths')
- "speed": maximum speed of the streaming job, in bytes per second
  (json-int)
- "granularity": granularity of the dirty bitmap, in bytes (json-int, optional)
- "buf-size": maximum amount of data in flight from source to target, in bytes
  (json-int, default 10M)
- "sync": what parts of the disk image should be copied to the destination;
  possibilities include "full" for all the disk, "top" for only the sectors
  allocated in the topmost image, or "none" to only replicate new I/O
  (MirrorSyncMode).
- "on-source-error": the action to take on an error on the source
  (BlockdevOnError, default 'report')
- "on-target-error": the action to take on an error on the target
  (BlockdevOnError, default 'report')
- "unmap": whether the target sectors should be discarded where source has only
  zeroes. (json-bool, optional, default true)

The default value of the granularity is the image cluster size clamped
between 4096 and 65536, if the image format defines one.  If the format
does not define a cluster size, the default value of the granularity
is 65536.


Example:

-> { "execute": "drive-mirror", "arguments": { "device": "ide-hd0",
                                               "target": "/some/place/my-image",
                                               "sync": "full",
                                               "format": "qcow2" } }
<- { "return": {} }

```

- qapi/block-core.json

```
##
# @drive-mirror
#
# Start mirroring a block device's writes to a new destination.
#
# @device:  the name of the device whose writes should be mirrored.
#
# @target: the target of the new image. If the file exists, or if it
#          is a device, the existing file/device will be used as the new
#          destination.  If it does not exist, a new file will be created.
#
# @format: #optional the format of the new destination, default is to
#          probe if @mode is 'existing', else the format of the source
#
# @node-name: #optional the new block driver state node name in the graph
#             (Since 2.1)
#
# @replaces: #optional with sync=full graph node name to be replaced by the new
#            image when a whole image copy is done. This can be used to repair
#            broken Quorum files. (Since 2.1)
#
# @mode: #optional whether and how QEMU should create a new image, default is
#        'absolute-paths'.
#
# @speed:  #optional the maximum speed, in bytes per second
#
# @sync: what parts of the disk image should be copied to the destination
#        (all the disk, only the sectors allocated in the topmost image, or
#        only new I/O).
#
# @granularity: #optional granularity of the dirty bitmap, default is 64K
#               if the image format doesn't have clusters, 4K if the clusters
#               are smaller than that, else the cluster size.  Must be a
#               power of 2 between 512 and 64M (since 1.4).
#
# @buf-size: #optional maximum amount of data in flight from source to
#            target (since 1.4).
#
# @on-source-error: #optional the action to take on an error on the source,
#                   default 'report'.  'stop' and 'enospc' can only be used
#                   if the block device supports io-status (see BlockInfo).
#
# @on-target-error: #optional the action to take on an error on the target,
#                   default 'report' (no limitations, since this applies to
#                   a different block device than @device).
# @unmap: #optional Whether to try to unmap target sectors where source has
#         only zero. If true, and target unallocated sectors will read as zero,
#         target image sectors will be unmapped; otherwise, zeroes will be
#         written. Both will result in identical contents.
#         Default is true. (Since 2.4)
#
# Returns: nothing on success
#          If @device is not a valid block device, DeviceNotFound
#
# Since 1.3
##
{ 'command': 'drive-mirror',
  'data': { 'device': 'str', 'target': 'str', '*format': 'str',
            '*node-name': 'str', '*replaces': 'str',
            'sync': 'MirrorSyncMode', '*mode': 'NewImageMode',
            '*speed': 'int', '*granularity': 'uint32',
            '*buf-size': 'int', '*on-source-error': 'BlockdevOnError',
            '*on-target-error': 'BlockdevOnError',
            '*unmap': 'bool' } }
```

- hmp.c

```c
void hmp_drive_mirror(Monitor *mon, const QDict *qdict)
{
    const char *device = qdict_get_str(qdict, "device");
    const char *filename = qdict_get_str(qdict, "target");
    const char *format = qdict_get_try_str(qdict, "format");
    bool reuse = qdict_get_try_bool(qdict, "reuse", false);
    bool full = qdict_get_try_bool(qdict, "full", false);
    enum NewImageMode mode;
    Error *err = NULL;

    if (!filename) {
        error_setg(&err, QERR_MISSING_PARAMETER, "target");
        hmp_handle_error(mon, &err);
        return;
    }

    if (reuse) {
        mode = NEW_IMAGE_MODE_EXISTING;
    } else {
        mode = NEW_IMAGE_MODE_ABSOLUTE_PATHS;
    }

    qmp_drive_mirror(device, filename, !!format, format,
                     false, NULL, false, NULL,
                     full ? MIRROR_SYNC_MODE_FULL : MIRROR_SYNC_MODE_TOP,
                     true, mode, false, 0, false, 0, false, 0,
                     false, 0, false, 0, false, true, &err);
    hmp_handle_error(mon, &err);
}
```

- blockdev.c

```c
void qmp_drive_mirror(const char *device, const char *target,
                      bool has_format, const char *format,
                      bool has_node_name, const char *node_name,
                      bool has_replaces, const char *replaces,
                      enum MirrorSyncMode sync,
                      bool has_mode, enum NewImageMode mode,
                      bool has_speed, int64_t speed,
                      bool has_granularity, uint32_t granularity,
                      bool has_buf_size, int64_t buf_size,
                      bool has_on_source_error, BlockdevOnError on_source_error,
                      bool has_on_target_error, BlockdevOnError on_target_error,
                      bool has_unmap, bool unmap,
                      Error **errp)
{
    BlockDriverState *bs;
    BlockBackend *blk;
    BlockDriverState *source, *target_bs;
    AioContext *aio_context;
    Error *local_err = NULL;
    QDict *options = NULL;
    int flags;
    int64_t size;
    int ret;

    blk = blk_by_name(device);
    if (!blk) {
        error_set(errp, ERROR_CLASS_DEVICE_NOT_FOUND,
                  "Device '%s' not found", device);
        return;
    }

    aio_context = blk_get_aio_context(blk);
    aio_context_acquire(aio_context);

    if (!blk_is_available(blk)) {
        error_setg(errp, QERR_DEVICE_HAS_NO_MEDIUM, device);
        goto out;
    }
    bs = blk_bs(blk);
    if (!has_mode) {
        mode = NEW_IMAGE_MODE_ABSOLUTE_PATHS;
    }

    if (!has_format) {
        format = mode == NEW_IMAGE_MODE_EXISTING ? NULL : bs->drv->format_name;
    }

    flags = bs->open_flags | BDRV_O_RDWR;
    source = backing_bs(bs);
    if (!source && sync == MIRROR_SYNC_MODE_TOP) {
        sync = MIRROR_SYNC_MODE_FULL;
    }
    if (sync == MIRROR_SYNC_MODE_NONE) {
        source = bs;
    }

    size = bdrv_getlength(bs);
    if (size < 0) {
        error_setg_errno(errp, -size, "bdrv_getlength failed");
        goto out;
    }

    if (has_replaces) {
        BlockDriverState *to_replace_bs;
        AioContext *replace_aio_context;
        int64_t replace_size;

        if (!has_node_name) {
            error_setg(errp, "a node-name must be provided when replacing a"
                             " named node of the graph");
            goto out;
        }

        to_replace_bs = check_to_replace_node(bs, replaces, &local_err);

        if (!to_replace_bs) {
            error_propagate(errp, local_err);
            goto out;
        }

        replace_aio_context = bdrv_get_aio_context(to_replace_bs);
        aio_context_acquire(replace_aio_context);
        replace_size = bdrv_getlength(to_replace_bs);
        aio_context_release(replace_aio_context);

        if (size != replace_size) {
            error_setg(errp, "cannot replace image with a mirror image of "
                             "different size");
            goto out;
        }
    }

    if ((sync == MIRROR_SYNC_MODE_FULL || !source)
        && mode != NEW_IMAGE_MODE_EXISTING)
    {
        /* create new image w/o backing file */
        assert(format);
        bdrv_img_create(target, format,
                        NULL, NULL, NULL, size, flags, &local_err, false);
    } else {
        switch (mode) {
        case NEW_IMAGE_MODE_EXISTING:
            break;
        case NEW_IMAGE_MODE_ABSOLUTE_PATHS:
            /* create new image with backing file */
            bdrv_img_create(target, format,
                            source->filename,
                            source->drv->format_name,
                            NULL, size, flags, &local_err, false);
            break;
        default:
            abort();
        }
    }

    if (local_err) {
        error_propagate(errp, local_err);
        goto out;
    }

    options = qdict_new();
    if (has_node_name) {
        qdict_put(options, "node-name", qstring_from_str(node_name));
    }
    if (format) {
        qdict_put(options, "driver", qstring_from_str(format));
    }

    /* Mirroring takes care of copy-on-write using the source's backing
     * file.
     */
    target_bs = NULL;
    ret = bdrv_open(&target_bs, target, NULL, options,
                    flags | BDRV_O_NO_BACKING, &local_err);
    if (ret < 0) {
        error_propagate(errp, local_err);
        goto out;
    }

    bdrv_set_aio_context(target_bs, aio_context);

    blockdev_mirror_common(bs, target_bs,
                           has_replaces, replaces, sync,
                           has_speed, speed,
                           has_granularity, granularity,
                           has_buf_size, buf_size,
                           has_on_source_error, on_source_error,
                           has_on_target_error, on_target_error,
                           has_unmap, unmap,
                           &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        bdrv_unref(target_bs);
    }
out:
    aio_context_release(aio_context);
}
```

- block.c

```c
void bdrv_img_create(const char *filename, const char *fmt,
                     const char *base_filename, const char *base_fmt,
                     char *options, uint64_t img_size, int flags,
                     Error **errp, bool quiet)
{
    QemuOptsList *create_opts = NULL;
    QemuOpts *opts = NULL;
    const char *backing_fmt, *backing_file;
    int64_t size;
    BlockDriver *drv, *proto_drv;
    Error *local_err = NULL;
    int ret = 0;

    /* Find driver and parse its options */
    drv = bdrv_find_format(fmt);
    if (!drv) {
        error_setg(errp, "Unknown file format '%s'", fmt);
        return;
    }

    proto_drv = bdrv_find_protocol(filename, true, errp);
    if (!proto_drv) {
        return;
    }

    if (!drv->create_opts) {
        error_setg(errp, "Format driver '%s' does not support image creation",
                   drv->format_name);
        return;
    }

    if (!proto_drv->create_opts) {
        error_setg(errp, "Protocol driver '%s' does not support image creation",
                   proto_drv->format_name);
        return;
    }

    create_opts = qemu_opts_append(create_opts, drv->create_opts);
    create_opts = qemu_opts_append(create_opts, proto_drv->create_opts);

    /* Create parameter list with default values */
    opts = qemu_opts_create(create_opts, NULL, 0, &error_abort);
    qemu_opt_set_number(opts, BLOCK_OPT_SIZE, img_size, &error_abort);

    /* Parse -o options */
    if (options) {
        qemu_opts_do_parse(opts, options, NULL, &local_err);
        if (local_err) {
            error_report_err(local_err);
            local_err = NULL;
            error_setg(errp, "Invalid options for file format '%s'", fmt);
            goto out;
        }
    }

    if (base_filename) {
        qemu_opt_set(opts, BLOCK_OPT_BACKING_FILE, base_filename, &local_err);
        if (local_err) {
            error_setg(errp, "Backing file not supported for file format '%s'",
                       fmt);
            goto out;
        }
    }

    if (base_fmt) {
        qemu_opt_set(opts, BLOCK_OPT_BACKING_FMT, base_fmt, &local_err);
        if (local_err) {
            error_setg(errp, "Backing file format not supported for file "
                             "format '%s'", fmt);
            goto out;
        }
    }

    backing_file = qemu_opt_get(opts, BLOCK_OPT_BACKING_FILE);
    if (backing_file) {
        if (!strcmp(filename, backing_file)) {
            error_setg(errp, "Error: Trying to create an image with the "
                             "same filename as the backing file");
            goto out;
        }
    }

    backing_fmt = qemu_opt_get(opts, BLOCK_OPT_BACKING_FMT);

    // The size for the image must always be specified, with one exception:
    // If we are using a backing file, we can obtain the size from there
    size = qemu_opt_get_size(opts, BLOCK_OPT_SIZE, 0);
    if (size == -1) {
        if (backing_file) {
            BlockDriverState *bs;
            char *full_backing = g_new0(char, PATH_MAX);
            int64_t size;
            int back_flags;
            QDict *backing_options = NULL;

            bdrv_get_full_backing_filename_from_filename(filename, backing_file,
                                                         full_backing, PATH_MAX,
                                                         &local_err);
            if (local_err) {
                g_free(full_backing);
                goto out;
            }

            /* backing files always opened read-only */
            back_flags = flags;
            back_flags &= ~(BDRV_O_RDWR | BDRV_O_SNAPSHOT | BDRV_O_NO_BACKING);

            if (backing_fmt) {
                backing_options = qdict_new();
                qdict_put(backing_options, "driver",
                          qstring_from_str(backing_fmt));
            }

            bs = NULL;
            ret = bdrv_open(&bs, full_backing, NULL, backing_options,
                            back_flags, &local_err);
            g_free(full_backing);
            if (ret < 0) {
                goto out;
            }
            size = bdrv_getlength(bs);
            if (size < 0) {
                error_setg_errno(errp, -size, "Could not get size of '%s'",
                                 backing_file);
                bdrv_unref(bs);
                goto out;
            }

            qemu_opt_set_number(opts, BLOCK_OPT_SIZE, size, &error_abort);

            bdrv_unref(bs);
        } else {
            error_setg(errp, "Image creation needs a size parameter");
            goto out;
        }
    }

    if (!quiet) {
        printf("Formatting '%s', fmt=%s ", filename, fmt);
        qemu_opts_print(opts, " ");
        puts("");
    }

    ret = bdrv_create(drv, filename, opts, &local_err);

    if (ret == -EFBIG) {
        /* This is generally a better message than whatever the driver would
         * deliver (especially because of the cluster_size_hint), since that
         * is most probably not much different from "image too large". */
        const char *cluster_size_hint = "";
        if (qemu_opt_get_size(opts, BLOCK_OPT_CLUSTER_SIZE, 0)) {
            cluster_size_hint = " (try using a larger cluster size)";
        }
        error_setg(errp, "The image size is too large for file format '%s'"
                   "%s", fmt, cluster_size_hint);
        error_free(local_err);
        local_err = NULL;
    }

out:
    qemu_opts_del(opts);
    qemu_opts_free(create_opts);
    if (local_err) {
        error_propagate(errp, local_err);
    }
}
```

- blockdev.c

```c
/* Parameter check and block job starting for drive mirroring.
 * Caller should hold @device and @target's aio context (must be the same).
 **/
static void blockdev_mirror_common(BlockDriverState *bs,
                                   BlockDriverState *target,
                                   bool has_replaces, const char *replaces,
                                   enum MirrorSyncMode sync,
                                   bool has_speed, int64_t speed,
                                   bool has_granularity, uint32_t granularity,
                                   bool has_buf_size, int64_t buf_size,
                                   bool has_on_source_error,
                                   BlockdevOnError on_source_error,
                                   bool has_on_target_error,
                                   BlockdevOnError on_target_error,
                                   bool has_unmap, bool unmap,
                                   Error **errp)
{

    if (!has_speed) {
        speed = 0;
    }
    if (!has_on_source_error) {
        on_source_error = BLOCKDEV_ON_ERROR_REPORT;
    }
    if (!has_on_target_error) {
        on_target_error = BLOCKDEV_ON_ERROR_REPORT;
    }
    if (!has_granularity) {
        granularity = 0;
    }
    if (!has_buf_size) {
        buf_size = 0;
    }
    if (!has_unmap) {
        unmap = true;
    }

    if (granularity != 0 && (granularity < 512 || granularity > 1048576 * 64)) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE, "granularity",
                   "a value in range [512B, 64MB]");
        return;
    }
    if (granularity & (granularity - 1)) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE, "granularity",
                   "power of 2");
        return;
    }

    if (bdrv_op_is_blocked(bs, BLOCK_OP_TYPE_MIRROR_SOURCE, errp)) {
        return;
    }
    if (bdrv_op_is_blocked(target, BLOCK_OP_TYPE_MIRROR_TARGET, errp)) {
        return;
    }
    if (target->blk) {
        error_setg(errp, "Cannot mirror to an attached block device");
        return;
    }

    if (!bs->backing && sync == MIRROR_SYNC_MODE_TOP) {
        sync = MIRROR_SYNC_MODE_FULL;
    }

    /* pass the node name to replace to mirror start since it's loose coupling
     * and will allow to check whether the node still exist at mirror completion
     */
    mirror_start(bs, target,
                 has_replaces ? replaces : NULL,
                 speed, granularity, buf_size, sync,
                 on_source_error, on_target_error, unmap,
                 block_job_cb, bs, errp);
}
```

- block/mirror.c

```c
void mirror_start(BlockDriverState *bs, BlockDriverState *target,
                  const char *replaces,
                  int64_t speed, uint32_t granularity, int64_t buf_size,
                  MirrorSyncMode mode, BlockdevOnError on_source_error,
                  BlockdevOnError on_target_error,
                  bool unmap,
                  BlockCompletionFunc *cb,
                  void *opaque, Error **errp)
{
    bool is_none_mode;
    BlockDriverState *base;

    if (mode == MIRROR_SYNC_MODE_INCREMENTAL) {
        error_setg(errp, "Sync mode 'incremental' not supported");
        return;
    }
    is_none_mode = mode == MIRROR_SYNC_MODE_NONE;
    base = mode == MIRROR_SYNC_MODE_TOP ? backing_bs(bs) : NULL;
    mirror_start_job(bs, target, replaces,
                     speed, granularity, buf_size,
                     on_source_error, on_target_error, unmap, cb, opaque, errp,
                     &mirror_job_driver, is_none_mode, base);
}
```

```c
static void mirror_start_job(BlockDriverState *bs, BlockDriverState *target,
                             const char *replaces,
                             int64_t speed, uint32_t granularity,
                             int64_t buf_size,
                             BlockdevOnError on_source_error,
                             BlockdevOnError on_target_error,
                             bool unmap,
                             BlockCompletionFunc *cb,
                             void *opaque, Error **errp,
                             const BlockJobDriver *driver,
                             bool is_none_mode, BlockDriverState *base)
{
    MirrorBlockJob *s;
    BlockDriverState *replaced_bs;

    if (granularity == 0) {
        granularity = bdrv_get_default_bitmap_granularity(target);
    }

    assert ((granularity & (granularity - 1)) == 0);

    if ((on_source_error == BLOCKDEV_ON_ERROR_STOP ||
         on_source_error == BLOCKDEV_ON_ERROR_ENOSPC) &&
        (!bs->blk || !blk_iostatus_is_enabled(bs->blk))) {
        error_setg(errp, QERR_INVALID_PARAMETER, "on-source-error");
        return;
    }

    if (buf_size < 0) {
        error_setg(errp, "Invalid parameter 'buf-size'");
        return;
    }

    if (buf_size == 0) {
        buf_size = DEFAULT_MIRROR_BUF_SIZE;
    }

    /* We can't support this case as long as the block layer can't handle
     * multiple BlockBackends per BlockDriverState. */
    if (replaces) {
        replaced_bs = bdrv_lookup_bs(replaces, replaces, errp);
        if (replaced_bs == NULL) {
            return;
        }
    } else {
        replaced_bs = bs;
    }
    if (replaced_bs->blk && target->blk) {
        error_setg(errp, "Can't create node with two BlockBackends");
        return;
    }

    s = block_job_create(driver, bs, speed, cb, opaque, errp);
    if (!s) {
        return;
    }

    s->replaces = g_strdup(replaces);
    s->on_source_error = on_source_error;
    s->on_target_error = on_target_error;
    s->target = target;
    s->is_none_mode = is_none_mode;
    s->base = base;
    s->granularity = granularity;
    s->buf_size = ROUND_UP(buf_size, granularity);
    s->unmap = unmap;

    s->dirty_bitmap = bdrv_create_dirty_bitmap(bs, granularity, NULL, errp);
    if (!s->dirty_bitmap) {
        g_free(s->replaces);
        block_job_unref(&s->common);
        return;
    }

    bdrv_op_block_all(s->target, s->common.blocker);

    if (s->target->blk) {
        blk_set_on_error(s->target->blk, on_target_error, on_target_error);
        blk_iostatus_enable(s->target->blk);
    }
    s->common.co = qemu_coroutine_create(mirror_run);
    trace_mirror_start(bs, s, s->common.co, opaque);
    qemu_coroutine_enter(s->common.co, s);
}
```

- blockjob.c

```c
void *block_job_create(const BlockJobDriver *driver, BlockDriverState *bs,
                       int64_t speed, BlockCompletionFunc *cb,
                       void *opaque, Error **errp)
{
    BlockJob *job;

    if (bs->job) {
        error_setg(errp, QERR_DEVICE_IN_USE, bdrv_get_device_name(bs));
        return NULL;
    }
    bdrv_ref(bs);
    job = g_malloc0(driver->instance_size);
    error_setg(&job->blocker, "block device is in use by block job: %s",
               BlockJobType_lookup[driver->job_type]);
    bdrv_op_block_all(bs, job->blocker);
    bdrv_op_unblock(bs, BLOCK_OP_TYPE_DATAPLANE, job->blocker);

    job->driver        = driver;
    job->id            = g_strdup(bdrv_get_device_name(bs));
    job->bs            = bs;
    job->cb            = cb;
    job->opaque        = opaque;
    job->busy          = true;
    job->refcnt        = 1;
    bs->job = job;

    bdrv_add_aio_context_notifier(bs, block_job_attached_aio_context,
                                  block_job_detach_aio_context, job);

    /* Only set speed when necessary to avoid NotSupported error */
    if (speed != 0) {
        Error *local_err = NULL;

        block_job_set_speed(job, speed, &local_err);
        if (local_err) {
            block_job_unref(job);
            error_propagate(errp, local_err);
            return NULL;
        }
    }
    return job;
}
```

- block/dirty-bitmap.c

```c
BdrvDirtyBitmap *bdrv_create_dirty_bitmap(BlockDriverState *bs,
                                          uint32_t granularity,
                                          const char *name,
                                          Error **errp)
{
    int64_t bitmap_size;
    BdrvDirtyBitmap *bitmap;
    uint32_t sector_granularity;

    assert((granularity & (granularity - 1)) == 0);

    if (name && bdrv_find_dirty_bitmap(bs, name)) {
        error_setg(errp, "Bitmap already exists: %s", name);
        return NULL;
    }
    sector_granularity = granularity >> BDRV_SECTOR_BITS;
    assert(sector_granularity);
    bitmap_size = bdrv_nb_sectors(bs);
    if (bitmap_size < 0) {
        error_setg_errno(errp, -bitmap_size, "could not get length of device");
        errno = -bitmap_size;
        return NULL;
    }
    bitmap = g_new0(BdrvDirtyBitmap, 1);
    bitmap->bitmap = hbitmap_alloc(bitmap_size, ctz32(sector_granularity));
    bitmap->size = bitmap_size;
    bitmap->name = g_strdup(name);
    bitmap->disabled = false;
    QLIST_INSERT_HEAD(&bs->dirty_bitmaps, bitmap, list);
    return bitmap;
}
```

- block.c

```c
void bdrv_op_block_all(BlockDriverState *bs, Error *reason)
{
    int i;
    for (i = 0; i < BLOCK_OP_TYPE_MAX; i++) {
        bdrv_op_block(bs, i, reason);
    }
}
```

- block/block-backend.c

```c
void blk_iostatus_enable(BlockBackend *blk)
{
    blk->iostatus_enabled = true;
    blk->iostatus = BLOCK_DEVICE_IO_STATUS_OK;
}
```

- util/qemu-coroutine.c

```c
Coroutine *qemu_coroutine_create(CoroutineEntry *entry)
{
    Coroutine *co = NULL;

    if (CONFIG_COROUTINE_POOL) {
        co = QSLIST_FIRST(&alloc_pool);
        if (!co) {
            if (release_pool_size > POOL_BATCH_SIZE) {
                /* Slow path; a good place to register the destructor, too.  */
                if (!coroutine_pool_cleanup_notifier.notify) {
                    coroutine_pool_cleanup_notifier.notify = coroutine_pool_cleanup;
                    qemu_thread_atexit_add(&coroutine_pool_cleanup_notifier);
                }

                /* This is not exact; there could be a little skew between
                 * release_pool_size and the actual size of release_pool.  But
                 * it is just a heuristic, it does not need to be perfect.
                 */
                alloc_pool_size = atomic_xchg(&release_pool_size, 0);
                QSLIST_MOVE_ATOMIC(&alloc_pool, &release_pool);
                co = QSLIST_FIRST(&alloc_pool);
            }
        }
        if (co) {
            QSLIST_REMOVE_HEAD(&alloc_pool, pool_next);
            alloc_pool_size--;
        }
    }

    if (!co) {
        co = qemu_coroutine_new();
    }

    co->entry = entry;
    QTAILQ_INIT(&co->co_queue_wakeup);
    return co;
}
```

- block/mirror.c

```c
static void coroutine_fn mirror_run(void *opaque)
{
    MirrorBlockJob *s = opaque;
    MirrorExitData *data;
    BlockDriverState *bs = s->common.bs;
    int64_t sector_num, end, length;
    uint64_t last_pause_ns;
    BlockDriverInfo bdi;
    char backing_filename[2]; /* we only need 2 characters because we are only
                                 checking for a NULL string */
    int ret = 0;
    int n;
    int target_cluster_size = BDRV_SECTOR_SIZE;

    if (block_job_is_cancelled(&s->common)) {
        goto immediate_exit;
    }

    s->bdev_length = bdrv_getlength(bs);
    if (s->bdev_length < 0) {
        ret = s->bdev_length;
        goto immediate_exit;
    } else if (s->bdev_length == 0) {
        /* Report BLOCK_JOB_READY and wait for complete. */
        block_job_event_ready(&s->common);
        s->synced = true;
        while (!block_job_is_cancelled(&s->common) && !s->should_complete) {
            block_job_yield(&s->common);
        }
        s->common.cancelled = false;
        goto immediate_exit;
    }

    length = DIV_ROUND_UP(s->bdev_length, s->granularity);
    s->in_flight_bitmap = bitmap_new(length);

    /* If we have no backing file yet in the destination, we cannot let
     * the destination do COW.  Instead, we copy sectors around the
     * dirty data if needed.  We need a bitmap to do that.
     */
    bdrv_get_backing_filename(s->target, backing_filename,
                              sizeof(backing_filename));
    if (!bdrv_get_info(s->target, &bdi) && bdi.cluster_size) {
        target_cluster_size = bdi.cluster_size;
    }
    if (backing_filename[0] && !s->target->backing
        && s->granularity < target_cluster_size) {
        s->buf_size = MAX(s->buf_size, target_cluster_size);
        s->cow_bitmap = bitmap_new(length);
    }
    s->target_cluster_sectors = target_cluster_size >> BDRV_SECTOR_BITS;
    s->max_iov = MIN(s->common.bs->bl.max_iov, s->target->bl.max_iov);

    end = s->bdev_length / BDRV_SECTOR_SIZE;
    s->buf = qemu_try_blockalign(bs, s->buf_size);
    if (s->buf == NULL) {
        ret = -ENOMEM;
        goto immediate_exit;
    }

    mirror_free_init(s);

    last_pause_ns = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
    if (!s->is_none_mode) {
        /* First part, loop on the sectors and initialize the dirty bitmap.  */
        BlockDriverState *base = s->base;
        bool mark_all_dirty = s->base == NULL && !bdrv_has_zero_init(s->target);

        for (sector_num = 0; sector_num < end; ) {
            /* Just to make sure we are not exceeding int limit. */
            int nb_sectors = MIN(INT_MAX >> BDRV_SECTOR_BITS,
                                 end - sector_num);
            int64_t now = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);

            if (now - last_pause_ns > SLICE_TIME) {
                last_pause_ns = now;
                block_job_sleep_ns(&s->common, QEMU_CLOCK_REALTIME, 0);
            } else {
                block_job_pause_point(&s->common);
            }

            if (block_job_is_cancelled(&s->common)) {
                goto immediate_exit;
            }

            ret = bdrv_is_allocated_above(bs, base, sector_num, nb_sectors, &n);

            if (ret < 0) {
                goto immediate_exit;
            }

            assert(n > 0);
            if (ret == 1 || mark_all_dirty) {
                bdrv_set_dirty_bitmap(s->dirty_bitmap, sector_num, n);
            }
            sector_num += n;
        }
    }

    bdrv_dirty_iter_init(s->dirty_bitmap, &s->hbi);
    for (;;) {
        uint64_t delay_ns = 0;
        int64_t cnt;
        bool should_complete;

        if (s->ret < 0) {
            ret = s->ret;
            goto immediate_exit;
        }

        block_job_pause_point(&s->common);

        cnt = bdrv_get_dirty_count(s->dirty_bitmap);
        /* s->common.offset contains the number of bytes already processed so
         * far, cnt is the number of dirty sectors remaining and
         * s->sectors_in_flight is the number of sectors currently being
         * processed; together those are the current total operation length */
        s->common.len = s->common.offset +
                        (cnt + s->sectors_in_flight) * BDRV_SECTOR_SIZE;

        /* Note that even when no rate limit is applied we need to yield
         * periodically with no pending I/O so that bdrv_drain_all() returns.
         * We do so every SLICE_TIME nanoseconds, or when there is an error,
         * or when the source is clean, whichever comes first.
         */
        if (qemu_clock_get_ns(QEMU_CLOCK_REALTIME) - last_pause_ns < SLICE_TIME &&
            s->common.iostatus == BLOCK_DEVICE_IO_STATUS_OK) {
            if (s->in_flight == MAX_IN_FLIGHT || s->buf_free_count == 0 ||
                (cnt == 0 && s->in_flight > 0)) {
                trace_mirror_yield(s, s->in_flight, s->buf_free_count, cnt);
                mirror_wait_for_io(s);
                continue;
            } else if (cnt != 0) {
                delay_ns = mirror_iteration(s);
            }
        }

        should_complete = false;
        if (s->in_flight == 0 && cnt == 0) {
            trace_mirror_before_flush(s);
            ret = bdrv_flush(s->target);
            if (ret < 0) {
                if (mirror_error_action(s, false, -ret) ==
                    BLOCK_ERROR_ACTION_REPORT) {
                    goto immediate_exit;
                }
            } else {
                /* We're out of the streaming phase.  From now on, if the job
                 * is cancelled we will actually complete all pending I/O and
                 * report completion.  This way, block-job-cancel will leave
                 * the target in a consistent state.
                 */
                if (!s->synced) {
                    block_job_event_ready(&s->common);
                    s->synced = true;
                }

                should_complete = s->should_complete ||
                    block_job_is_cancelled(&s->common);
                cnt = bdrv_get_dirty_count(s->dirty_bitmap);
            }
        }

        if (cnt == 0 && should_complete) {
            /* The dirty bitmap is not updated while operations are pending.
             * If we're about to exit, wait for pending operations before
             * calling bdrv_get_dirty_count(bs), or we may exit while the
             * source has dirty data to copy!
             *
             * Note that I/O can be submitted by the guest while
             * mirror_populate runs.
             */
            trace_mirror_before_drain(s, cnt);
            bdrv_co_drain(bs);
            cnt = bdrv_get_dirty_count(s->dirty_bitmap);
        }

        ret = 0;
        trace_mirror_before_sleep(s, cnt, s->synced, delay_ns);
        if (!s->synced) {
            block_job_sleep_ns(&s->common, QEMU_CLOCK_REALTIME, delay_ns);
            if (block_job_is_cancelled(&s->common)) {
                break;
            }
        } else if (!should_complete) {
            delay_ns = (s->in_flight == 0 && cnt == 0 ? SLICE_TIME : 0);
            block_job_sleep_ns(&s->common, QEMU_CLOCK_REALTIME, delay_ns);
        } else if (cnt == 0) {
            /* The two disks are in sync.  Exit and report successful
             * completion.
             */
            assert(QLIST_EMPTY(&bs->tracked_requests));
            s->common.cancelled = false;
            break;
        }
        last_pause_ns = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
    }

immediate_exit:
    if (s->in_flight > 0) {
        /* We get here only if something went wrong.  Either the job failed,
         * or it was cancelled prematurely so that we do not guarantee that
         * the target is a copy of the source.
         */
        assert(ret < 0 || (!s->synced && block_job_is_cancelled(&s->common)));
        mirror_drain(s);
    }

    assert(s->in_flight == 0);
    qemu_vfree(s->buf);
    g_free(s->cow_bitmap);
    g_free(s->in_flight_bitmap);
    bdrv_release_dirty_bitmap(bs, s->dirty_bitmap);
    if (s->target->blk) {
        blk_iostatus_disable(s->target->blk);
    }

    data = g_malloc(sizeof(*data));
    data->ret = ret;
    /* Before we switch to target in mirror_exit, make sure data doesn't
     * change. */
    bdrv_drained_begin(s->common.bs);
    if (qemu_get_aio_context() == bdrv_get_aio_context(bs)) {
        /* FIXME: virtio host notifiers run on iohandler_ctx, therefore the
         * above bdrv_drained_end isn't enough to quiesce it. This is ugly, we
         * need a block layer API change to achieve this. */
        aio_disable_external(iohandler_get_aio_context());
    }
    block_job_defer_to_main_loop(&s->common, mirror_exit, data);
}
```
