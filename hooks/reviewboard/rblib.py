#
# Copyright (c) 2011 by Delphix.
# All rights reserved.
#

#
# Delphix ReviewBoard integration library.  This module is based on the RBTools
# package, and is designed solely to work with the Delphix ReviewBoard
# installation in the context of executing git hooks.
#
# It automatically handles logging into the server as the 'git' user, which is a
# normal user with the additional privilege of being able to change the status
# of other user's reviews.
#
# To use the library, simply do the following:
#
#   server = rblib.ReviewBoardServer()
#
# The server currently supports the following methods:
#
#   get_pending_review_requests([olderthan])
#
#       Return a list of all reviews in the 'pending' state.
#
#   get_review_request(id)
#
#       Get a particular review request.
#
#   mark_submitted(request)
#
#       Mark a particular review request as submitted.
#

#
# Copyright (c) 2007-2010  Christian Hammond
# Copyright (c) 2007-2010  David Trowbridge
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#

###
# Configuration Options
###

REVIEWBOARD_URL = "<rb_url>"
REVIEWBOARD_USER = "<username>"
REVIEWBOARD_PASSWORD = "<password>"

###
# End of Configuration Options
###

import base64
import cookielib
import difflib
import getpass
import marshal
import mimetools
import ntpath
import os
import re
import socket
import stat
import subprocess
import sys
import tempfile
import datetime
import urllib
import urllib2
from optparse import OptionParser
from pkg_resources import parse_version
from tempfile import mkstemp
from urlparse import urljoin, urlparse

try:
    from hashlib import md5
except ImportError:
    # Support Python versions before 2.5.
    from md5 import md5

try:
    # Specifically import json_loads, to work around some issues with
    # installations containing incompatible modules named "json".
    from json import loads as json_loads
except ImportError:
    from simplejson import loads as json_loads

import posixpath as cpath

class APIError(Exception):
    def __init__(self, http_status, error_code, rsp=None, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)
        self.http_status = http_status
        self.error_code = error_code
        self.rsp = rsp

    def __str__(self):
        code_str = "HTTP %d" % self.http_status

        if self.error_code:
            code_str += ', API Error %d' % self.error_code

        if self.rsp and 'err' in self.rsp:
            return '%s (%s)' % (self.rsp['err']['msg'], code_str)
        else:
            return code_str


class HTTPRequest(urllib2.Request):
    def __init__(self, url, body, headers={}, method="PUT"):
        urllib2.Request.__init__(self, url, body, headers)
        self.method = method

    def get_method(self):
        return self.method


class PresetHTTPAuthHandler(urllib2.BaseHandler):
    """urllib2 handler that conditionally presets the use of HTTP Basic Auth.

    This is used when specifying --username= on the command line. It will
    force an HTTP_AUTHORIZATION header with the user info, asking the user
    for any missing info beforehand. It will then try this header for that
    first request.

    It will only do this once.
    """
    handler_order = 480 # After Basic auth

    def __init__(self, url, password_mgr):
        self.url = url
        self.password_mgr = password_mgr
        self.used = False

    def reset(self):
        self.password_mgr.rb_user = None
        self.password_mgr.rb_pass = None
        self.used = False

    def http_request(self, request):
        if REVIEWBOARD_USER and not self.used:
            # Note that we call password_mgr.find_user_password to get the
            # username and password we're working with. This allows us to
            # prompt if, say, --username was specified but --password was not.
            username, password = \
                self.password_mgr.find_user_password('Web API', self.url)
            raw = '%s:%s' % (username, password)
            request.add_header(
                urllib2.HTTPBasicAuthHandler.auth_header,
                'Basic %s' % base64.b64encode(raw).strip())
            self.used = True

        return request

    https_request = http_request


class ReviewBoardHTTPErrorProcessor(urllib2.HTTPErrorProcessor):
    """Processes HTTP error codes.

    Python 2.6 gets HTTP error code processing right, but 2.4 and 2.5 only
    accepts HTTP 200 and 206 as success codes. This handler ensures that
    anything in the 200 range is a success.
    """
    def http_response(self, request, response):
        if not (200 <= response.code < 300):
            response = self.parent.error('http', request, response,
                                         response.code, response.msg,
                                         response.info())

        return response

    https_response = http_response


class ReviewBoardHTTPBasicAuthHandler(urllib2.HTTPBasicAuthHandler):
    """Custom Basic Auth handler that doesn't retry excessively.

    urllib2's HTTPBasicAuthHandler retries over and over, which is useless.
    This subclass only retries once to make sure we've attempted with a
    valid username and password. It will then fail so we can use
    tempt_fate's retry handler.
    """
    def __init__(self, *args, **kwargs):
        urllib2.HTTPBasicAuthHandler.__init__(self, *args, **kwargs)
        self._retried = False

    def retry_http_basic_auth(self, *args, **kwargs):
        if not self._retried:
            self._retried = True
            response = urllib2.HTTPBasicAuthHandler.retry_http_basic_auth(
                self, *args, **kwargs)

            if response.code != 401:
                self._retried = False

            return response
        else:
            return None


class ReviewBoardHTTPPasswordMgr(urllib2.HTTPPasswordMgr):
    """
    Adds HTTP authentication support for URLs.

    Python 2.4's password manager has a bug in http authentication when the
    target server uses a non-standard port.  This works around that bug on
    Python 2.4 installs. This also allows post-review to prompt for passwords
    in a consistent way.

    See: http://bugs.python.org/issue974757
    """
    def __init__(self, reviewboard_url, rb_user=None, rb_pass=None):
        self.passwd  = {}
        self.rb_url  = reviewboard_url
        self.rb_user = rb_user
        self.rb_pass = rb_pass

    def find_user_password(self, realm, uri):
        if uri.startswith(self.rb_url):
            if self.rb_user is None or self.rb_pass is None:

                print "==> HTTP Authentication Required"
                print 'Enter authorization information for "%s" at %s' % \
                    (realm, urlparse(uri)[1])

                if not self.rb_user:
                    self.rb_user = raw_input('Username: ')

                if not self.rb_pass:
                    self.rb_pass = getpass.getpass('Password: ')

            return self.rb_user, self.rb_pass
        else:
            # If this is an auth request for some other domain (since HTTP
            # handlers are global), fall back to standard password management.
            return urllib2.HTTPPasswordMgr.find_user_password(self, realm, uri)


class ReviewBoardServer(object):
    """
    An instance of a Review Board server.
    """
    def __init__(self):
        self.url = REVIEWBOARD_URL
        if self.url[-1] != '/':
            self.url += '/'
        self._server_info = None
        self.root_resource = None

        if 'HOME' in os.environ:
            homepath = os.environ["HOME"]
        else:
            homepath = ''

        # Load the config and cookie files
        self.cookie_file = os.path.join(homepath, ".post-review-cookies.txt")
        self.cookie_jar  = cookielib.MozillaCookieJar(self.cookie_file)

        if self.cookie_file:
            try:
                self.cookie_jar.load(self.cookie_file, ignore_expires=True)
            except IOError:
                pass

        # Set up the HTTP libraries to support all of the features we need.
        cookie_handler = urllib2.HTTPCookieProcessor(self.cookie_jar)
        password_mgr = ReviewBoardHTTPPasswordMgr(self.url, REVIEWBOARD_USER,
            REVIEWBOARD_PASSWORD)
        basic_auth_handler  = ReviewBoardHTTPBasicAuthHandler(password_mgr)
        digest_auth_handler = urllib2.HTTPDigestAuthHandler(password_mgr)
        self.preset_auth_handler = PresetHTTPAuthHandler(self.url, password_mgr)
        http_error_processor = ReviewBoardHTTPErrorProcessor()

        opener = urllib2.build_opener(cookie_handler, basic_auth_handler,
            digest_auth_handler, self.preset_auth_handler, http_error_processor)
        opener.addheaders = [('User-agent', 'rblib')]
        urllib2.install_opener(opener)

        self.login()

    def login(self, force=False):
        """
        Logs in to a Review Board server, prompting the user for login
        information if needed.
        """

        self.root_resource = self.api_get('api/')
        rsp = self.api_get(self.root_resource['links']['info']['href'])

        self.rb_version = rsp['info']['product']['package_version']

        if force:
            self.preset_auth_handler.reset()

    def has_valid_cookie(self):
        """
        Load the user's cookie file and see if they have a valid
        'rbsessionid' cookie for the current Review Board server.  Returns
        true if so and false otherwise.
        """
        try:
            parsed_url = urlparse(self.url)
            host = parsed_url[1]
            path = parsed_url[2] or '/'

            # Cookie files don't store port numbers, unfortunately, so
            # get rid of the port number if it's present.
            host = host.split(":")[0]

            # Cookie files also append .local to bare hostnames
            if '.' not in host:
                host += '.local'

            try:
                cookie = self.cookie_jar._cookies[host][path]['rbsessionid']

                if not cookie.is_expired():
                    return True

            except KeyError:
                pass

        except IOError, error:
            pass

        return False

    def _get_server_info(self):
        if not self._server_info:
            self._server_info = self._info.find_server_repository_info(self)

        return self._server_info

    info = property(_get_server_info)

    def process_json(self, data):
        """
        Loads in a JSON file and returns the data if successful. On failure,
        APIError is raised.
        """
        rsp = json_loads(data)

        if rsp['stat'] == 'fail':
            # With the new API, we should get something other than HTTP
            # 200 for errors, in which case we wouldn't get this far.
            self.process_error(200, data)

        return rsp

    def process_error(self, http_status, data):
        """Processes an error, raising an APIError with the information."""
        try:
            rsp = json_loads(data)

            assert rsp['stat'] == 'fail'

            raise APIError(http_status, rsp['err']['code'], rsp,
                           rsp['err']['msg'])
        except ValueError:
            raise APIError(http_status, None, None, data)

    def http_get(self, path):
        """
        Performs an HTTP GET on the specified path, storing any cookies that
        were set.
        """

        url = self._make_url(path)
        rsp = urllib2.urlopen(url).read()

        try:
            self.cookie_jar.save(self.cookie_file)
        except IOError, e:
            pass
        return rsp

    def _make_url(self, path):
        """Given a path on the server returns a full http:// style url"""
        if path.startswith('http'):
            # This is already a full path.
            return path

        app = urlparse(self.url)[2]

        if path[0] == '/':
            url = urljoin(self.url, app[:-1] + path)
        else:
            url = urljoin(self.url, app + path)

        if not url.startswith('http'):
            url = 'http://%s' % url
        return url

    def api_get(self, path, args=None):
        """
        Performs an API call using HTTP GET at the specified path.
        """
        if args:
            first = True
            for name in args:
                if first:
                    path += "?"
                    first = False
                else:
                    path += "&"
                path += "%s=%s"%(name, args[name])
        try:
            return self.process_json(self.http_get(path))
        except urllib2.HTTPError, e:
            self.process_error(e.code, e.read())

    def http_post(self, path, fields, files=None):
        """
        Performs an HTTP POST on the specified path, storing any cookies that
        were set.
        """
        if fields:
            debug_fields = fields.copy()
        else:
            debug_fields = {}

        if 'password' in debug_fields:
            debug_fields["password"] = "**************"
        url = self._make_url(path)

        content_type, body = self._encode_multipart_formdata(fields, files)
        headers = {
            'Content-Type': content_type,
            'Content-Length': str(len(body))
        }

        try:
            r = urllib2.Request(url, body, headers)
            data = urllib2.urlopen(r).read()
            try:
                self.cookie_jar.save(self.cookie_file)
            except IOError, e:
                pass
            return data
        except urllib2.HTTPError, e:
            # Re-raise so callers can interpret it.
            raise e
        except urllib2.URLError, e:
            try:
                e.read()
            except AttributeError:
                pass

            die("Unable to access %s. The host path may be invalid\n%s" % \
                (url, e))

    def http_put(self, path, fields):
        """
        Performs an HTTP PUT on the specified path, storing any cookies that
        were set.
        """
        url = self._make_url(path)

        content_type, body = self._encode_multipart_formdata(fields, None)
        headers = {
            'Content-Type': content_type,
            'Content-Length': str(len(body))
        }

        try:
            r = HTTPRequest(url, body, headers, method='PUT')
            data = urllib2.urlopen(r).read()
            self.cookie_jar.save(self.cookie_file)
            return data
        except urllib2.HTTPError, e:
            # Re-raise so callers can interpret it.
            raise e
        except urllib2.URLError, e:
            try:
                e.read()
            except AttributeError:
                pass

            die("Unable to access %s. The host path may be invalid\n%s" % \
                (url, e))

    def http_delete(self, path):
        """
        Performs an HTTP DELETE on the specified path, storing any cookies that
        were set.
        """
        url = self._make_url(path)

        try:
            r = HTTPRequest(url, body, headers, method='DELETE')
            data = urllib2.urlopen(r).read()
            self.cookie_jar.save(self.cookie_file)
            return data
        except urllib2.HTTPError, e:
            # Re-raise so callers can interpret it.
            raise e
        except urllib2.URLError, e:
            try:
                e.read()
            except AttributeError:
                pass

            die("Unable to access %s. The host path may be invalid\n%s" % \
                (url, e))

    def api_post(self, path, fields=None, files=None):
        """
        Performs an API call using HTTP POST at the specified path.
        """
        try:
            return self.process_json(self.http_post(path, fields, files))
        except urllib2.HTTPError, e:
            self.process_error(e.code, e.read())

    def api_put(self, path, fields=None):
        """
        Performs an API call using HTTP PUT at the specified path.
        """
        try:
            return self.process_json(self.http_put(path, fields))
        except urllib2.HTTPError, e:
            self.process_error(e.code, e.read())

    def api_delete(self, path):
        """
        Performs an API call using HTTP DELETE at the specified path.
        """
        try:
            return self.process_json(self.http_delete(path))
        except urllib2.HTTPError, e:
            self.process_error(e.code, e.read())

    def _encode_multipart_formdata(self, fields, files):
        """
        Encodes data for use in an HTTP POST.
        """
        BOUNDARY = mimetools.choose_boundary()
        content = ""

        fields = fields or {}
        files = files or {}

        for key in fields:
            content += "--" + BOUNDARY + "\r\n"
            content += "Content-Disposition: form-data; name=\"%s\"\r\n" % key
            content += "\r\n"
            content += str(fields[key]) + "\r\n"

        for key in files:
            filename = files[key]['filename']
            value = files[key]['content']
            content += "--" + BOUNDARY + "\r\n"
            content += "Content-Disposition: form-data; name=\"%s\"; " % key
            content += "filename=\"%s\"\r\n" % filename
            content += "\r\n"
            content += value + "\r\n"

        content += "--" + BOUNDARY + "--\r\n"
        content += "\r\n"

        content_type = "multipart/form-data; boundary=%s" % BOUNDARY

        return content_type, content

    def get_review_request(self, rid):
        """
        Returns the review request with the specified ID.
        """
        url = '%s%s/' % (
            self.root_resource['links']['review_requests']['href'], rid)

        rsp = self.api_get(url)

        return rsp['review_request']

    def get_pending_reviews(self, older_than=None):
        """
        Return a list of all reviews in the pending state
        """
        params = {
            'status': 'pending',
            'max-results': 50
        }

        if older_than:
            params['last-updated-to'] = str(older_than)

	return self.api_get_list(
	    self.root_resource['links']['review_requests']['href'],
	    'review_requests', params)

    def api_get_list(self, link, name, params={ 'max-results': 50 }):
        result = self.api_get(link, params)
        ret = result[name]
	offset = 0
	pagesize = params['max-results']
        while offset + pagesize < result['total_results']:
             offset += pagesize
             params['start'] = offset
             result = self.api_get(link, params)
             ret += result[name]

        return ret

    def get_group(self, groupname):
	"""
	Returns the group with the given name.
	"""
        url = '%s%s/' % (
            self.root_resource['links']['groups']['href'], groupname)

	return self.api_get(url)['group']

    def mark_submitted(self, review_request):
        self.api_put(review_request['links']['self']['href'], {
            'status': 'submitted',
        })


def die(msg=None):
    if msg:
        print msg

    sys.exit(1)
