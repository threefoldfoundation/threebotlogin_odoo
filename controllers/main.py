# -*- coding: utf-8 -*-
# Part of Odoo. See LICENSE file for full copyright and licensing details.

import functools
import logging

import json
import uuid
import time
import base64

import requests
import nacl.encoding
import nacl.signing
from nacl.public import Box

import werkzeug.urls
import werkzeug.utils
from werkzeug.exceptions import BadRequest

from odoo import api, http, SUPERUSER_ID, _
from odoo.exceptions import AccessDenied
from odoo.http import request
from odoo import registry as registry_get

from odoo.addons.auth_signup.controllers.main import AuthSignupHome as Home
from odoo.addons.web.controllers.main import db_monodb, ensure_db, set_cookie_and_redirect, login_and_redirect


_logger = logging.getLogger(__name__)


#----------------------------------------------------------
# helpers
#----------------------------------------------------------
def fragment_to_query_string(func):
    @functools.wraps(func)
    def wrapper(self, *a, **kw):
        kw.pop('debug', False)
        if not kw:
            return """<html><head><script>
                var l = window.location;
                var q = l.hash.substring(1);
                var r = l.pathname + l.search;
                if(q.length !== 0) {
                    var s = l.search ? (l.search === '?' ? '' : '&') : '?';
                    r = l.pathname + l.search + s + q;
                }
                if (r == l.pathname) {
                    r = '/';
                }
                window.location = r;
            </script></head><body></body></html>"""
        return func(self, *a, **kw)
    return wrapper


#----------------------------------------------------------
# Controller
#----------------------------------------------------------
class OAuthLogin(Home):
    def list_providers(self):
        try:
            providers = request.env['auth.oauth.provider'].sudo().search_read([('enabled', '=', True)])
        except Exception:
            providers = []
        for provider in providers:
            return_url = request.httprequest.url_root + 'auth_oauth/signin'
            state = self.get_state(provider)
            params = dict(
                response_type='token',
                client_id=provider['client_id'],
                redirect_uri=return_url,
                scope=provider['scope'],
                state=json.dumps(state),
            )

            if provider['client_id'] == 'threefold_erp':

                private_key = nacl.signing.SigningKey(provider['private_key'], encoder=nacl.encoding.Base64Encoder)
                public_key = private_key.verify_key.to_curve25519_public_key().encode(
                    encoder=nacl.encoding.Base64Encoder)

                state = str(uuid.uuid4()) + '-' + str(round(time.time()))
                request.session['state'] = state

                params['appid'] = provider['client_id']
                params['redirecturl'] = params.pop('redirect_uri')
                params['publickey'] = public_key

            provider['auth_link'] = "%s?%s" % (provider['auth_endpoint'], werkzeug.url_encode(params))
        return providers

    def get_state(self, provider):
        redirect = request.params.get('redirect') or 'web'
        if not redirect.startswith(('//', 'http://', 'https://')):
            redirect = '%s%s' % (request.httprequest.url_root, redirect[1:] if redirect[0] == '/' else redirect)
        state = dict(
            d=request.session.db,
            p=provider['id'],
            r=werkzeug.url_quote_plus(redirect),
        )
        token = request.params.get('token')
        if token:
            state['t'] = token
        return state

    @http.route()
    def web_login(self, *args, **kw):
        ensure_db()
        if request.httprequest.method == 'GET' and request.session.uid and request.params.get('redirect'):
            # Redirect if already logged in and redirect param is present
            return http.redirect_with_hash(request.params.get('redirect'))
        providers = self.list_providers()

        response = super(OAuthLogin, self).web_login(*args, **kw)
        if response.is_qweb:
            error = request.params.get('oauth_error')
            if error == '1':
                error = _("Sign up is not allowed on this database.")
            elif error == '2':
                error = _("Access Denied")
            elif error == '3':
                error = _("You do not have access to this database or your invitation has expired. Please ask for an invitation and be sure to follow the link in your invitation email.")
            else:
                error = None

            response.qcontext['providers'] = providers
            if error:
                response.qcontext['error'] = error

        return response

    @http.route()
    def web_auth_signup(self, *args, **kw):
        providers = self.list_providers()
        response = super(OAuthLogin, self).web_auth_signup(*args, **kw)
        response.qcontext.update(providers=providers)
        return response

    @http.route()
    def web_auth_reset_password(self, *args, **kw):
        providers = self.list_providers()
        response = super(OAuthLogin, self).web_auth_reset_password(*args, **kw)
        response.qcontext.update(providers=providers)
        return response


class OAuthController(http.Controller):

    def _get_threebot_info(self, kw):
        provider = request.env.ref('auth_oauth.provider_threebot').sudo()
        signedhash = kw.get('signedhash')
        username = kw.get('username')
        data = kw.get('data')

        if signedhash is None or username is None or data is None:
            return set_cookie_and_redirect('/web/login?oauth_error=4')

        data = json.loads(data)

        res = requests.get('https://login.threefold.me/api/users/{0}'.format(username),
                           {'Content-Type': 'application/json'})

        if res.status_code != 200:
            return set_cookie_and_redirect('/web/login?oauth_error=5')

        user_pub_key = nacl.signing.VerifyKey(res.json()['publicKey'], encoder=nacl.encoding.Base64Encoder)
        nonce = base64.b64decode(data['nonce'])
        ciphertext = base64.b64decode(data['ciphertext'])
        private_key = nacl.signing.SigningKey(provider.private_key, encoder=nacl.encoding.Base64Encoder)

        state = user_pub_key.verify(base64.b64decode(signedhash)).decode()

        box = Box(
            private_key.to_curve25519_private_key(),
            user_pub_key.to_curve25519_public_key()
        )
        try:
            decrypted = box.decrypt(ciphertext, nonce)
            result = json.loads(decrypted)
            email = result['email']['email']
            emailVerified = result['email']['verified']
            if not emailVerified:
                return set_cookie_and_redirect('/web/login?oauth_error=7')
        except:
            return set_cookie_and_redirect('/web/login?oauth_error=8')

        return {
            'state': json.loads(state),
            'email': email,
            'username': username
        }

    @http.route('/auth_oauth/signin', type='http', auth='none')
    @fragment_to_query_string
    def signin(self, **kw):
        if 'state' in kw:
            state = json.loads(kw['state'])
        else:
            info = self._get_threebot_info(kw)
            state = info['state']
            kw.pop('signedhash')
            kw.pop('data')
            kw['state'] = json.dumps(state)
            kw['email'] = info['email']
            kw['access_token']:''
        dbname = state['d']
        if not http.db_filter([dbname]):
            return BadRequest()
        provider = state['p']
        context = state.get('c', {})
        registry = registry_get(dbname)
        with registry.cursor() as cr:
            try:
                env = api.Environment(cr, SUPERUSER_ID, context)
                credentials = env['res.users'].sudo().auth_oauth(provider, kw)
                cr.commit()
                action = state.get('a')
                menu = state.get('m')
                redirect = werkzeug.url_unquote_plus(state['r']) if state.get('r') else False
                url = '/web'
                if redirect:
                    url = redirect
                elif action:
                    url = '/web#action=%s' % action
                elif menu:
                    url = '/web#menu_id=%s' % menu
                request.session.authenticate(db=credentials[0], uid=credentials[1])
                return set_cookie_and_redirect(redirect)
                # Since /web is hardcoded, verify user has right to land on it
                if werkzeug.urls.url_parse(resp.location).path == '/web' and not request.env.user.has_group('base.group_user'):
                    resp.location = '/'
                return resp
            except AttributeError:
                # auth_signup is not installed
                _logger.error("auth_signup not installed on database %s: oauth sign up cancelled." % (dbname,))
                url = "/web/login?oauth_error=1"
            except AccessDenied:
                # oauth credentials not valid, user could be on a temporary session
                _logger.info('OAuth2: access denied, redirect to main page in case a valid session exists, without setting cookies')
                url = "/web/login?oauth_error=3"
                redirect = werkzeug.utils.redirect(url, 303)
                redirect.autocorrect_location_header = False
                return redirect
            except Exception as e:
                # signup error
                _logger.exception("OAuth2: %s" % str(e))
                url = "/web/login?oauth_error=2"

        return set_cookie_and_redirect(url)

    @http.route('/auth_oauth/oea', type='http', auth='none')
    def oea(self, **kw):
        """login user via Odoo Account provider"""
        dbname = kw.pop('db', None)
        if not dbname:
            dbname = db_monodb()
        if not dbname:
            return BadRequest()
        if not http.db_filter([dbname]):
            return BadRequest()

        registry = registry_get(dbname)
        with registry.cursor() as cr:
            try:
                env = api.Environment(cr, SUPERUSER_ID, {})
                provider = env.ref('auth_oauth.provider_openerp')
            except ValueError:
                return set_cookie_and_redirect('/web?db=%s' % dbname)
            assert provider._name == 'auth.oauth.provider'

        state = {
            'd': dbname,
            'p': provider.id,
            'c': {'no_user_creation': True},
        }

        kw['state'] = json.dumps(state)
        return self.signin(**kw)
