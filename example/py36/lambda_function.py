import logging
logger = logging.getLogger("saml2.idp")
logger.setLevel(logging.DEBUG)

import sys
sys.path.insert(0,"./pip")
sys.path.insert(0,"./")

from subprocess import call
import os

import json
import re
from hashlib import sha1
import base64
import time
import importlib

from saml2 import server
from saml2 import time_util
from saml2 import BINDING_HTTP_POST
from saml2 import BINDING_HTTP_ARTIFACT
from saml2 import BINDING_SOAP
from saml2 import BINDING_HTTP_REDIRECT
from saml2.authn_context import AuthnBroker, PASSWORD, UNSPECIFIED, authn_context_class_ref
from saml2.httputil import convert, get_post
from saml2.sigver import encrypt_cert_from_item
from saml2.s_utils import rndstr
from saml2.s_utils import UnknownPrincipal
from saml2.s_utils import UnsupportedBinding

from six.moves.urllib.parse import parse_qs
from six.moves.http_cookies import SimpleCookie
import six

import boto3
s3 = boto3.client('s3', region_name='ap-northeast-2')
bucketName = "bsg-json"

from idp_user import USERS

CONFIG = None
AUTHN_BROKER = None
IDP = None
AUTHN_URLS = []
NON_AUTHN_URLS = []
PASSWD = {
  "daev0001": "qwerty",
  "testuser": "qwerty",
  "roland": "dianakra",
  "babs": "howes",
  "upper": "crust"
}
REPOZE_ID_EQUIVALENT = "uid"


class Cache(object):
    def __init__(self):
        self.user2uid = {}
        self.uid2user = {}

def do_verify(environ, _):
  query = parse_qs(get_post(environ))

  logger.debug("do_verify: %s", query)

  try:
    _ok, user = verify_username_and_password(query)
  except KeyError:
    _ok = False
    user = None

  if not _ok:
    resp = Unauthorized("Unknown user or wrong password")
  else:
    uid = rndstr(24)
    IDP.cache.uid2user[uid] = user
    IDP.cache.user2uid[user] = uid
    logger.debug("Register %s under '%s'", user, uid)

    r = s3.put_object(Body=user.encode("utf-8"), Bucket=bucketName, Key='{0}/{1}.json'.format("sso",uid))
    if r["ResponseMetadata"]["HTTPStatusCode"] == 200:
      logger.debug("writeToS3: Succeed")
    else:
      logger.debug("writeToS3: Failed")


    kaka = set_cookie("idpauthn", "/", uid, query["authn_reference"][0])

    lox = "%s?id=%s&key=%s" % (query["redirect_uri"][0], uid,
                               query["key"][0])
    logger.debug("Redirect => %s", lox)
    resp = Redirect(lox, headers=kaka, content="text/html")

  return resp(environ)

def set_cookie(name, _, *args):
  cookie = SimpleCookie()
  cookie[name] = base64.b64encode(":".join(args).encode())
  cookie[name]['path'] = "/"
  cookie[name]["expires"] = _expiration(5)  # 5 minutes from now
  logger.debug("Cookie expires: %s", cookie[name]["expires"])

  tup = tuple(cookie.output().split(": ", 1))
  dic = {}
  dic[tup[0]] = tup[1]
  return dic

def delete_cookie(environ, name):
  kaka = environ.get("headers", None)
  if kaka:
    kaka = kaka.get("cookie", None)

  logger.debug("delete KAKA: %s", kaka)
  if kaka:
    cookie_obj = SimpleCookie(kaka)
    morsel = cookie_obj.get(name, None)
    cookie = SimpleCookie()
    cookie[name] = ""
    cookie[name]['path'] = "/"
    logger.debug("Expire: %s", morsel)
    cookie[name]["expires"] = _expiration("dawn")
    return tuple(cookie.output().split(": ", 1))
  return None

def info_from_cookie(kaka):
  logger.debug("KAKA: %s", kaka)
  if kaka:
    cookie_obj = SimpleCookie(kaka)
    morsel = cookie_obj.get("idpauthn", None)

    b = morsel.value.replace("b'","")
    b = b.replace("'","")

    if morsel:
      try:
        key, ref = base64.b64decode(b).decode().split(":")
        getCache(key)
        return IDP.cache.uid2user[key], ref
      except (KeyError, TypeError):
        return None, None
    else:
      logger.debug("No idpauthn cookie")
  return None, None

def _expiration(timeout, tformat="%a, %d-%b-%Y %H:%M:%S GMT"):
  """
  :param timeout:
  :param tformat:
  :return:
  """
  if timeout == "now":
    return time_util.instant(tformat)
  elif timeout == "dawn":
    return time.strftime(tformat, time.gmtime(0))
  else:
    # validity time should match lifetime of assertions
    return time_util.in_a_while(minutes=timeout, format=tformat)

def verify_username_and_password(dic):
  global PASSWD
  # verify username and password
  if PASSWD[dic["login"][0]] == dic["password"][0]:
    return True, dic["login"][0]
  else:
    return False, ""

def do_authentication(environ, authn_context, key,
                      redirect_uri, headers=None):
  """
  Display the login form
  """
  logger.debug("Do authentication")
  auth_info = AUTHN_BROKER.pick(authn_context)

  if len(auth_info):
    method, reference = auth_info[0]
    logger.debug("Authn chosen: %s (ref=%s)", method, reference)
    return method(environ, reference, key, redirect_uri, headers)
  else:
    resp = Unauthorized("No usable authentication method")
    return resp(environ)

def username_password_authn(environ, reference, key,
                            redirect_uri, headers=None):
  """
  Display the login form
  """
  logger.info("The login page")

  kwargs = {}
  #kwargs = dict(mako_template="login.mako", template_lookup=LOOKUP)
  if headers:
      kwargs["headers"] = headers

  resp = Response(**kwargs)

  argv = {
      "action": "/beta/verify",
      "login": "",
      "password": "",
      "key": key,
      "authn_reference": reference,
      "redirect_uri": redirect_uri
  }
  logger.info("do_authentication argv: %s", argv)
  #return resp(environ, **argv)
  return login_page(**argv)

def convToJSON(obj):
  if isinstance(obj, dict):
    return dict([(k,convToJSON(obj[k])) for k in obj])
  elif isinstance(obj, list):
    return [convToJSON(i) for i in obj]
  else:
    try:
      json.dumps(obj)
      return obj
    except:
      jsonResult = {}
      try:
        obj.__dict__
      except AttributeError:
        return None
      for k in obj.__dict__:
        #print(k)
        if type(obj.__dict__[k]).__name__ == "method":
          pass
        #elif type(obj.__dict__[k]).__name__ == "NoneType":
        #  pass
        else:
          jsonResult[k] = convToJSON(obj.__dict__[k])
      return jsonResult

def getMessage(info):
  try:
    return info.message
  except AttributeError:
    try:
      return info["message"]
    except KeyError:
      raise

class Service(object):
  def __init__(self, environ, user=None):
    self.environ = environ
    logger.debug("ENVIRON: %s", environ)
    self.user = user

  def unpack_redirect(self):
    if "queryStringParameters" in self.environ:
      _qs = self.environ["queryStringParameters"]
      return _qs
    else:
      return None

  def unpack_post(self):
    _dict = parse_qs(self.environ['body'])
    logger.debug("unpack_post:: %s", _dict)
    try:
      return dict([(k, v[0]) for k, v in _dict.items()])
    except Exception:
      return None

  def unpack_either(self):
    if self.environ["httpMethod"] == "GET":
      _dict = self.unpack_redirect()
    elif self.environ["httpMethod"] == "POST":
      _dict = self.unpack_post()
    else:
      _dict = None
    logger.debug("unpacked _dict: %s", _dict)
    return _dict

  def not_authn(self, key, requested_authn_context):
    ruri = geturl(self.environ, query=False)

    kwargs = dict(authn_context=requested_authn_context, key=key, redirect_uri=ruri)
    # Clear cookie, if it already exists
    kaka = delete_cookie(self.environ, "idpauthn")
    if kaka:
      kwargs["headers"] = [kaka]
    return do_authentication(self.environ, **kwargs)

  def response(self, binding, http_args):
    resp = None
    if binding == BINDING_HTTP_ARTIFACT:
      resp = Redirect()
    elif http_args["data"]:
      resp = Response(http_args["data"], headers=http_args["headers"])
    else:
      for header in http_args["headers"]:
        if header[0] == "Location":
          resp = Redirect(header[1])

    if not resp:
      resp = ServiceError("Don't know how to return response")

    return resp(self.environ)

  def do(self, query, binding, relay_state="", encrypt_cert=None):
      pass

  def post(self):
    """ Expects a HTTP-POST request """

    _dict = self.unpack_post()
    return self.operation(_dict, BINDING_HTTP_POST)

  def operation(self, saml_msg, binding):
    logger.debug("_operation: %s", saml_msg)
    if not (saml_msg and 'SAMLRequest' in saml_msg):
      resp = BadRequest('Error parsing request or no request')
      return resp(self.environ)
    else:
      # saml_msg may also contain Signature and SigAlg
      if "Signature" in saml_msg:
        try:
          kwargs = {"signature": saml_msg["Signature"],
                    "sigalg": saml_msg["SigAlg"]}
        except KeyError:
          resp = BadRequest(
              'Signature Algorithm specification is missing')
          return resp(self.environ)
      else:
        kwargs = {}

      try:
        kwargs['encrypt_cert'] = encrypt_cert_from_item(
            getMessage(saml_msg["req_info"]))
      except KeyError:
        pass

      try:
        kwargs['relay_state'] = saml_msg['RelayState']
      except KeyError:
        pass

      return self.do(saml_msg["SAMLRequest"], binding, **kwargs)

class SSO(Service):
  def __init__(self, environ, user=None):
    Service.__init__(self, environ, user)
    self.binding = ""
    self.response_bindings = None
    self.resp_args = {}
    self.binding_out = None
    self.destination = None
    self.req_info = None
    self.op_type = ""

  def verify_request(self, query, binding):
    """
    :param query: The SAML query, transport encoded
    :param binding: Which binding the query came in over
    """
    resp_args = {}
    if not query:
      logger.info("Missing QUERY")
      resp = Unauthorized('Unknown user')
      return resp_args, resp(self.environ)

    if not self.req_info:
      self.req_info = IDP.parse_authn_request(query, binding)

    logger.info("parsed OK")
    logger.info(self.req_info)
    _authn_req = self.req_info.message
    logger.debug("%s", _authn_req)

    try:
      self.binding_out, self.destination = IDP.pick_binding(
          "assertion_consumer_service",
          bindings=self.response_bindings,
          entity_id=_authn_req.issuer.text, request=_authn_req)
    except Exception as err:
      logger.error("Couldn't find receiver endpoint: %s", err)
      raise

    logger.debug("Binding: %s, destination: %s", self.binding_out,
                                                   self.destination)

    resp_args = {}
    try:
      resp_args = IDP.response_args(_authn_req)
      _resp = None
    except UnknownPrincipal as excp:
      _resp = IDP.create_error_response(_authn_req.id,
                                          self.destination, excp)
    except UnsupportedBinding as excp:
      _resp = IDP.create_error_response(_authn_req.id,
                                          self.destination, excp)

    return resp_args, _resp

  def do(self, query, binding_in, relay_state="", encrypt_cert=None,
         **kwargs):
    """

    :param query: The request
    :param binding_in: Which binding was used when receiving the query
    :param relay_state: The relay state provided by the SP
    :param encrypt_cert: Cert to use for encryption
    :return: A response
    """
    try:
      resp_args, _resp = self.verify_request(query, binding_in)
    except UnknownPrincipal as excp:
      logger.error("UnknownPrincipal: %s", excp)
      resp = ServiceError("UnknownPrincipal: %s" % (excp,))
      return resp(self.environ)
    except UnsupportedBinding as excp:
      logger.error("UnsupportedBinding: %s", excp)
      resp = ServiceError("UnsupportedBinding: %s" % (excp,))
      return resp(self.environ)

    if not _resp:
      identity = USERS[self.user].copy()
      # identity["eduPersonTargetedID"] = get_eptid(IDP, query, session)
      logger.info("Identity: %s", identity)

      if REPOZE_ID_EQUIVALENT:
        identity[REPOZE_ID_EQUIVALENT] = self.user
      try:
        try:
          metod = self.environ["idp.authn"]
        except KeyError:
          pass
        else:
          resp_args["authn"] = metod

        _resp = IDP.create_authn_response(
            identity, userid=self.user,
            encrypt_cert_assertion=encrypt_cert,
            **resp_args)
      except Exception as excp:
        logging.error(exception_trace(excp))
        resp = ServiceError("Exception: %s" % (excp,))
        return resp(self.environ)

    logger.info("AuthNResponse: %s", _resp)
    if self.op_type == "ecp":
      kwargs = {"soap_headers": [
          ecp.Response(
              assertion_consumer_service_url=self.destination)]}
    else:
      kwargs = {}

    http_args = IDP.apply_binding(self.binding_out,
                                  "%s" % _resp, self.destination,
                                  relay_state, response=True, **kwargs)

    logger.debug("HTTPargs: %s", http_args)
    return self.response(self.binding_out, http_args)

  @staticmethod
  def _store_request(saml_msg):
    logger.debug("_store_request: %s", saml_msg)
    key = sha1(saml_msg["SAMLRequest"].encode()).hexdigest()
    # store the AuthnRequest
    IDP.ticket[key] = {}
    IDP.ticket[key]["SAMLRequest"] = saml_msg["SAMLRequest"]
    IDP.ticket[key]["RelayState"] = saml_msg["RelayState"]

    r = s3.put_object(Body=json.dumps(convToJSON(IDP.ticket)).encode("utf-8"), Bucket=bucketName, Key='{0}/{1}.json'.format("sso","ticket"))
    if r["ResponseMetadata"]["HTTPStatusCode"] == 200:
      logger.debug("writeToS3: Succeed")
    else:
      logger.debug("writeToS3: Failed")

    return key

  def post(self):
    """
    The HTTP-Post endpoint
    """
    logger.info("--- In SSO POST ---")
    saml_msg = self.unpack_either()

    try:
      _key = saml_msg["key"]
      IDP.ticket = s3.get_object(Bucket=bucketName, Key="{0}/{1}.json".format("sso","ticket"))
      IDP.ticket = json.loads(IDP.ticket['Body'].read())
      logger.info(IDP.ticket)

      saml_msg = IDP.ticket[_key]
      logger.info(saml_msg)

      try:
        self.req_info = saml_msg["req_info"]
      except KeyError:
        self.req_info = IDP.parse_authn_request(
          saml_msg["SAMLRequest"], BINDING_HTTP_POST)

      del IDP.ticket[_key]
    except KeyError:
      self.req_info = IDP.parse_authn_request(
        saml_msg["SAMLRequest"], BINDING_HTTP_POST)
      _req = self.req_info.message
      if self.user:
        if _req.force_authn is not None and \
            _req.force_authn.lower() == 'true':
          saml_msg["req_info"] = self.req_info
          key = self._store_request(saml_msg)
          return self.not_authn(key, _req.requested_authn_context)
        else:
          return self.operation(saml_msg, BINDING_HTTP_POST)
      else:
        saml_msg["req_info"] = self.req_info
        key = self._store_request(saml_msg)
        return self.not_authn(key, _req.requested_authn_context)
    else:
      return self.operation(saml_msg, BINDING_HTTP_POST)

class SLO(Service):
  def do(self, request, binding, relay_state="", encrypt_cert=None, **kwargs):

    logger.info("--- Single Log Out Service ---")
    try:
      logger.debug("req: '%s'", request)
      req_info = IDP.parse_logout_request(request, binding)
    except Exception as exc:
      logger.error("Bad request: %s", exc)
      resp = BadRequest("{}".format(exc))
      return resp(self.environ)

    msg = req_info.message
    if msg.name_id:
      lid = IDP.ident.find_local_id(msg.name_id)
      logger.info("local identifier: %s", lid)
      logger.info(getattr(CONFIG, "CONFIG"))
      if lid in IDP.cache.user2uid:
        uid = IDP.cache.user2uid[lid]
        if uid in IDP.cache.uid2user:
          del IDP.cache.uid2user[uid]
        del IDP.cache.user2uid[lid]
      # remove the authentication
      try:
        IDP.session_db.remove_authn_statements(msg.name_id)
      except KeyError as exc:
        logger.error("Unknown session: %s", exc)
        resp = ServiceError("Unknown session: {}".format(exc))
        return resp(self.environ)

    signRes = False
    sign_response = getattr(CONFIG, "CONFIG")
    if sign_response:
      sign_response = sign_response.get("service",None)
      if sign_response:
        sign_response = sign_response.get("idp",None)
        if sign_response:
          sign_response = sign_response.get("sign_response",None)
          if sign_response == True:
            signRes = True

    resp = IDP.create_logout_response(msg, [binding], sign=signRes)

    if binding == BINDING_SOAP:
      destination = ""
      response = False
    else:
      binding, destination = IDP.pick_binding("single_logout_service",
                                              [binding], "spsso",
                                              req_info)
      response = True

    try:
      hinfo = IDP.apply_binding(binding, "%s" % resp, destination,
                                relay_state, response=response)
    except Exception as exc:
      logger.error("ServiceError: %s", exc)
      resp = ServiceError("%s" % exc)
      return resp(self.environ)

    #_tlh = dict2list_of_tuples(hinfo["headers"])
    delco = delete_cookie(self.environ, "idpauthn")
    if delco:
      hinfo["headers"][delco[0]] = delco[1]
    logger.info("Header: %s", (hinfo["headers"],))

    if binding == BINDING_HTTP_REDIRECT:
      for key, value in hinfo['headers'].items():
        if key.lower() == 'location':
          resp = Redirect(value, headers=hinfo["headers"])
          return resp(self.environ)

      resp = ServiceError('missing Location header')
      return resp(self.environ)
    else:
      resp = Response(hinfo["data"], headers=hinfo["headers"])
      return resp(self.environ)

class Response(object):
  _template = None
  _statusCode = '200'
  _content_type = 'text/html'
  _mako_template = None
  _mako_lookup = None

  def __init__(self, message=None, **kwargs):
    self.statusCode = kwargs.get('statusCode', self._statusCode)
    self.response = kwargs.get('response', self._response)
    self.template = kwargs.get('template', self._template)
    #self.mako_template = kwargs.get('mako_template', self._mako_template)
    #self.mako_lookup = kwargs.get('template_lookup', self._mako_lookup)

    self.body = message

    self.headers = kwargs.get('headers', {})
    _content_type = kwargs.get('content', self._content_type)
    addContentType = True
    logger.debug(self.headers)
    for headerKey in self.headers:
      if 'content-type' == headerKey.lower():
        addContentType = False
    if addContentType:
      self.headers['Content-type'] = _content_type

  def __call__(self, environ, **kwargs):
    return self.response(self.body or geturl(environ), **kwargs)

  def _response(self, message="", **argv):

    if self.template:
      if isinstance(message, six.string_types):
        self.body = self.template.format(message)
      else:
        self.body = self.template.format(*message)
    #elif self.mako_lookup and self.mako_template:
    #  argv["message"] = message
    #  mte = self.mako_lookup.get_template(self.mako_template)
    #  return [mte.render(**argv)]
    else:
      if isinstance(message, six.string_types):
        # Note(JP): A WSGI app should always respond
        # with bytes, so at this point the message should
        # become encoded instead of passing a text object.
        self.body = message
      elif isinstance(message, six.binary_type):
        self.body = message.decode()
      else:
        self.body = message

    return self.lambda_result()

  def reply(self, **kwargs):
    return self.response(self.body, **kwargs)

  def lambda_result(self):
    jsonResult = {}
    for k in self.__dict__:
      #print(k)
      if type(self.__dict__[k]).__name__ == "method":
        pass
      elif type(self.__dict__[k]).__name__ == "NoneType":
        pass
      elif k == "template":
        pass
      else:
        jsonResult[k] = self.__dict__[k]
    logger.debug(jsonResult)
    return jsonResult

class BadRequest(Response):
    _statusCode = "400"
    _template = "<html>{}</html>"

class NotFound(Response):
    _statusCode = '404'

class Unauthorized(Response):
    _statusCode = "401"
    _template = "<html>{}</html>"

class Redirect(Response):
  _template = '<html>\n<head><title>Redirecting to {}</title></head>\n' \
              '<body>\nYou are being redirected to <a href="{}">{}</a>\n' \
              '</body>\n</html>'
  _statusCode = '302'

  def __call__(self, environ, **kwargs):
    location = self.body
    self.headers['location'] = location
    return self.response((location, location, location))

class ServiceError(Response):
  _statusCode = '500'

def geturl(environ,query=True):
  url = []
  url.append("{}://".format(environ['headers']['X-Forwarded-Proto'])) #https://
  url.append(environ['headers']['Host'])
  url.append(environ['requestContext']['path'])
  return "".join(url)

def not_found(environ):
  logger.debug("not_found")
  resp = NotFound()
  return resp(environ)

def login_page(**kwargs):
  return {
    "headers":{
      "Content-Type": "text/html"
    },
    "body": """
      <form action="{action}" method="post">

        <input type="hidden" name="key" value="{key}"/>
        <input type="hidden" name="authn_reference" value="{authn_reference}"/>
        <input type="hidden" name="redirect_uri" value="{redirect_uri}"/>

        <div class="label">
            <label for="login">Username</label>
        </div>
        <div>
            <input type="text" name="login" value="{login}" autofocus><br/>
        </div>

        <div class="label">
            <label for="password">Password</label>
        </div>
        <div>
            <input type="password" name="password"
                   value="{password}"/>
        </div>

        <input class="submit" type="submit" name="form.submitted" value="Log In"/>
      </form>
      """.format(**kwargs)
  }

def getCache(uid):
  if IDP.cache.uid2user == {}:
    user = s3.get_object(Bucket=bucketName, Key="{0}/{1}.json".format("sso",uid))
    user = user['Body'].read().decode()
    logger.info(user)

    IDP.cache.uid2user[uid] = user
    IDP.cache.user2uid[user] = uid

def lambda_handler(event, context):
  """
  """
  print(event)
  global IDP, CONFIG, AUTHN_URLS, NON_AUTHN_URLS, AUTHN_BROKER

  call(["cp","lib/xmlsec1","/tmp/xmlsec1"])
  #Moving the binary to /tmp and making it executable worked for me
  os.chmod('/tmp/xmlsec1', 0o555)

  IDP = server.Server("idp_conf", cache=Cache())
  IDP.ticket = {}

  CONFIG = importlib.import_module("idp_conf")
  # map urls to functions
  AUTHN_URLS = [
      # sso
      (r'sso/post$', (SSO, "post")),
      # slo
      (r'slo/post$', (SLO, "post")),
  ]

  NON_AUTHN_URLS = [
      (r'verify?(.*)$', do_verify),
  ]

  AUTHN_BROKER = AuthnBroker()
  AUTHN_BROKER.add(authn_context_class_ref(PASSWORD),
                   username_password_authn, 10,
                   CONFIG.BASE)
  AUTHN_BROKER.add(authn_context_class_ref(UNSPECIFIED),
                   "", 0, CONFIG.BASE)

  path = event['pathParameters']['proxy']
  url_patterns = AUTHN_URLS
  user = None

  kaka = event.get("headers", None)
  if kaka:
    kaka = kaka.get("cookie", None)

  logger.info("<application> PATH: %s", path)

  if kaka:
    logger.info("= KAKA =")
    user, authn_ref = info_from_cookie(kaka)
    if authn_ref:
      event["idp.authn"] = AUTHN_BROKER[authn_ref]
  else:
    try:
      if event["httpMethod"] == "GET":
        query = event["queryStringParameters"]
        if query is not None:
          uid = query["id"]
        else:
          uid = None
      else:
        query = parse_qs(convert(event["body"]))
        uid = query["id"][0]
      logger.debug("QUERY: %s", query)
      logger.debug("uid: %s", uid)
      if uid is None:
        pass
      else:
        getCache(uid)
        user = IDP.cache.uid2user[uid]
    except KeyError:
      user = None

  if not user:
    logger.info("-- No USER --")
    # insert NON_AUTHN_URLS first in case there is no user
    url_patterns = NON_AUTHN_URLS + url_patterns

  for regex, callback in url_patterns:
    match = re.search(regex, path)
    if match is not None:
      logger.debug("Callback: %s", callback)
      print(callback)
      if isinstance(callback, tuple):
        cls = callback[0](event, user)
        func = getattr(cls, callback[1])
        print(func)

        return func()
      return callback(event, user)

  return not_found(event)
