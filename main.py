# gaba coding:utf-8 gaba
# @gaba 16.11.07

import json
import os
import sys

import tornado.httpserver
import tornado.ioloop
import tornado.options
import tornado.web
from tornado import gen
from tornado.options import define, options

from lib.system_info import get_interface_info
from lib.data_stroge import LogDataStorage
from lib.dict_unicode_to_utf import convert
from lib.json_encoder import JSONEncoder
from lib.libiptables import *
from data import get_coll
from lib.netfilter import mmain
reload(sys)
sys.setdefaultencoding('utf-8')

define("port", default=4566, help="run on the given port", type=int)
define("verbose", default=False, help="verbose", type=bool)
define("debug", default=False, help="debug", type=bool)


class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/", HomeHandler),
            (r"/auth/login", AuthLoginHandler),
            (r"/auth/logout", AuthLogoutHandler),
            #(r"/check_json", JsonCheckerHandler),
            (r"/system_status", SystemStatusHandler),
            (r"/firewall", FirewallHandler),
            (r"/firewall/display", FirewallDisplayHandler),
            (r"/firewall/add", FirewallAddHandler),
            (r"/firewall/delete", FirewallDeleteHandler),
            (r"/ips", IPSHandler),
        ]
        settings = dict(
            template_path=os.path.join(os.path.dirname(__file__), "templates"),
            static_path=os.path.join(os.path.dirname(__file__), "static"),
            # xsrf_cookies=True,
            cookie_secret="GabaGabaasaddGabaHey",
            login_url="/auth/login",
            debug=options.debug,
        )
        super(Application, self).__init__(handlers, **settings)


class BaseHandler(tornado.web.RequestHandler):
    def gaba(self):
        return "gaba"

    def get_current_user(self):
        user_id = self.get_secure_cookie("login")
        if not user_id:
            return None
        return True

class HomeHandler(BaseHandler):
    """
    OUTPUT WEB PAGE
    """

    def get(self):
        if not self.get_current_user():
            self.redirect("/auth/login")
        else:
            self.render("index.html")


class SystemStatusHandler(BaseHandler):
    """
    API
    OUTPUT
    没有登录 401
    成功登录 200
    {'lo': {'AF_PACKET': [{'peer': '00:00:00:00:00:00', 'addr': '00:00:00:00:00:00'}],
            'AF_INET': [{'peer': '127.0.0.1', 'netmask': '255.0.0.0', 'addr': '127.0.0.1'}]},
     'eth0': {'AF_PACKET': [{'broadcast': 'ff:ff:ff:ff:ff:ff', 'addr': '00:0c:29:1c:83:89'}],
              'AF_INET': [{'broadcast': '192.168.188.255', 'netmask': '255.255.255.0', 'addr': '192.168.188.142'}]}}
    """

    def get(self):
        if not self.get_current_user():
            raise tornado.web.HTTPError(401)
        # status = {"version": "0.1a"}
        # print get_interface_info()
        self.write(get_interface_info())


class JsonCheckerHandler(BaseHandler):
    """
    JUST FOR TEST
    """

    def post(self):
        data = json.loads(self.request.body.decode('utf-8'))
        print data
        self.write(data)


class AuthLoginHandler(BaseHandler):
    def get(self):
        """
        OUTPUT WEB PAGE
        """
        login = self.get_secure_cookie("login")
        if login:
            self.redirect("/")
        else:
            self.render("login.html")

    @gen.coroutine
    def post(self):
        """
        API
        INPUT POST
        {"username": "admin",
        "password": "asdada"}
        OUTPUT
        如果已经登录 403
        数据格式错误 406
        登录成功 200 {"success": "True"}
        登录失败 400
        """
        login_check = self.get_secure_cookie("login")
        if login_check:
            raise tornado.web.HTTPError(403)
        if not self.request.body:
            raise tornado.web.HTTPError(406)
        data = json.loads(self.request.body.decode('utf-8'))
        if not data or not isinstance(data, dict):
            raise tornado.web.HTTPError(406)
        if "username" not in data or "password" not in data:
            raise tornado.web.HTTPError(406)
        # TODO username password check
        if data.get("username") == "admin" and data.get("password") == "admin":
            self.set_secure_cookie("login", "asd")
            login_status = {"success": "True"}
            self.write(login_status)
        else:
            raise tornado.web.HTTPError(400)


class AuthLogoutHandler(BaseHandler):
    def get(self):
        """
        API
        OUTPUT
        如果没有登录 403
        成功登出 200 {"success": "True"}
        """
        login_check = self.get_secure_cookie("login")
        if not login_check:
            raise tornado.web.HTTPError(403)
        self.clear_cookie("login")
        self.write({"success": "True"})


class FirewallHandler(BaseHandler):
    """
    OUTPUT Web Page
    如果没有登录返回401
    登录可以正常返回
    """

    def get(self):
        login_check = self.get_secure_cookie("login")
        if not login_check:
            raise tornado.web.HTTPError(401)
        self.render("temp.html")


class FirewallDisplayHandler(BaseHandler):
    """
    API

    INPUT
    GET /firewall/display
    OUTPUT
    如果没有登录 401
    成功返回JSON
    {"rules": [{"INPUT": [
    {"src": "192.168.1.1/255.255.255.255", "protocol": "tcp", "dst": "0.0.0.0/0.0.0.0", "number": 0, "dport": "50",
    "in": null, "action": "ACCEPT", "sport", "out": null}]}, {"OUTPUT": []}, {"FORWARD": []}],
    "result": "True"}
    """

    def get(self):
        login_check = self.get_secure_cookie("login")
        if not login_check:
            raise tornado.web.HTTPError(401)
        iptb = ShowIptables(debug=True)
        input_rules = iptb.get_rules("filter", "INPUT")
        output_rules = iptb.get_rules("filter", "OUTPUT")
        forward_rules = iptb.get_rules("filter", "FORWARD")
        result = {"result": "True",
                  "rules": [{"INPUT": self._split_rules(input_rules)},
                            {"OUTPUT": self._split_rules(output_rules)},
                            {"FORWARD": self._split_rules(forward_rules)}]
                  }
        print result
        self.write(result)

    def _split_rules(self, rules):
        split_rules = []
        for rule_number in range(len(rules)):
            rule = rules[rule_number]
            rule_dict = {"number": rule_number, "protocol": rule.protocol, "src": rule.src, "dst": rule.dst,
                         "in": rule.in_interface, "out": rule.out_interface, "action": rule.target.name}
            if len(rule.matches) > 0:
                for match in rule.matches:
                    if match.sport:
                        rule_dict.update({"sport": match.sport})
                    else:
                        rule_dict.update({"sport":""})
                    if match.dport:
                        rule_dict.update({"dport": match.dport})
                    else:
                        rule_dict.update({"dport":""})
            split_rules.append(rule_dict)
        return split_rules


class FirewallAddHandler(BaseHandler):
    """
    API
    
    INPUT
    {"chain",
     "sip",
     "dip",
     "sport",
     "dport",
     "protocol",
     "iintf",
     "ointf",
     "action"
     }
     
    OUTPUT
    未登录 401
    数据格式异常 406
    成功添加 200 {"result":"True", "error_message":"error"}
    """

    def post(self):
        login_check = self.get_secure_cookie("login")
        if not login_check:
            raise tornado.web.HTTPError(401)
        if not self.request.body:
            raise tornado.web.HTTPError(406)
        data = json.loads(self.request.body.encode("utf-8"))
        print 123
        print data.get("switchlock")
        if data.get("switchlock")=="true":
             mmain()
        print data.get("chain")
        data = convert(data)
        print data
        if not data or not isinstance(data, dict):
            raise tornado.web.HTTPError(406)
        for key in ["chain", "sip", "dip", "sport", "dport", "protocol", "iintf", "ointf", "action","a111"]:
            if key not in data:
                raise tornado.web.HTTPError(406)
        if not self._check_dict(data):
            raise tornado.web.HTTPError(406)
        chain_name = data.get("chain")
        print data.get("a111")
        print data.get("chain")
        add_rule = SetIptables(debug=True,
                               table_name="filter",
                               chain_name=chain_name,
                               method="add",
                               rule_dict=data)
        error_message = ""
        success = add_rule.successful()
        if not success:
            error_message = add_rule.error_message
        self.write({"result": str(success), "error_message": error_message})

    def _check_dict(self, dt):
        if not dt.get("chain") or not dt.get("action"):
            return False
        return True


class FirewallDeleteHandler(BaseHandler):
    """
    API
    
    INPUT
    POST
    {"chain":"INPUT", "number":0}
    
    OUTPUT
    未登录 401
    数据格式异常 406
    成功删除 200 {"result":"True", "error_message":"error"}
    """

    def post(self):
        login_check = self.get_secure_cookie("login")
        if not login_check:
            raise tornado.web.HTTPError(401)
        else:
            if not self.request.body:
                raise tornado.web.HTTPError(406)
            data = json.loads(self.request.body.decode('utf-8'))
            if not data or not isinstance(data, dict):
                raise tornado.web.HTTPError(406)
            if "chain" not in data or "number" not in data:
                raise tornado.web.HTTPError(406)
            print 123
            print data.get("switchlock")
            if data.get("switchlock")=="on":
                mmain()
                print "netfilter.py is running"
            chain = str(data.get("chain"))
            number = data.get("number")
            delete_dict = {"number": str(number)}
            print chain, delete_dict
            set_iptb = SetIptables(debug=False, table_name="filter", chain_name=chain, method="delete",
                                   rule_dict=delete_dict)
            error_message = ""
            success = set_iptb.successful()
            if not success:
                error_message = set_iptb.error_message
            res = {"result": str(success), "error_message": error_message}
            self.write(res)


class IPSHandler(BaseHandler):
    """
    API
    INPUT
    GET /ips

    OUTPUT
    未登录 401`
    200 {"result": ...}
    """
    def get(self):
        login_check = self.get_secure_cookie("login")
        if not login_check:
            raise tornado.web.HTTPError(401)
        else:
            ips_coll = get_coll()
            data = ips_coll.get_suricata_log(0, 100)
            arr = []
            for da in data:
                del da['_id']
		arr.append(da)
            self.write({"result":arr})


def run_web_on_local():
    tornado.options.parse_command_line()
    http_server = tornado.httpserver.HTTPServer(Application())
    http_server.listen(options.port)
    # logging.info("[+] config done: 127.0.0.1:" + str(options.port))
    tornado.ioloop.IOLoop.current().start()


def judge_netfilter(self,kk):
        login_check = self.get_secure_cookie("login")
        if not login_check:
                raise tornado.web.HTTPError(401)
        else:
                if(self.get_argument["name"]=="a111"):
                    print "netfilter.py is running"
                    mmain()
                else:
                    print "netfilter已经关闭！"
                	
			

if __name__ == "__main__":
    run_web_on_local()
    judge_netfilter()
