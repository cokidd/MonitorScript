
from .alerts import Alerter
import logging
import time
import hmac
import hashlib
import base64
import urllib.parse
import json
import requests


class DingtalkAlerter(Alerter):

    # By setting required_options to a set of strings
    # You can ensure that the rule config file specifies all
    # of the options. Otherwise, ElastAlert will throw an exception
    # when trying to load the rule.
    def __init__(self, *args):
        super(DingtalkAlerter, self).__init__(*args)
        self.dingtalk_webhook_url = self.rule['dingtalk_webhook']
        self.dingtalk_secret = self.rule.get('dingtalk_secret', '')
        self.dingtalk_msgtype = self.rule.get('dingtalk_msgtype', 'text')
        self.dingtalk_isAtAll = self.rule.get('dingtalk_isAtAll', False)
        self.dingtalk_title = self.rule.get('dingtalk_title', '')
        self.timestamp = str(round(time.time() * 1000))

    def make_sign(self):
        secret_enc = self.dingtalk_secret.encode('utf-8')
        string_to_sign = '{}\n{}'.format(self.timestamp, self.dingtalk_secret)
        string_to_sign_enc = string_to_sign.encode('utf-8')
        hmac_code = hmac.new(secret_enc, string_to_sign_enc, digestmod=hashlib.sha256).digest()
        sign = urllib.parse.quote(base64.b64encode(hmac_code))
        return sign


    # Alert is called
    def alert(self, matches):
        headers = {
            "Content-Type":"application/json",
            "Accept":"application/json;charset=utf-8"
        }
        body = self.create_alert_body(matches)
        payload = {
            "msgtype" : self.dingtalk_msgtype,
            "text" : {
                "content":body
            },
            "at" : {
                "isAtAll": False
            }
        }
        if self.dingtalk_secret == '':
            response = requests.post(self.dingtalk_webhook_url,
                             data=json.dumps(payload),
                             headers=headers)
        else:
            sign=self.make_sign()
            webhook = self.dingtalk_webhook_url+'&timestamp='+self.timestamp+"&sign="+sign
            response = requests.post(webhook, data=json.dumps(payload), headers=headers)

    # get_info is called after an alert is sent to get data that is written back
    # to Elasticsearch in the field "alert_info"
    # It should return a dict of information relevant to what the alert does
    def get_info(self):
        return {
            'type': "dingtalk",
            "dingtalk_webhook": self.dingtalk_webhook_url
        }

