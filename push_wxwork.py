# coding: UTF-8

import requests
import json

wxwork_api = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=9683fe17-6159-4063-85dd-5a79ad5cc35f"


def github_push(ps="这是一条备注", name="None",time="None", url="None", des='None'):
    body = """{"msgtype": "text","text": {"content":\"""" + ps + "\n" + name + "\n" \
           + time + "\n" + des + "\n" + url + "\n"  """\"}}"""
    print(body)
    send = requests.post(wxwork_api, data=body.encode(), headers={"Content-Type": "application/json"})
    print(send.headers)


def trends_push(cve, cvssv3_score, cvssv3_serverity,des, epss, github_repos):
    data_test = """
            "漏洞名称:{}, cvss v3评分:{}, cvss v3等级:{}, epss利用率:{}, 描述:{}, poc链接:{}"
        """.format(cve, cvssv3_score, cvssv3_serverity, epss, des, github_repos)
    body = """{"msgtype": "text","text": {"content":""" + data_test + """}}"""
    print(body)
    try:
        send = requests.post(wxwork_api, data=body.encode(), headers={"Content-Type": "application/json"})
        print(send)
    except Exception as err:
        print(err)
        pass


def daily_trends_handler(cve, cvssv3_score, cvssv3_serverity,des, epss, github_repos):
    data_test = """
                "漏洞名称:{},
                 cvss v3评分:{},
                 cvss v3等级:{},
                 描述:{},
                 epss利用率:{},
                 poc链接:{}"
            """.format(cve, cvssv3_score, cvssv3_serverity, des, epss, github_repos)
    print(data_test)
    return data_test


if __name__ == "__main__":
    # github_push()
    trends_push()