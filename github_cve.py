# coding=utf8

import datetime
import requests
import push_wxwork
from SQL import sql_actions
import base64
import time

github_token = "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"

github_headers = {
    "Authorization": github_token,
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.80 Safari/537.36',
    'Connection': 'keep-alive',
}

year = datetime.datetime.now().year


def cve_monitor():
    try:
        while True:
            api = "https://api.github.com/search/repositories?q=CVE-{}&sort=updated".format(year)
            reqs = requests.get(api, headers=github_headers, timeout=60)
            req = reqs.json()
            total_count = req['total_count']
            print("cve_count:", total_count)
            with open('.\SQL\Datebases\count.txt', 'r') as f:
                old_count = f.readlines()
                if len(old_count) == 1:
                    old_count = old_count[0]
                else:
                    print("github count异常：", old_count)
            old_count = int(old_count)
            up_count = total_count - old_count
            if total_count == old_count:
                log_update_time = str(datetime.datetime.now().ctime())
                print(log_update_time, "GitHub 无更新")
                item = req['items'][0]
                git_id = item['id']
                git_name = item['name']
                git_url = item['html_url']
                git_uptime = item['created_at']
                git_description = str(item['description'])
                ps = "GitHub 无更新, 以下为最新一条数据："
                push_wxwork.github_push(ps, git_name, git_uptime, git_url, git_description)
                time.sleep(60*10)
            else:
                with open('.\SQL\Datebases\count.txt', 'w') as f:
                    f.write(str(total_count))
                print("old:", old_count)
                print("new:", total_count)
            items = req['items']
            key = 'github'
            ps = "GitHub 有更新，请关注："
            count = 0
            for item in items:
                git_id = item['id']
                git_name = item['name']
                git_url = item['html_url']
                git_uptime = item['created_at']
                git_description = str(item['description'])
                des = str(base64.b64encode(git_description.encode('utf8')), encoding='utf8')
                if count == up_count:
                    break
                else:
                    if sql_actions.is_exist('git_id', git_id, key):
                        print(git_name, "is exist!")
                        pass
                    else:
                        values = "'{}', '{}', '{}', '{}', '{}'".format(git_id, git_name, git_uptime, des,
                                                                   git_url)
                        sql_actions.insert(key, values)
                        push_wxwork.github_push(ps, git_name, git_uptime, git_url, des)
                    count += 1
    except KeyboardInterrupt as e:
        log_update_time = str(datetime.datetime.now().ctime())
        shutdown_msg = "[*] 程序人为终止"
        print(shutdown_msg)
        with open('./LOG/sql.log', 'a') as f:
            print(log_update_time, ",github_cve_monitor:", e, file=f)


def cve_poc_load():
    try:
        while True:
            page = 1
            api = "https://api.github.com/search/repositories?q=CVE-{}&sort=updated&per_page=100&page={}".format(year, page)
            reqs = requests.get(api, headers=github_headers, timeout=5)
            req = reqs.json()
            items = req['items']
            if len(items) > 0:
                for item in items:
                    git_name = item['name']
                    git_url = item['html_url']
                    git_uptime = item['created_at']
                    print(git_name)
                    with open('test.txt', 'a') as f:
                        f.write(git_name+'\n')
                page+=1
            else:
                break
    except Exception as err:
        print(err)


if __name__ == "__main__":
    # cve_poc_load()
    cve_monitor()
