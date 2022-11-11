import sqlite3
import os
import datetime
import requests
import base64


def db_init():
    conn = sqlite3.connect('./Datebases/monitor.db')
    cursor = conn.cursor()
    # github监控表
    cursor.execute('create table IF NOT EXISTS github'
                   '(git_id TEXT PRIMARY KEY, git_name TEXT,'
                   'git_uptime TEXT,git_url TEXT, git_des TEXT)')
    # cvetrend数据表
    cursor.execute('create table IF NOT EXISTS cvetrend'
                   '(trend_name TEXT PRIMARY KEY, trend_cvss_score TEXT,'
                   'trend_cvss_severity TEXT,trend_des TEXT, trend_url TEXT)')
    # 数据分析表
    cursor.execute('create table IF NOT EXISTS git_analysis'
                   '(id int PRIMARY KEY autoincrement,date TEXT, git_name TEXT,'
                   'git_url TEXT, git_des TEXT）')
    cursor.close()
    conn.commit()
    conn.close()
    github_init()


# github上cve更新的统计表，自增主键，更新时间，
def analysis_init():
    dbname = 'git_analysis'
    value = '*'
    condition = "order by git_uptime desc"
    init_data = select(dbname, value, condition)
    for i in init_data:
        time = i[2][:10]
    pass


def conn_db():
    conn = sqlite3.connect('.\Datebases\monitor.db')
    cursor = conn.cursor()
    return conn, cursor




def is_db_empty(dbname):
    conn, cursor = conn_db()
    sql = "select count(*) from {}".format(dbname)
    try:
        cursor.execute(sql)
        info = cursor.fetchone()
        if info[0] == 0:
            print("[*] 数据库为空，数据库开始初始化。。。。。")
            if dbname == "github":
                github_init()
            if dbname == "cvetrend":
                trend_init()
            return True
        else:
            return False
    except Exception as e:
        with open('../LOG/sql.log', 'a') as f:
            print(e, file=f)


def delete(dbname, id):
    sql = "delete from {} where git_id={}".format(dbname,id)
    con, cursor = conn_db()
    try:
        cursor.execute(sql)
        cursor.close()
        con.commit()
        con.close()
    except Exception as e:
        with open('../LOG/sql.log', 'a') as f:
            print("delete:", e, file=f)


def select(dbname, values, condition=None):
    sql = 'select {} from {} {}'.format(values, dbname, condition)
    con, cursor = conn_db()
    try:
        cursor.execute(sql)
        info = cursor.fetchall()
        cursor.close()
        con.close()
        return info
    except Exception as e:
        with open('../LOG/sql.log', 'a') as f:
            print("select:", e, file=f)


def insert(dbname, values):
    sql = "insert or ignore into {} values({})".format(dbname, values)
    print(sql)
    con, cursor = conn_db()
    try:
        cursor.execute(sql)
        cursor.close()
        con.commit()
        con.close()
    except Exception as e:
        with open('../LOG/sql.log', 'a') as f:
            print("insert:", e, file=f)


def github_init():
    dbname = "github"
    year = datetime.datetime.now().year
    api = "https://api.github.com/search/repositories?q=CVE-{}&sort=updated&per_page=100".format(year)
    github_token = r"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"
    github_headers = {
        "Authorization": github_token,
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                      'Chrome/75.0.3770.80 Safari/537.36',
        'Connection': 'keep-alive',
    }
    reqs = requests.get(api, headers=github_headers, timeout=30)
    req = reqs.json()
    total_count = req['total_count']
    print(total_count)
    if total_count%100 == 0:
        pages = total_count // 100
    else:
        pages = total_count // 100 + 1
    for i in range(1, pages+1):
        api_pages = "https://api.github.com/search/repositories?q=CVE-{}&sort=updated&per_page=100&page={}".format(year, i)
        print(api_pages)
        reqs = requests.get(api_pages, headers=github_headers, timeout=30)
        print(reqs)
        req = reqs.json()
        total_count = req['total_count']
        items = req['items']
        key = 'github'
        for item in items:
            git_id = item['id']
            git_name = item['name']
            if is_exist('git_id', git_id, key):
                # print(git_name, "is exist!")
                pass
            git_url = item['html_url']
            git_uptime = item['created_at']
            git_description = str(base64.b64encode(str(item['description']).encode('utf8')), encoding='utf8')
            # print(git_description)
            values = "'{}', '{}', '{}', '{}', '{}'".format(git_id, git_name, git_uptime, git_description, git_url)
            insert(dbname, values)


def trend_init():
    hrs_api = 'https://cvetrends.com/api/cves/24hrs'
    r = requests.get(hrs_api).json()
    datas = []
    data = r['data']
    try:
        # daily = True
        for per_data in data:
            cve_name = per_data["cve"]
            cvssv3_base_score = per_data["cvssv3_base_score"]
            cvssv3_base_severity = per_data["cvssv3_base_severity"]
            description = per_data["description"]
            epss_score = per_data["epss_score"]
            github_repos = []
            for github_repo in per_data["github_repos"]:
                github_repos.append(github_repo["url"])
            description = str(base64.b64encode(description.encode('utf8')), encoding='utf8')
            github_repos = str(base64.b64encode(str(github_repo).encode('utf8')), encoding='utf8')
            values = "'{}', '{}', '{}', '{}', '{}'".format(cve_name,cvssv3_base_score,cvssv3_base_severity, description, github_repos)
            # print(values)
            insert('cvetrend', values)
    except Exception as err:
        print(err)
        pass
    pass


def show(dbname):
    conn, cursor = conn_db()
    sql = "select count(*) from {}".format(dbname)
    cursor.execute(sql)
    info = cursor.fetchall()
    cursor.close()
    conn.close()
    print(info)
    # return info


def is_exist(key, value, dbname="github"):
    conn, cursor = conn_db()
    sql = "select count(*) from {} where {}={}".format(dbname, key, value)
    cursor.execute(sql)
    info = cursor.fetchone()[0]
    if info:
        return True
    else:
        return False


if __name__ == "__main__":
    # db_init()
    # print(is_exist('git_id', '504359221'))
    show('cvetrend')
    # github_init()
    trend_init()
    # delete("github", )
