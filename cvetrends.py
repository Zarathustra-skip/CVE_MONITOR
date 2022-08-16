# coding: UTF-8

import requests
import push_wxwork

trends_url = "https://cvetrends.com/api/cves/"


def trends_24hrs():
    hrs_url = trends_url + "24hrs"
    r = requests.get(hrs_url).json()
    print(r)
    return r


def trends_7days():
    days_url = trends_url + "7days"
    r = requests.get(days_url).json
    return r


def trends(model=24):
    if model == 24:
        data = trends_24hrs()['data']
    if model == 7:
        data = trends_7days()['data']
    try:
        for i in data:
            handler(i)
            print(i)
    except Exception as err:
        print(err)
    print(len(data))


def daily_trends(model=24):
    datas = []
    if model == 24:
        data = trends_24hrs()['data']
    if model == 7:
        data = trends_7days()['data']
    try:
        for i in data:
            datas.append(handler(i, True))
    except Exception as err:
        print(err)
    print(len(data))


def handler(per_data, daily=False):
    try:
        # daily = True
        cve_name = per_data["cve"]
        cvssv3_base_score = per_data["cvssv3_base_score"]
        cvssv3_base_severity = per_data["cvssv3_base_severity"]
        description = per_data["description"]
        epss_score = per_data["epss_score"]
        github_repos = []
        for github_repo in per_data["github_repos"]:
            github_repos.append(github_repo["url"])
        if not daily:
            push_wxwork.trends_push(cve_name,cvssv3_base_score,cvssv3_base_severity, description,epss_score,github_repos)
        else:
            push_wxwork.daily_trends_handler(cve_name,cvssv3_base_score,cvssv3_base_severity, description,epss_score,github_repos)
    except Exception as err:
        print(err)
        pass


if __name__ == "__main__":
    trends()