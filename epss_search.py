import requests
import json

header = {
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.80 Safari/537.36',
    'Connection': 'keep-alive',
}
epss_api = "https://api.first.org/data/v1/epss?cve={}"

def epss_query():
    pass


def epss_querys(file_name):
    with open(file_name,'r') as f:
        lines = f.readlines()
    f = open("epss评分表.txt", 'a')
    f.write("cve,epss,percemtole\n")
    for i in lines:
        api = epss_api.format(i[:-1])
        r = requests.get(api,headers=header,timeout=5).json()
        if len(r['data']) > 0:
            r['data'] = r['data'][0]
            cve = r['data']['cve']
            epss = r['data']['epss']
            percentile = r['data']['percentile']
            f.write(cve+","+epss+","+percentile+"\n")
    f.close()


if __name__ == "__main__":
    file = "github热门.txt"
    epss_querys(file)