import re


def escape(des:str):
    a = ('\'', '\"')
    for i in a:
        des = des.replace(i, '\\'+i)
    print(des)
    return des


if __name__ == "__main__":
    test = "I'm trying"
    print(escape(test))