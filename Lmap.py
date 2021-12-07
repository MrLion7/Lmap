from ipaddress import ip_address,ip_network
import asyncio
import re
from lxml import etree
import argparse
import json
from configparser import ConfigParser
from pathlib import Path
import sys
from rich.progress import Progress
from rich.console import Console
from httpx import AsyncClient
from prettytable import PrettyTable

console = Console()


def banner():
    console.print('Lmap V2.0 By Lion', style='bold cyan', justify='center')
    console.print('A tool combined with the advantages of masscan and nmap', style='bold cyan', justify='center')
    console.print('Enjoy~', style='bold cyan', justify='center')


def create_ini(masscan_path, nmap_path):
    config = ConfigParser()
    config['Masscan'] = {'path': masscan_path, 'rate': '500', 'ConcurrentLimit': '3', 'PortGap': '11000', 'IpGap': '10',
                         'waf-threshold': '50'}
    config['Nmap'] = {'path': nmap_path, 'ConcurrentLimit': '10'}
    config['Httpx'] = {'ConcurrentLimit': '100'}
    configfile = (Path(sys.argv[0]).parent / 'config.ini')
    config.write(configfile.open('w+', encoding='utf-8'))


def split_ip(ips):
    ip_list = []
    if (',' in ips):
        ip_list = ips.split(',')
    elif ('/' in ips):
        net = ip_network(ips)
        for ip in zip(net):
            ip_list.append(str(ip[0]))
    elif ('-' in ips):
        start_ip,end_ip = ips.split('-')
        start_ip = ip_address(start_ip)
        end_ip = ip_address(end_ip)
        while start_ip <= end_ip:
            ip_list.append(str(start_ip))
            start_ip += 1
    else:
        ip_list.append(ips)
    return ip_list


async def async_exec_cmd(cmd, sem=None):
    if (sem != None):
        async with sem:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await proc.communicate()
            info = stdout.decode() if stdout else stderr.decode()
            return info
    else:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await proc.communicate()
        info = stdout.decode() if stdout else stderr.decode()
        return info


async def masscan(path, ips, ports, nmap_queue, sem, waf_threshold,httpx_queue):
    cmd = f'{path}  {ips} -p {ports} --rate {masscan_rate}'
    info = await async_exec_cmd(cmd, sem)
    re_obj1 = re.compile('Discovered open port \d+/')
    re_obj2 = re.compile('on \d*.\d*.\d*.\d*')
    port_list = [element[21:-1] for element in re_obj1.findall(info)]
    ip_list = [element[3:] for element in re_obj2.findall(info)]
    # 定义临时字典防止waf用
    tmp_dict = {}
    if (len(ip_list) >= 1):
        for i in range(len(ip_list)):
            ip = ip_list[i]
            port = port_list[i]
            print(f'\033[32m{port} on {ip} is open\033[0m')
            # 放入临时字典里
            if (ip not in tmp_dict.keys()):
                tmp_dict[ip] = {}
                if ('count' not in tmp_dict[ip].keys()):
                    tmp_dict[ip]['count'] = 0
            tmp_dict[ip]['count'] += 1
            if (tmp_dict[ip]['count'] > int(waf_threshold)):
                waf_ip.append(ip)
    if (len(ip_list) >= 1):
        for i in range(len(ip_list)):
            ip = ip_list[i]
            port = port_list[i]
            # 如果在有waf的ip列表里就忽略
            if (ip in waf_ip):
                continue
            # 放入全局结果字典
            if (ip not in result_dic.keys()):
                result_dic[ip] = {}
                if ('count' not in result_dic[ip].keys()):
                    result_dic[ip]['count'] = 0
                    result_dic[ip]['portlist'] = []
            result_dic[ip]['count'] += 1
            result_dic[ip]['portlist'].append({'port': port, 'service': '-', 'product': '-','title':'-'})
            await nmap_queue.put({'ip': ip, 'port': port})
            if (httpx_queue != None):
                await httpx_queue.put({'ip': ip, 'port': port})
    progress_bar.update(masscan_progress, advance=1)


# 通过生产者消费者模型，一旦扫描出开放端口就用nmap进行版本探测
async def nmap(path, nmap_queue, nmap_args='-sS -Pn -n'):
    while True:
        data = await nmap_queue.get()
        ip = data['ip']
        port = data['port']
        xml_file = f'temp/{ip}:{port}.xml'
        cmd = f'{path} {nmap_args} {ip} -p {port} -oX {xml_file}'
        nmap_progress = progress_bar.add_task(f'[cyan]nmap service on {ip}:{port}')
        try:
            await asyncio.wait_for(async_exec_cmd(cmd), timeout=60)
            root = etree.parse(xml_file)
            state = root.xpath("//state/@state")[0]
            service = root.xpath("//service/@name")
            product = root.xpath("//service/@product")
            if (state == 'open'):
                if (service != []):
                    for port_data in result_dic[ip]['portlist']:
                        if (port_data['port'] == port):
                            port_data['service'] = service[0]
                            print(f'\033[32mservice on {ip}:{port} is {service[0]}\033[0m')
                            if (product != []):
                                port_data['product'] = product[0]
                                print(f'\033[32mproduct on {ip}:{port} is {product[0]}\033[0m')
        except Exception:
            pass
        finally:
            progress_bar.update(nmap_progress, completed=True, visible=False)
            nmap_queue.task_done()



# 通过生产者消费者模型，一旦扫描出开放端口就尝试获取web标题
async def async_request_get(headers, httpx_queue,sem):
    while True:
        data = await httpx_queue.get()
        ip = data['ip']
        port = data['port']
        title = '-'
        async with AsyncClient(verify=False) as async_client:
            # 限制并发量
            async with sem:
                try:
                    url = f'http://{ip}:{port}'
                    res = await async_client.get(url, headers=headers, timeout=5, follow_redirects=True)
                    if (res.status_code == 200):
                        html = etree.HTML(res.text, etree.HTMLParser())
                        if (len(html.xpath('//head/title/text()')) > 0):
                            title = html.xpath('//head/title/text()')[0]
                except Exception:
                    pass
                # 如果访问失败，使用https再次尝试
                if (title == '-'):
                    try:
                        url = f'https://{ip}:{port}'
                        res = await async_client.get(url, headers=headers, timeout=5,follow_redirects=True)
                        if (res.status_code == 200):
                            html = etree.HTML(res.text, etree.HTMLParser())
                            if (len(html.xpath('//head/title/text()')) > 0):
                                title = html.xpath('//head/title/text()')[0]
                    except Exception:
                        pass
                if (title != '-'):
                    print(f'\033[33mtitle on {url} is {title}\033[0m')
                    portlist = result_dic[ip]['portlist']
                    for port_data in portlist:
                        if (int(port_data['port']) == int(port)):
                            port_data['title'] = title
                httpx_queue.task_done()

async def main():
    # 读取输入
    ip_list = []
    if (file):
        for line in open(file, 'r', encoding='utf-8'):
            ip_list.append(line.strip('\n'))
    else:
        ip_list = split_ip(target)
    start_port, end_port = [int(i) for i in port_range.split('-')]
    # 初始化结果字典
    global result_dic
    result_dic = {}
    global waf_ip
    waf_ip = []
    ports_list = []
    headers = {
        'User-Agent': 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.55 Mobile Safari/537.36 Edg/96.0.1054.43'
    }
    # 把端口分组
    if (end_port - start_port >= masscan_port_gap):
        for i in range((end_port - start_port) // masscan_port_gap):
            ports_list.append(f'{start_port + i * masscan_port_gap}-{start_port + (i + 1) * masscan_port_gap - 1}')
        ports_list.append(
            (f'{start_port + ((end_port - start_port) // masscan_port_gap) * masscan_port_gap}-{end_port}'))
    else:
        ports_list.append(f'{start_port}-{end_port}')
    # 把ip分组
    ip_part_list = [ip_list[i:i + masscan_ip_gap] for i in range(0, len(ip_list), masscan_ip_gap)]
    # 创建nmap消费者
    nmap_queue = asyncio.Queue()
    nmap_tasklist = []
    for _ in range(nmap_concurrent_limit):
        if (scan_version == True):
            nmap_tasklist.append(
                asyncio.create_task(nmap(path=nmap_path, nmap_queue=nmap_queue, nmap_args='-sV -Pn -n')))
        if (scan_version == False):
            nmap_tasklist.append(
                asyncio.create_task(nmap(path=nmap_path, nmap_queue=nmap_queue, nmap_args='-sS -Pn -n')))
    if (scan_title):
        # 创建httpx消费者
        httpx_queue = asyncio.Queue()
        httpx_sem = asyncio.Semaphore(int(httpx_concurrent_limit))
        httpx_tasklist = []
        httpx_tasklist.append(asyncio.create_task(async_request_get(headers=headers,httpx_queue=httpx_queue,sem=httpx_sem)))
    # 创建masscan生产者
    global masscan_progress
    masscan_progress = progress_bar.add_task('[blue]masscan progressing...',
                                             total=(len(ip_part_list) * len(ports_list)))
    masscan_sem = asyncio.Semaphore(int(masscan_concurrent_limit))
    masscan_tasklist = []
    if (scan_title):
        for ip_part in ip_part_list:
            for ports in ports_list:
                ips = ','.join(ip_part)
                masscan_tasklist.append(
                    asyncio.create_task(masscan(path=masscan_path, ips=ips, ports=ports, nmap_queue=nmap_queue, sem=masscan_sem,
                                                waf_threshold=waf_threshold,httpx_queue=httpx_queue)))
    else:
        for ip_part in ip_part_list:
            for ports in ports_list:
                ips = ','.join(ip_part)
                masscan_tasklist.append(
                    asyncio.create_task(masscan(path=masscan_path, ips=ips, ports=ports, nmap_queue=nmap_queue, sem=masscan_sem,
                                                waf_threshold=waf_threshold,httpx_queue=None)))
    # 等待各队列结束
    await asyncio.gather(*masscan_tasklist)
    print('success1')
    await nmap_queue.join()
    print('success2')
    if (scan_title):
        await httpx_queue.join()
    print('success3')
    # 销毁nmap消费者
    for nmap_task in nmap_tasklist:
        nmap_task.cancel()
    print('success4')
    # 销毁httpx消费者
    if (scan_title):
        for httpx_task in httpx_tasklist:
            httpx_task.cancel()
    print('success5')
    progress_bar.update(masscan_progress, completed=True, visible=False)
    # 输出内容
    if (output_url):
        with open(output_url, 'a+', encoding='utf-8') as f:
            for ip, data in result_dic.items():
                for port_data in data['portlist']:
                    f.write(f"http://{ip}:{port_data['port']}\n")
    if (output_json):
        with open(output_json, 'w+', encoding='utf-8') as f:
            json.dump(result_dic, f, sort_keys=True, indent=4, separators=(',', ':'))
    # 生成表格
    table = PrettyTable(['IP', 'Port', 'Service', 'Product','Title'])
    for ip, data in result_dic.items():
        for port_data in data['portlist']:
            table.add_row([ip, port_data['port'], port_data['service'], port_data['product'],port_data['title']])
    print(table)


if __name__ == '__main__':
    banner()
    # 初始化配置文件和临时文件夹
    configfile = Path(sys.argv[0]).parent / 'config.ini'
    if (configfile.exists() == False):
        masscan_path = input('please input masscan path\n')
        nmap_path = input('please input nmap path\n')
        create_ini(masscan_path, nmap_path)
    temp_file = Path(sys.argv[0]).parent / 'temp'
    if (temp_file.exists() == False):
        temp_file.mkdir()
    config = ConfigParser()
    config.read_file(configfile.open('r', encoding='utf-8'))
    masscan_path = config['Masscan']['path']
    nmap_path = config['Nmap']['path']
    waf_threshold = config['Masscan']['waf-threshold']
    masscan_rate = config['Masscan']['rate']
    masscan_concurrent_limit = int(config['Masscan']['ConcurrentLimit'])
    masscan_port_gap = int(config['Masscan']['PortGap'])
    masscan_ip_gap = int(config['Masscan']['IpGap'])
    nmap_concurrent_limit = int(config['Nmap']['ConcurrentLimit'])
    httpx_concurrent_limit = int(config['Httpx']['ConcurrentLimit'])
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', help='please input ips like 192.168.0.1,192.168.0.2 or 192.168.0.1/24 or 1.1.1.1-2.2.2.2')
    parser.add_argument('-p', '--port', help='please input ports like 1-65535', required=True)
    parser.add_argument('-f', '--file', help='pleases input your file')
    parser.add_argument('-oj', '--output-json', help='please input output json file', default=None)
    parser.add_argument('-ou', '--output-url', help='please input output url file', default=None)
    parser.add_argument('-sv', '--scan-version', help='please input whether use sv mode,True or False', type=bool,
                        default=False)
    parser.add_argument('-st', '--scan-title', help='please input whether scan title,True or False', type=bool,
                        default=True)
    args = parser.parse_args()
    target = args.target
    file = args.file
    port_range = args.port
    output_json = args.output_json
    output_url = args.output_url
    scan_version = args.scan_version
    scan_title = args.scan_title
    with Progress() as progress_bar:
        asyncio.run(main())
