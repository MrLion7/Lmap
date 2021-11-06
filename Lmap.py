import asyncio
import re
from lxml import etree
import argparse
import json
import configparser
from pathlib import Path
import sys
from rich.progress import Progress
from rich.console import Console
console = Console()
from prettytable import PrettyTable

def banner():
    console.print('Lmap1.0 By Lion',style='bold cyan',justify='center')
    console.print('A tool combined with the advantages of masscan and nmap',style='bold cyan',justify='center')
    console.print('Enjoy~',style='bold cyan',justify='center')

def create_ini():
    config = configparser.ConfigParser()
    config['Masscan'] = {'rate': '800', 'ConcurrentLimit': '3', 'PortGap': '11000', 'IpGap': '3'}
    config['Nmap'] = {'ConcurrentLimit': '10'}
    configfile = (Path(sys.argv[0]).parent / 'config.ini')
    config.write(configfile.open('w+', encoding='utf-8'))


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


async def masscan(ips, ports, queue, sem):
    cmd = f'masscan  {ips} -p {ports} --rate {masscan_rate}'
    info = await async_exec_cmd(cmd, sem)
    re_obj1 = re.compile('Discovered open port \d+/')
    re_obj2 = re.compile('on \d*.\d*.\d*.\d*')
    port_list = [element[21:-1] for element in re_obj1.findall(info)]
    ip_list = [element[3:] for element in re_obj2.findall(info)]
    if (len(port_list) > 0):
        for i in range(len(port_list)):
            print(f'\033[32m{port_list[i]} on {ip_list[i]} is open\033[0m')
            await queue.put({'ip': ip_list[i], 'port': port_list[i]})
            progress.update(masscan_task, advance=1)

# 通过生产者消费者模型，一旦扫描出开放端口就用nmap进行版本探测
async def nmap(queue):
    while True:
        data = await queue.get()
        ip = data['ip']
        port = data['port']
        xml_file = f'temp/{ip}:{port}.xml'
        cmd = f'nmap -sV -Pn -n -v  {ip} -p {port} -oX {xml_file}'
        result = {'ip': str(ip), 'port': str(port), 'service': 'unknown', 'product': 'unknown'}
        nmap_task = progress.add_task(f'[cyan]nmap service on {ip}:{port}')
        try:
            await asyncio.wait_for(async_exec_cmd(cmd), timeout=60)
            root = etree.parse(xml_file)
            state = root.xpath("//state/@state")[0]
            service = root.xpath("//service/@name")
            product = root.xpath("//service/@product")
            if (state == 'open'):
                if (service != []):
                    result['service'] = service[0]
                    print(f'\033[32mservice on {ip}:{port} is {service[0]}\033[0m')
                if (product != []):
                    result['product'] = product[0]
                    print(f'\033[32mproduct on {ip}:{port} is {product[0]}\033[0m')
        except Exception:
            print(f'\033[33mcan not identify {port} on {ip}\033[0m')
        finally:
            if (result):
                result_list.append(result)
            progress.update(nmap_task,completed=True,visible=False)
            queue.task_done()


async def main(ips, file, port_range, output_json, output_url):
    ip_list = []
    if (file):
        for line in open(file, 'r', encoding='utf-8'):
            ip_list.append(line.strip('\n'))
    else:
        ip_list = ips.split(',')
    start_port, end_port = [int(i) for i in port_range.split('-')]
    global result_list
    result_list = []
    ports_list = []
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
    port_queue = asyncio.Queue()
    sem = asyncio.Semaphore(masscan_concurrent_limit)
    job_list = []
    nmap_task_list = []
    for _ in range(nmap_concurrent_limit):
        nmap_task_list.append(asyncio.create_task(nmap(queue=port_queue)))
    global masscan_task
    masscan_task = progress.add_task('[blue]masscan progressing...', total=(len(ip_part_list) * len(ports_list)))
    for ip_part in ip_part_list:
        for ports in ports_list:
            ips = ','.join(ip_part)
            job_list.append(asyncio.create_task(masscan(ips=ips, ports=ports, queue=port_queue, sem=sem)))
    await asyncio.gather(*job_list)
    await port_queue.join()
    for nmap_task in nmap_task_list:
        nmap_task.cancel()
    if (output_url):
        with open(output_url, 'a+', encoding='utf-8') as f:
            for result in result_list:
                f.write("{}:{}\n".format(result['ip'], result['port']))
    if (output_json):
        with open(output_json, 'w+', encoding='utf-8') as f:
            json.dump(result_list, f, sort_keys=True, indent=4, separators=(',', ':'))
    progress.update(masscan_task,visible=False)
    table = PrettyTable(['IP','Port','Service','Product'])
    for result in result_list:
        table.add_row([result['ip'],result['port'],result['service'],result['product']])
    print(table)


if __name__ == '__main__':
    banner()
    configfile = Path(sys.argv[0]).parent / 'config.ini'
    if (configfile.exists() == False):
        create_ini()
    temp_file = Path(sys.argv[0]).parent / 'temp'
    if (temp_file.exists() == False):
        temp_file.mkdir()
    config = configparser.ConfigParser()
    config.read_file(configfile.open('r', encoding='utf-8'))
    masscan_rate = config['Masscan']['rate']
    masscan_concurrent_limit = int(config['Masscan']['ConcurrentLimit'])
    masscan_port_gap = int(config['Masscan']['PortGap'])
    masscan_ip_gap = int(config['Masscan']['IpGap'])
    nmap_concurrent_limit = int(config['Nmap']['ConcurrentLimit'])
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', help='请输入ip')
    parser.add_argument('-p', '--port', help='请输入端口，如1-65535', required=True)
    parser.add_argument('-f', '--file', help='请输入文件，每行一个ip')
    parser.add_argument('-oj', '--output-json', help='请输入输出json文件路径')
    parser.add_argument('-ou', '--output-url', help='请输入输出url文件路径')
    args = parser.parse_args()
    target = args.target
    file = args.file
    port_range = args.port
    output_json = args.output_json
    output_url = args.output_url
    with Progress() as progress:
        asyncio.run(main(target, file, port_range, output_json, output_url))
