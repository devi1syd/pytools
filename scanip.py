#!/usr/bin/python
#_*_ coding:utf8 _*_
import netifaces,nmap


def get_ip_lists(ip):

    ip_lists = []
    for i in range(1, 256):
        ip_lists.append('{}{}'.format(ip[:-1], i))
    return ip_lists

def main(ip=None):
    ip_lists=get_ip_lists(ip)
    nmScan,temp_ip_lists,hosts = nmap.PortScanner(),[],ip[:-1]+'0/24'
    ret = nmScan.scan(hosts=hosts, arguments='-sP')
    print('扫描时间：'+ret['nmap']['scanstats']['timestr'])
    for ip in ip_lists:
        if ip not in ret['scan']:
            temp_ip_lists.append(ip)
    print(str(hosts) +' 网络中的存活主机:')
    for ip in temp_ip_lists:ip_lists.remove(ip)
    for ip in ip_lists:
        print(ip)
        f.write(ip+"\n")


if __name__ == '__main__':
    f = open("/Users/devi1/Desktop/upip.txt", 'w+')
    ip = raw_input("输入ipc段(例如：192.168.1):") +".1"#'180.149.139'
    main(ip)
    f.close()