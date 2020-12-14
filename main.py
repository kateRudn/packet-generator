import PySimpleGUI as sg
import scapy.all as sc
from scapy.layers.inet import *
from datetime import datetime

interfaces = []
packetQueue = []

TCP_NUM = 6
UDP_NUM = 17
ICMP_NUM = 1

def showInterfaces():
    for interface in sc.get_windows_if_list():
        interfaces.append(interface['name'] + ': ' + interface['description'])
    return interfaces;

def calcTosFlags(values):
    return "{0}{1}{2}".format(str(int(values['delay'])),str(int(values['bandw'])),str(int(values['reliab'])))

def calcTOS(values):
    tos='0'
    if (values['prec']):
        tos = bin(int(values['prec']))
        tos = str(tos)
    if values['delay']:
        tos += '1'
    else:
        tos += '0'
    if values['bandw']:
        tos += '1'
    else:
        tos += '0'
    if values['reliab']:
        tos += '1'
    else:
        tos += '0'
    if values['ecn'] == 'ECT':
        tos += '01'
    if values['ecn'] == 'Not-ECT':
        tos += '00'
    elif values['ecn'] == 'CE':
        tos += '11'
    tos = int(tos, 2)
    return tos

def calcIPFlags(values):
    return "{0}{1}{2}".format(str(int(values['res'])), str(int(values['df'])), str(int(values['mf'])))

def calcTCPFlags(values):
    return "{0}{1}{2}{3}{4}{5}{6}{7}".format(
        str(int(values['cwrTCP'])),  # окно перегрузки уменьшено
        str(int(values['eceTCP'])),  # если SYN=1, то ECE установлено, иначе перегрузка
        str(int(values['urgTCP'])),  # передача ссылки на поле указателя срочности
        str(int(values['ackTCP'])),  # содержание значения номера подтверждения
        str(int(values['pshTCP'])),  # установка типа пакета на пакет проталкивания
        str(int(values['rstTCP'])),  # сброс соединения
        str(int(values['synTCP'])),  # начало соединения и синхронизация
        str(int(values['finTCP']))) # завершение соединения

def toDec(x, n):
    try:
        return int(x, n)
    except:
        return 'Input Error'

def ipPckt(values):
    ipPacket=IP()
    if values['win']=='TCPwin':
        ipPacket.proto=TCP_NUM
    elif values['win']=='UDPwin':
        ipPacket.proto=UDP_NUM
    elif values['win']=='ICMPwin':
        ipPacket.proto=ICMP_NUM
    if (values['ttl']):
        ipPacket.ttl = int(values['ttl'])
    if (values['ihl']):
        ipPacket.ihl = int(values['ihl'])
    ipPacket.tos = calcTOS(values)
    if (values['id']):
        ipPacket.id = int(values['id'])
    if (values['lenght']):
        ipPacket.len = int(values['lenght'])
    if (values['offset']):
        ipPacket.frag = int(values['offset'])
    if (values['version']):
        ipPacket.version = int(values['version'])
    if (values['chksum']):
        ipPacket.chksum = int(values['chksum'])
    if (values['dst']):
        ipPacket.dst = values['dst']
    if (values['src']):
        ipPacket.src = values['src']
    ipPacket.flags = toDec(calcIPFlags(values), 2)
    return ipPacket

def tcpPckt(values):
    tcpPacket = TCP()
    if (values['srcportTCP']):
        tcpPacket.sport=int(values['srcportTCP'])
    if (values['destportTCP']):
        tcpPacket.sport=int(values['srcportTCP'])
    if (values['seqnumTCP']):
        tcpPacket.seq = int(values['seqnumTCP'])
    if (values['acknumTCP']):
        tcpPacket.ack = int(values['acknumTCP'])
    if (values['offsetTCP']):
        tcpPacket.dataofs = int(values['offsetTCP'])
    if (values['resTCP']):
        tcpPacket.reserved = int(values['resTCP'])
    if (values['chksumTCP']):
        tcpPacket.chksum = int(values['chksumTCP'])
    if (values['winszTCP']):
        tcpPacket.window = int(values['winszTCP'])
    if (values['urgpTCP']):
        tcpPacket.urgptr = int(values['urgpTCP'])
    tcpPacket.flags = toDec(calcTCPFlags(values), 2)
    return tcpPacket

def udpPckt(values):
    udpPacket = UDP()
    if (values['srcportUDP']):
        udpPacket.sport=int(values['srcportUDP'])
    if (values['destportUDP']):
        udpPacket.sport=int(values['srcportUDP'])
    if (values['lenUDP']):
        udpPacket.len = int(values['lenUDP'])
    if (values['chksumUDP']):
        udpPacket.chksum = int(values['chksumUDP'])
    return udpPacket

def icmpPckt(values):
    icmpPacket = ICMP()
    if values['typReply']:
        icmpPacket.type = 0
    elif values['typReq']:
        icmpPacket.type = 8
    if (values['codeICMP']):
        icmpPacket.code = int(values['codeICMP'])
    if (values['idICMP']):
        icmpPacket.id = int(values['idICMP'])
    if (values['chksumICMP']):
        icmpPacket.chksum = int(values['chksumICMP'])
    if (values['seqnumICMP']):
        icmpPacket.seq = int(values['seqnumICMP'])
    return icmpPacket

def formPckt(values):
    ip = ipPckt(values)
    if values['win'] =='TCPwin':
        protocol = tcpPckt(values)
    elif values['win'] =='UDPwin':
        protocol = udpPckt(values)
    elif values['win'] =='ICMPwin':
        protocol = icmpPckt(values)
    data = values['data']
    return ip / protocol / data

def addPckt(values):
    packetQueue.append(formPckt(values))
    if values['win'] == 'TCPwin':
        sendInfo = "TCP: " + str(datetime.now().time())
    elif values['win'] == 'UDPwin':
        sendInfo = "UDP: " + str(datetime.now().time())
    elif values['win'] == 'ICMPwin':
        sendInfo = "ICMP: " + str(datetime.now().time())
    print(sendInfo)
    return

def clearPckt():
    packetQueue.clear()
    window.FindElement('data').update('')
    window.FindElement('send').update('')
    return

def sendPckt(values):
    for packet in packetQueue:
       sc.send(packet, iface=values['ntwrk'].split(':')[0])
    packetQueue.clear()
    window.FindElement('send').update('')
    return

layout_tcp = [[sg.Frame('Fields', [[sg.Column([
                [sg.Text('Source Port'), sg.InputText(size=(10, 20), key='srcportTCP', pad=(0,0))],
                [sg.Text('Destination Port'), sg.InputText(size=(10, 20), key='destportTCP', pad=(0,0))],
                [sg.Text('Sequence Number'), sg.InputText(size=(10, 20), key='seqnumTCP', pad=(0,0))],
                [sg.Text('Acknowledgment Number'), sg.InputText(size=(10, 20), key='acknumTCP', pad=(0, 0))],
                [sg.Text('Offset'), sg.InputText(size=(10, 20), key='offsetTCP', pad=(0, 0))],
                [sg.Text('Reserved'), sg.InputText(size=(10, 20), key='resTCP', pad=(0, 0))],
                [sg.Text('Checksum'), sg.InputText(size=(10, 20), key='chksumTCP', pad=(0, 0))],
                [sg.Text('Window Size'), sg.InputText(size=(10, 20), key='winszTCP', pad=(0, 0))],
                [sg.Text('Urgent Pointer'), sg.InputText(size=(10, 20), key='urgpTCP', pad=(0, 0))],
                [sg.Frame('Flags', [[
                sg.Column([
                [sg.Checkbox('SYN', key='synTCP')],
                [sg.Checkbox('ACK', key='ackTCP')],
                [sg.Checkbox('PSH', key='pshTCP')]
                ]),
                sg.Column([
                [sg.Checkbox('URG', key='urgTCP')],
                [sg.Checkbox('RST', key='rstTCP')],
                [sg.Checkbox('FIN', key='finTCP')]
                ]),
                sg.Column([
                [sg.Checkbox('ECE', key='eceTCP')],
                [sg.Checkbox('CWR', key='cwrTCP')]
                ]),
                ]])],
                ])]])]
                ]
layout_udp = [[sg.Column([
                [sg.Text('Source Port'), sg.InputText(size=(10, 20), key='srcportUDP', pad=(0,0))],
                [sg.Text('Destination Port'), sg.InputText(size=(10, 20), key='destportUDP', pad=(0,0))],
                [sg.Text('Lenght'), sg.InputText(size=(10, 20), key='lenUDP', pad=(0,0))],
                [sg.Text('Checksum'), sg.InputText(size=(10, 20), key='chksumUDP', pad=(0, 0))]
                ])]
                ]
layout_icmp = [[sg.Column([
                [sg.Text('Type'), sg.Radio('Echo request', '', key='typReq'), sg.Radio('Echo reply', '', key='typReply')],
                [sg.Text('Code'), sg.InputText(size=(10, 20), key='codeICMP', pad=(0,0))],
                [sg.Text('ID'), sg.InputText(size=(10, 20), key='idICMP', pad=(0,0))],
                [sg.Text('Checksum'), sg.InputText(size=(10, 20), key='chksumICMP', pad=(0, 0))],
                [sg.Text('Sequence Number'), sg.InputText(size=(10, 20), key='seqnumICMP', pad=(0, 0))]
                ])]
]

tab_group_layout = [[sg.Tab('TCP', layout_tcp, font='Courier 15', key='TCPwin'),
                     sg.Tab('UDP', layout_udp, font='Courier 15', key='UDPwin'),
                     sg.Tab('ICMP', layout_icmp, font='Courier 15', key='ICMPwin'),
                     ]]

layout_ntwrk=[sg.Text('Network Adapter'), sg.InputOptionMenu(values=showInterfaces(), key='ntwrk')]

layout_ipv4=[
    [sg.Frame('Adresses', [[sg.Column([
                [sg.Text('SRC address'), sg.InputText(size=(20, 20), key='src')],
                [sg.Text('DST address'), sg.InputText(size=(20, 20), key='dst')]
                ])
    ]])],
    [sg.Frame('Fields', [[sg.Column([
                [sg.Text('TTL'), sg.InputText(default_text=64, size=(10, 20), key='ttl', pad=(5,0))],
                [sg.Text('IHL'), sg.InputText(size=(10, 20), key='ihl', pad=(7,0))],
                [sg.Text('ID'), sg.InputText(size=(10, 20), key='id', pad=(13, 0))]
                ])
        ,
        sg.Column([
                [sg.Text('Total Lenght'), sg.InputText(size=(10, 20), key='lenght', pad=(0,0))],
                [sg.Text('Offset'), sg.InputText(default_text=0, size=(10, 20), key='offset', pad=(36,0))],
                [sg.Text('Version', pad=(11,0)), sg.InputText(default_text=4, size=(10, 20), key='version', pad=(14,0))],
                [sg.Text('Checksum'), sg.InputText(size=(10, 20), key='chksum', pad=(8, 0))]
                ]),
    ]])],
    [sg.Frame('Flags', [[sg.Checkbox('MF', key=('mf')), sg.Checkbox('DF', key=('df')), sg.Checkbox('Reserve', key=('res'))]])],
    [sg.Frame('Type of service', [[sg.Column([
                [sg.Text('ECN', pad=(0,0)), sg.InputOptionMenu(values=('ECT', 'Not-ECT', 'CE'), key='ecn')],
                [sg.Text('Precenden', pad=(0,0)), sg.InputText(default_text=0, size=(10, 20), key='prec')],
                [sg.Checkbox('Delay', key=('delay'), pad=(0,0))],
                [sg.Checkbox('Reliability', key=('reliab'), pad=(0,0))],
                [sg.Checkbox('Bandwidth', key=('bandw'), pad=(0,0))]
                ])]])],
    [sg.Frame('Data',[[sg.Multiline(size=(40, 10), key='data')]])],
]

layout_protocols = [
    [sg.TabGroup(tab_group_layout, enable_events=True, key='win'),]
]

layout_other=[sg.Button('Clear all', key='clearAll')]
layout_send=[[sg.Output(size=(50,10), key='send')]]
lau1=sg.Column([[sg.Frame('IPv4', layout_ipv4)]])
lau2=sg.Column([[sg.Frame('Protocols', layout_protocols)], [sg.Frame('Send', layout_send)], [sg.Button('Add packet', key='addPckt'), sg.Button('Clear', key='clearPckt'), sg.Button('Send', key='sendPckt')]])
layout=[layout_ntwrk, [lau1, lau2], layout_other]
window = sg.Window('Packet Generator', layout)

while True:
    event, values = window.read()
    if event in (None, 'Exit', 'Cancel'):
        break
    if event == 'addPckt':
        addPckt(values)
    if event == 'sendPckt':
        sendPckt(values)
    if event == 'clearPckt':
        clearPckt()
window.close()

