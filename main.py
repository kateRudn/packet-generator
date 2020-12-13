import PySimpleGUI as sg
import scapy.all as sc
from scapy.layers.inet import *
from scapy.all import send, get_windows_if_list #send - посылка пакетов, get_windows_if_list - показ доступных  сетевых интерфейсов
from datetime import datetime


interfaces=[]

TCP_NUM = 6
UDP_NUM = 17
ICMP_NUM = 1

def showInterfaces():
    for interface in sc.get_windows_if_list():
        interfaces.append(interface['name'] + ': ' + interface['description'])
    return interfaces;

def calcTOS(values):
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
    else:
        tos += '11'

    tos = int(tos, 2)
    return tos

def calcFlags(values):
    return "{0}{1}{2}".format(str(int(values['res'])), str(int(values['df'])), str(int(values['mf'])))

def toDec(x, n):
    try:
        return int(x, n)
    except:
        return 'Input Error'

def ipPckt(values):
    ipPacket=IP()
    if values['win']=='TCPwin':
        ipPacket.proto=TCP_NUM
        #print ("TCP")
    elif values['win']=='UDPwin':
        ipPacket.proto=UDP_NUM
    elif values['win']=='ICMPwin':
        ipPacket.proto=ICMP_NUM
    ipPacket.ttl = int(values['ttl'])
    ipPacket.ihl = int(values['ihl'])
    ipPacket.tos = calcTOS(values)
    ipPacket.id = int(values['id'])
    ipPacket.len = int(values['lenght'])
    ipPacket.frag = int(values['offset'])
    ipPacket.version = int(values['version'])
    ipPacket.chksum = int(values['chksum'])
    if (values['dst']):
        ipPacket.dst = values['dst']
    if (values['src']):
        ipPacket.src = values['src']
    ipPacket.flags = toDec(calcFlags(values), 2)
    return ipPacket

def tcpPckt(values):
    tcpPacket = TCP()
    if (values['srcportTCP']):
        tcpPacket.sport=int(values['srcportTCP'])
    if (values['destportTCP']):
        tcpPacket.sport=int(values['srcportTCP'])
    tcpPacket.seq = int(values['seqnumTCP'])
    tcpPacket.ack = int(values['acknumTCP'])
    tcpPacket.dataofs = int(values['offsetTCP'])
    tcpPacket.reserved = int(values['resTCP'])
    tcpPacket.reserved = int(values['resTCP'])
    return tcpPacket

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
                [sg.Text('SRC address'), sg.InputText(default_text='192.168.1.1', size=(20, 20), key='src')],
                [sg.Text('DST address'), sg.InputText(default_text='192.168.1.10', size=(20, 20), key='dst')]
                ])
    ]])],
    [sg.Frame('Fields', [[sg.Column([
                [sg.Text('TTL'), sg.InputText(size=(10, 20), key='ttl', pad=(5,0))],
                [sg.Text('IHL'), sg.InputText(size=(10, 20), key='ihl', pad=(7,0))],
                [sg.Text('TOS'), sg.InputText(size=(10, 20), key='tos', pad=(0,0))],
                [sg.Text('ID'), sg.InputText(size=(10, 20), key='id', pad=(13, 0))]
                ])
        ,
        sg.Column([
                [sg.Text('Total Lenght'), sg.InputText(size=(10, 20), key='lenght', pad=(0,0))],
                [sg.Text('Offset'), sg.InputText(size=(10, 20), key='offset', pad=(36,0))],
                [sg.Text('Version', pad=(11,0)), sg.InputText(size=(10, 20), key='version', pad=(14,0))],
                [sg.Text('Checksum'), sg.InputText(size=(10, 20), key='chksum', pad=(8, 0))]
                ]),
    ]])],
    [sg.Frame('Flags', [[sg.Checkbox('MF', key=('mf')), sg.Checkbox('DF', key=('df')), sg.Checkbox('Reserve', key=('res'))]])],
    [sg.Frame('Type of service', [[sg.Column([
                [sg.Text('ECN', pad=(0,0)), sg.InputOptionMenu(values=('ECT', 'Not-ECT', 'CE'), key='ecn')],
                [sg.Text('Precenden', pad=(0,0)), sg.InputText(size=(10, 20), key='prec')],
                [sg.Checkbox('Delay', key=('delay'), pad=(0,0))],
                [sg.Checkbox('Reliability', key=('reliab'), pad=(0,0))],
                [sg.Checkbox('Bandwidth', key=('bandw'), pad=(0,0))]
                ])]])],
    [sg.Frame('Data',[[sg.Multiline(size=(40, 10), key='data')]])],
]

layout_protocols = [
    [sg.TabGroup(tab_group_layout, enable_events=True, key='win'),]
]

layout_other=[sg.Submit(), sg.Cancel()]
layout_send=[[sg.Output(size=(50,10))]]
lau1=sg.Column([[sg.Frame('IPv4', layout_ipv4)]])
lau2=sg.Column([[sg.Frame('Protocols', layout_protocols)], [sg.Frame('Send', layout_send)], [sg.Button('Add packet', key='addPckt'), sg.Button('Clear', key='clearPckt'), sg.Button('Send', key='sendPckt')]])
layout=[layout_ntwrk, [lau1, lau2], layout_other]
window = sg.Window('Packet Generator', layout)

while True:
    event, values = window.read()
    if event in (None, 'Exit', 'Cancel'):
        break
    if event == 'Submit':
        ipPckt(values)
window.close()

