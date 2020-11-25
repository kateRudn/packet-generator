import PySimpleGUI as sg
import scapy.all as sc

interfaces=[]

def showInterfaces():
    for interface in sc.get_windows_if_list():
        interfaces.append(interface['name'] + ': ' + interface['description'])
    return interfaces;

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
lau2=sg.Column([[sg.Frame('Protocols', layout_protocols)], [sg.Frame('Send', layout_send)]])
layout=[layout_ntwrk, [lau1, lau2], layout_other]
window = sg.Window('Packet Generator', layout)

while True:
    event, values = window.read()
    if event in (None, 'Exit', 'Cancel'):
        break
    #if event == 'Submit':
window.close()