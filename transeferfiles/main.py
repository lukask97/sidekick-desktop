import os
import socket
import zipfile
from tkinter import Entry, Label, StringVar
from tkinter import ttk
from tkinter.filedialog import askopenfilename

import paramiko
import scapy.all as scapy
from paramiko import SSHClient
from prettytable import PrettyTable
from tkinterdnd2 import *


# Networking

def scan(ip_range):
    print(f"Scanning IP range: {ip_range}")

    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    print("Sending ARP requests...")
    answered_list = scapy.srp(arp_request_broadcast, timeout=10, verbose=True)[0]

    if not answered_list:
        print("No responses received.")
    else:
        print("Responses received.")

    devices = []
    for element in answered_list:
        device = {'ip': element[1].psrc, 'mac': element[1].hwsrc}
        try:
            device['hostname'] = socket.gethostbyaddr(element[1].psrc)[0]
        except:
            device['hostname'] = 0
        devices.append(device)

    return devices


def scan_network(ip_range):
    devices = scan(ip_range)
    display_devices(devices)
    return devices


def display_devices(devices):
    if devices:
        t = PrettyTable(['IP', "Hostname"])
        t.align = "l"
        for device in devices:
            t.add_row([str(device['ip']), str(device['hostname'])])
        print(t.get_string(sortby="Hostname"))
    else:
        print("No devices found.")


def do_scan(event):
    ip_range = '192.168.178.0/24'
    devices = scan_network(ip_range)
    dropdownlist = []
    for device in devices:
        dropdownlist.append(device['hostname'])
    dropdown.configure(values=dropdownlist)
    dropdown.current(0)


def get_path(event):
    event.widget.configure(textvariable=StringVar(value=event.data))


def openfiledialog(event):
    event.widget.configure(textvariable=StringVar(
        value=askopenfilename(title="Datei ausählen", initialdir=os.getcwd(), initialfile="test.txt")))


text_IP = "192.168.137.32"
text_Name = "deck"

root = TkinterDnD.Tk()
root.geometry("640x480")
root.title("SFTP-Uploader")

frm = ttk.Frame(root, padding=10)
frm.grid()

lb_IP = Label(frm, text="IP oder hostname")
lb_IP.grid(column=0, row=0)
tb_IP = Entry(frm, textvariable=StringVar(value=text_IP))
tb_IP.grid(column=0, row=1)

lb_Name = Label(frm, text="Benutzername")
lb_Name.grid(column=1, row=0)
tb_Name = Entry(frm, textvariable=StringVar(value=text_Name))
tb_Name.grid(column=1, row=1)

lb_PWD = Label(frm, text="Passwort")
lb_PWD.grid(column=2, row=0)
tb_PWD = Entry(frm, show="*")
tb_PWD.grid(column=2, row=1)

entryWidget = Entry(frm)
entryWidget.grid(column=0, columnspan=2, row=2, sticky='ew')
entryWidget.drop_target_register(DND_ALL)
entryWidget.dnd_bind("<<Drop>>", get_path)

entryWidget2 = Entry(frm)
entryWidget2.grid(column=0, columnspan=2, row=3, sticky='ew')
entryWidget2.drop_target_register(DND_ALL)
entryWidget2.dnd_bind("<<Drop>>", get_path)

entryWidget3 = Entry(frm, textvariable=StringVar(value="Choose File or drop File here"))
entryWidget3.grid(column=0, columnspan=2, row=4, sticky='ew')
entryWidget3.drop_target_register(DND_ALL)
entryWidget3.dnd_bind("<<Drop>>", get_path)
entryWidget3.dnd_bind("<Button>", openfiledialog)

dropdown = ttk.Combobox(frm)
dropdown.grid(column=2, columnspan=1, row=5, sticky='ew')


def works(event):
    ssh = SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname=tb_IP.get(), username="deck", password=tb_PWD.get(),
                disabled_algorithms={'keys': ['rsa-sha2-256', 'rsa-sha2-512']})
    print("Connected")
    sftp = ssh.open_sftp()
    sftp.put(entryWidget.get(), 'Desktop/text.txt')
    sftp.close()
    ssh.close()

    print("works")


def unzip(event):
    with zipfile.ZipFile(entryWidget2.get(), "r") as zip_ref:
        zip_ref.extractall("tmp")

    print("works")


button1 = ttk.Button(frm, text="<--- Senden")
button1.grid(column=2, row=2)
button1.drop_target_register(DND_ALL)
button1.dnd_bind('<Button>', works)

button2 = ttk.Button(frm, text="<--- Unzip")
button2.grid(column=2, row=3)
button2.drop_target_register(DND_ALL)
button2.dnd_bind('<Button>', unzip)

button3 = ttk.Button(frm, text="ARP-Network-Scan")
button3.grid(column=2, row=4)
button3.drop_target_register(DND_ALL)
button3.dnd_bind('<Button>', do_scan)
# print(get_if_list())
# print(ni.interfaces())

root.mainloop()
