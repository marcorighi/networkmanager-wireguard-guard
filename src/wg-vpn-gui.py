#!/usr/bin/env python3
"""Two-route indicator GUI; LEDs describe inferred routing, not packet rates."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tkinter as tk
from tkinter import messagebox, ttk

CONFIG = Path('/etc/networkmanager-wireguard-guard/sites.json')
GUARD = '/usr/local/sbin/wg-guard'
WRAPPER = '/usr/local/bin/wg-vpn'
DARK = '#18232f'
LIGHT = '#eef5fa'
GREEN = '#34c38f'
OFF = '#607080'
WARN = '#f4b942'


def shell(*args, timeout=5):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


class App:
    def __init__(self):
        self.sites = json.loads(CONFIG.read_text(encoding='utf-8'))['sites']
        self.root = tk.Tk()
        self.root.title('WireGuard routing dashboard')
        self.root.geometry('630x400')
        self.root.configure(bg=DARK)
        self.destination = tk.StringVar(value='homeLAN')
        self.mode = tk.StringVar(value='full')
        tk.Label(self.root, text='WireGuard connections', font=('Sans', 18, 'bold'),
                 bg=DARK, fg=LIGHT).pack(pady=14)
        self.state = tk.Label(self.root, text='Inspecting...', bg=DARK, fg=LIGHT)
        self.state.pack(pady=5)
        route = tk.Frame(self.root, bg=DARK)
        route.pack(fill='x', pady=15, padx=15)
        self.leds = {}
        for label in ('Guest Internet', 'WireGuard tunnel'):
            cell = tk.Frame(route, bg=DARK)
            cell.pack(side='left', expand=True)
            bulb = tk.Canvas(cell, width=35, height=36, bg=DARK, highlightthickness=0)
            oval = bulb.create_oval(5, 5, 31, 31, fill=OFF, outline='')
            bulb.pack()
            tk.Label(cell, text=label, bg=DARK, fg=LIGHT).pack()
            self.leds[label] = bulb, oval
        controls = tk.Frame(self.root, bg=DARK)
        controls.pack(pady=13)
        ttk.Combobox(controls, values=('homeLAN', 'workLAB'), textvariable=self.destination,
                     state='readonly', width=16).grid(row=0, column=0, padx=8)
        ttk.Combobox(controls, values=('full', 'split'), textvariable=self.mode,
                     state='readonly', width=12).grid(row=0, column=1, padx=8)
        tk.Button(controls, text='Connect', command=self.connect).grid(row=1, column=0, pady=12)
        tk.Button(controls, text='Disconnect', command=self.disconnect).grid(row=1, column=1)
        tk.Label(self.root, text='Indicators show routing permissions, not real-time packet activity.\n'
                                  'Encrypted VPN and permitted LAN packets still use the physical interface.',
                 bg=DARK, fg=LIGHT, justify='center').pack(pady=10)
        self.root.after(250, self.update_status)

    def set_led(self, name, status):
        canvas, oval = self.leds[name]
        canvas.itemconfigure(oval, fill={'on': GREEN, 'off': OFF, 'unknown': WARN}[status])

    def update_status(self):
        try:
            cp = shell('nmcli', '-t', '-f', 'NAME,TYPE,DEVICE', 'connection', 'show', '--active')
            if cp.returncode:
                raise RuntimeError('Cannot inspect NetworkManager')
            lines = [line.rsplit(':', 2) for line in cp.stdout.splitlines()]
            active = {row[0] for row in lines if len(row) == 3 and row[1] == 'wireguard'}
            full = {site['full_profile'] for site in self.sites.values()}
            split = {site['split_profile'] for site in self.sites.values()}
            guard = shell('sudo', '-n', GUARD, 'status')
            verified = guard.returncode == 0
            guarded = verified and 'Firewall guard: ACTIVE' in guard.stdout and 'Guard state: PRESENT' in guard.stdout
            absent = verified and 'Firewall guard: ABSENT' in guard.stdout and 'Guard state: ABSENT' in guard.stdout
            if active & full:
                self.set_led('Guest Internet', 'off' if guarded else 'unknown')
                self.set_led('WireGuard tunnel', 'on' if guarded else 'unknown')
                text = 'Protected full tunnel' if guarded else 'WARNING: unverified full-tunnel guard'
            elif guarded:
                self.set_led('Guest Internet', 'off')
                self.set_led('WireGuard tunnel', 'off')
                text = 'Guard active; VPN tunnel disconnected'
            elif active & split and absent:
                self.set_led('Guest Internet', 'on')
                self.set_led('WireGuard tunnel', 'on')
                text = 'Split tunnel active'
            elif absent:
                self.set_led('Guest Internet', 'on')
                self.set_led('WireGuard tunnel', 'off')
                text = 'No protected VPN active'
            else:
                self.set_led('Guest Internet', 'unknown')
                self.set_led('WireGuard tunnel', 'unknown')
                text = 'Guard state unavailable or inconsistent'
            self.state.config(text=text)
        except (OSError, ValueError, KeyError, subprocess.TimeoutExpired) as exc:
            self.set_led('Guest Internet', 'unknown')
            self.set_led('WireGuard tunnel', 'unknown')
            self.state.config(text='Status unavailable: ' + str(exc)[:90])
        self.root.after(2500, self.update_status)

    def execute(self, args):
        terminal = shutil.which('xfce4-terminal')
        if not terminal:
            messagebox.showerror('Terminal missing', 'Install xfce4-terminal')
            return
        subprocess.Popen([terminal, '--disable-server', '--hold', '--execute', WRAPPER, *args],
                         start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def connect(self):
        self.execute([self.destination.get(), self.mode.get()])

    def disconnect(self):
        self.execute([self.destination.get(), 'stop'])


if __name__ == '__main__':
    App().root.mainloop()
