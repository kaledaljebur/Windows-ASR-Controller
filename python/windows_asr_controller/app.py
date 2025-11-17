#!/usr/bin/env python3
# Windows ASR Controller
# Author: Kaled Aljebur
# Requires: Windows, admin rights, Microsoft Defender active
import os
import sys
import json
import ctypes
import subprocess
import threading
import platform
from tkinter import *
from tkinter import ttk, filedialog, messagebox

APP_TITLE = "Windows ASR Controller"
APP_WIDTH, APP_HEIGHT = 980, 620

ASR_RULES = {
    "56a863a9-875e-4185-98a7-b882c64b5ce5": "Block abuse of exploited vulnerable signed drivers",
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c": "Block Adobe Reader from creating child processes",
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a": "Block all Office applications from creating child processes",
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2": "Block credential stealing from LSASS",
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550": "Block executable content from email client and webmail",
    "01443614-cd74-433a-b99e-2ecdc07bfc25": "Block executable files unless prevalence/age/trusted",
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc": "Block execution of potentially obfuscated scripts",
    "d3e037e1-3eb8-44c8-a917-57927947596d": "Block JS/VBS from launching downloaded executable content",
    "3b576869-a4ec-4529-8536-b80a7769e899": "Block Office apps from creating executable content",
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84": "Block Office apps from injecting code into other processes",
    "26190899-1602-49e8-8b27-eb1d0a1ce869": "Block Office comms apps from creating child processes",
    "e6db77e5-3df2-4cf1-b95a-636979351e5b": "Block persistence through WMI event subscription",
    "d1e49aac-8f56-4280-b9ba-993a6d77406c": "Block process creations from PSExec and WMI commands",
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4": "Block untrusted/unsigned processes from USB",
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b": "Block Win32 API calls from Office macros",
    "c1db55ab-c21a-4637-bb3f-a12568109d35": "Use advanced protection against ransomware",
    "33ddedf1-c6e0-47cb-833e-de6133960387": "Block rebooting machine in Safe Mode (preview)",
    "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb": "Block use of copied/impersonated system tools (preview)",
    "a8f5898e-1dc8-49a9-9878-85004b8a61e6": "Block Webshell creation for Servers",
}

STATUS_MAP_TO_TEXT = {
    "0": "Disabled",
    "1": "Enabled",
    "2": "AuditMode",
    "6": "Warn",
}
STATUS_MAP_FROM_SHORT = {
    "D": "Disabled", "DISABLED": "Disabled", "0": "Disabled",
    "E": "Enabled",  "ENABLED":  "Enabled",  "1": "Enabled",
    "A": "AuditMode","AUDIT":    "AuditMode","2": "AuditMode",
    "W": "Warn",     "WARN":     "Warn",     "6": "Warn",
}
VALID_ACTIONS = {"Disabled", "Enabled", "AuditMode", "Warn"}

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def is_windows():
    return platform.system().lower().startswith("win")

def run_powershell(ps_command):
    """Run PowerShell one-shot and return (exitcode, stdout, stderr)."""
    cmd = [
        "powershell.exe",
        "-NoLogo",
        "-NonInteractive",
        "-NoProfile",
        "-WindowStyle", "Hidden",
        "-ExecutionPolicy", "Bypass",
        "-Command", ps_command
    ]
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    CREATE_NO_WINDOW = 0x08000000
    proc = subprocess.Popen(cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        startupinfo=startupinfo,
        creationflags=CREATE_NO_WINDOW,
    )
    out, err = proc.communicate()
    return proc.returncode, out.strip(), err.strip()

def defender_cmdlets_available():
    code, out, err = run_powershell(
        r"$a = Get-Command Get-MpPreference -ErrorAction SilentlyContinue; "
        r"if ($a) { 'true' } else { 'false' }"
    )
    if code != 0:
        return False
    return out.lower() == "true"

def defender_is_active():
    code, out, err = run_powershell(
        r"try { $null = Get-MpPreference; 'true' } catch { 'false' }"
    )
    return (code == 0) and (out.lower() == "true")

def ps_json_status():
    ps = r"""
$mp = Get-MpPreference
$ids = $mp.AttackSurfaceReductionRules_Ids
$acts = $mp.AttackSurfaceReductionRules_Actions
if (-not $ids) { '[]' | Write-Output; exit }
$map = @{ '0'='Disabled'; '1'='Enabled'; '2'='AuditMode'; '6'='Warn' }
$out = @()
for ($i=0; $i -lt $ids.Count; $i++) {
  $out += [PSCustomObject]@{
    RuleID = $ids[$i]
    Status = $map[[string]$acts[$i]]
  }
}
$out | ConvertTo-Json -Depth 3
"""
    return run_powershell(ps)

def ps_apply(rule_id, action_text):
    ps = f"Add-MpPreference -AttackSurfaceReductionRules_Ids '{rule_id}' -AttackSurfaceReductionRules_Actions {action_text} -ErrorAction Stop"
    return run_powershell(ps)

def ps_remove(rule_id):
    ps = f"Remove-MpPreference -AttackSurfaceReductionRules_Ids '{rule_id}' -ErrorAction Stop"
    return run_powershell(ps)

def safe_action_label(action):
    up = str(action).upper()
    return STATUS_MAP_FROM_SHORT.get(up, action)

class App(Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry(f"{APP_WIDTH}x{APP_HEIGHT}")
        self.minsize(860, 520)

        self._make_menu()
        self._make_layout()

        if not is_windows():
            messagebox.showerror("Unsupported OS", "This app requires Windows.")
            self._log("ERROR: Not running on Windows.")
            return
        if not is_admin():
            messagebox.showerror("Admin required", "Please run as Administrator.")
            self._log("ERROR: Not elevated. Re-run as Administrator.")
            return
        if not defender_cmdlets_available() or not defender_is_active():
            messagebox.showerror("Defender not available", "Microsoft Defender Antivirus is not active. ASR cannot be managed.")
            self._log("ERROR: Defender cmdlets/service unavailable.")
            return

        self.refresh_status()

    def _make_menu(self):
        menubar = Menu(self)

        filem = Menu(menubar, tearoff=0)
        filem.add_command(label="Export JSON…", command=self.export_json)
        filem.add_command(label="Import JSON…", command=self.import_json)
        filem.add_separator()
        filem.add_command(label="Exit", command=self.quit)
        menubar.add_cascade(label="File", menu=filem)

        actionm = Menu(menubar, tearoff=0)
        actionm.add_command(label="Enable ALL", command=lambda: self.bulk_apply("Enabled"))
        actionm.add_command(label="Disable ALL", command=lambda: self.bulk_apply("Disabled"))
        actionm.add_command(label="Audit ALL", command=lambda: self.bulk_apply("AuditMode"))
        actionm.add_command(label="Warn ALL", command=lambda: self.bulk_apply("Warn"))
        actionm.add_separator()
        actionm.add_command(label="Reset selected (NotConfigured)", command=self.reset_selected)
        menubar.add_cascade(label="Actions", menu=actionm)

        helpm = Menu(menubar, tearoff=0)
        helpm.add_command(label="Testing links", command=self.show_testing_links)
        helpm.add_command(label="About", command=lambda: messagebox.showinfo("About", APP_TITLE + "\nGUI manager for Defender ASR rules."))
        menubar.add_cascade(label="Help", menu=helpm)

        self.config(menu=menubar)

    def _make_layout(self):
        top = ttk.Frame(self)
        top.pack(side=TOP, fill=X, padx=10, pady=8)

        ttk.Label(top, text="Quick Actions:").pack(side=LEFT, padx=(0,8))
        ttk.Button(top, text="Refresh", command=self.refresh_status).pack(side=LEFT, padx=4)
        ttk.Button(top, text="Enable All", command=lambda: self.bulk_apply("Enabled")).pack(side=LEFT, padx=4)
        ttk.Button(top, text="Disable All", command=lambda: self.bulk_apply("Disabled")).pack(side=LEFT, padx=4)
        ttk.Button(top, text="Audit All", command=lambda: self.bulk_apply("AuditMode")).pack(side=LEFT, padx=4)
        ttk.Button(top, text="Warn All", command=lambda: self.bulk_apply("Warn")).pack(side=LEFT, padx=4)

        middle = ttk.Frame(self)
        middle.pack(side=TOP, fill=BOTH, expand=True, padx=10, pady=(0,8))

        cols = ("Status", "RuleID", "Name")
        self.tree = ttk.Treeview(middle, columns=cols, show="headings", selectmode="extended")
        self.tree.heading("Status", text="Status")
        self.tree.heading("RuleID", text="RuleID")
        self.tree.heading("Name", text="Rule Description")
        self.tree.column("Status", width=110, anchor=W)
        self.tree.column("RuleID", width=360, anchor=W)
        self.tree.column("Name", width=520, anchor=W)

        yscroll = ttk.Scrollbar(middle, orient=VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=yscroll.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")

        right = ttk.Frame(middle)
        right.grid(row=0, column=2, sticky="nsw", padx=(10,0))
        ttk.Label(right, text="Selected Rules:").pack(anchor="w", pady=(0,6))
        ttk.Button(right, text="Enable", command=lambda: self.apply_selected("Enabled")).pack(fill=X, pady=2)
        ttk.Button(right, text="Disable", command=lambda: self.apply_selected("Disabled")).pack(fill=X, pady=2)
        ttk.Button(right, text="Audit", command=lambda: self.apply_selected("AuditMode")).pack(fill=X, pady=2)
        ttk.Button(right, text="Warn", command=lambda: self.apply_selected("Warn")).pack(fill=X, pady=2)
        ttk.Separator(right, orient=HORIZONTAL).pack(fill=X, pady=8)
        ttk.Button(right, text="Reset (NotConfigured)", command=self.reset_selected).pack(fill=X, pady=2)
        ttk.Separator(right, orient=HORIZONTAL).pack(fill=X, pady=8)
        ttk.Button(right, text="Export JSON…", command=self.export_json).pack(fill=X, pady=2)
        ttk.Button(right, text="Import JSON…", command=self.import_json).pack(fill=X, pady=2)

        middle.columnconfigure(0, weight=1)
        middle.rowconfigure(0, weight=1)

        bottom = ttk.Frame(self)
        bottom.pack(side=TOP, fill=BOTH, expand=False, padx=10, pady=(0,10))
        ttk.Label(bottom, text="Log:").pack(anchor="w")
        self.log = Text(bottom, height=8)
        self.log.pack(fill=BOTH, expand=True)

    def _log(self, msg):
        self.log.insert(END, msg + "\n")
        self.log.see(END)

    def refresh_status(self):
        def work():
            self._log("[*] Reading ASR status…")
            code, out, err = ps_json_status()
            self.tree.delete(*self.tree.get_children())
            if code != 0:
                self._log(f"[!] Failed to read status: {err or out}")
                return
            try:
                data = json.loads(out) if out else []
            except Exception as e:
                self._log(f"[!] JSON parse error: {e}\n{out[:400]}")
                return
            if not data:
                self._log("[i] No ASR rules currently configured on this system.")
            for row in data:
                rid = row.get("RuleID", "")
                status = row.get("Status", "")
                name = ASR_RULES.get(rid, "(Unknown rule)")
                self.tree.insert("", END, values=(status, rid, name))
            self._log("[✓] Done.")

        threading.Thread(target=work, daemon=True).start()

    def _selected_rule_ids(self):
        sel = []
        for iid in self.tree.selection():
            vals = self.tree.item(iid, "values")
            if len(vals) >= 2:
                sel.append(vals[1])
        return sel

    def apply_selected(self, action_text):
        action_text = safe_action_label(action_text)
        if action_text not in VALID_ACTIONS:
            messagebox.showerror("Invalid action", f"Unsupported action: {action_text}")
            return
        rids = self._selected_rule_ids()
        if not rids:
            messagebox.showinfo("Nothing selected", "Select one or more rules first.")
            return

        def work():
            self._log(f"[*] Applying {action_text} to {len(rids)} rule(s)…")
            for rid in rids:
                code, out, err = ps_apply(rid, action_text)
                if code == 0:
                    self._log(f"[✓] {action_text:<10} {rid}  {ASR_RULES.get(rid, '')}")
                else:
                    self._log(f"[!] FAILED {rid}: {err or out}")
            self.refresh_status()

        threading.Thread(target=work, daemon=True).start()

    def bulk_apply(self, action_text):
        action_text = safe_action_label(action_text)
        if action_text not in VALID_ACTIONS:
            messagebox.showerror("Invalid action", f"Unsupported action: {action_text}")
            return

        if not messagebox.askyesno("Confirm", f"Apply '{action_text}' to ALL {len(ASR_RULES)} known ASR rules?"):
            return

        def work():
            self._log(f"[*] Applying {action_text} to ALL rules…")
            for rid in ASR_RULES.keys():
                code, out, err = ps_apply(rid, action_text)
                if code == 0:
                    self._log(f"[✓] {action_text:<10} {rid}  {ASR_RULES.get(rid, '')}")
                else:
                    self._log(f"[!] FAILED {rid}: {err or out}")
            self.refresh_status()

        threading.Thread(target=work, daemon=True).start()

    def reset_selected(self):
        rids = self._selected_rule_ids()
        if not rids:
            messagebox.showinfo("Nothing selected", "Select one or more rules first.")
            return
        if not messagebox.askyesno("Confirm", f"Reset {len(rids)} rule(s) to NotConfigured?"):
            return

        def work():
            self._log(f"[*] Resetting {len(rids)} rule(s)…")
            for rid in rids:
                code, out, err = ps_remove(rid)
                if code == 0:
                    self._log(f"[✓] Reset      {rid}  {ASR_RULES.get(rid, '')}")
                else:
                    self._log(f"[!] FAILED {rid}: {err or out}")
            self.refresh_status()

        threading.Thread(target=work, daemon=True).start()

    def export_json(self):
        items = []
        for iid in self.tree.get_children():
            status, rid, name = self.tree.item(iid, "values")
            items.append({"Status": status, "RuleID": rid, "Name": name})

        if not items:
            code, out, err = ps_json_status()
            if code != 0:
                messagebox.showerror("Export failed", err or out)
                return
            raw = json.loads(out) if out else []
            for r in raw:
                rid = r.get("RuleID", "")
                items.append({"Status": r.get("Status", ""), "RuleID": rid, "Name": ASR_RULES.get(rid, "(Unknown rule)")})

        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files","*.json")], initialfile="Windows-ASR-Controller.json")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            json.dump(items, f, indent=2)
        self._log(f"[✓] Exported to {path}")

    def import_json(self):
        path = filedialog.askopenfilename(filetypes=[("JSON files","*.json")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            messagebox.showerror("Import failed", f"JSON parse error: {e}")
            return

        if not isinstance(data, list) or not data:
            messagebox.showinfo("Import", "JSON is empty or invalid.")
            return

        if not messagebox.askyesno("Confirm", f"Apply actions from JSON to {len(data)} entries?"):
            return

        def work():
            self._log(f"[*] Applying imported JSON ({len(data)} entries)…")
            for entry in data:
                rid = entry.get("RuleID")
                status = safe_action_label(entry.get("Status",""))
                if not rid or status not in VALID_ACTIONS:
                    self._log(f"[!] Skipped invalid entry: {entry}")
                    continue
                code, out, err = ps_apply(rid, status)
                if code == 0:
                    self._log(f"[✓] {status:<10} {rid}  {ASR_RULES.get(rid, '')}")
                else:
                    self._log(f"[!] FAILED {rid}: {err or out}")
            self.refresh_status()

        threading.Thread(target=work, daemon=True).start()

    def show_testing_links(self):
        msg = (
            "Testing resources:\n"
            "• https://demo.wd.microsoft.com/Page/ASR2\n"
            "• https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-deployment-test\n"
            "• https://www.splunk.com/en_us/blog/security/deploy-test-monitor-mastering-microsoft-defender-asr-with-atomic-techniques-in-splunk.html\n"
        )
        messagebox.showinfo("Testing links", msg)

def main():
    app = App()
    app.mainloop()

if __name__ == "__main__":
    main()
