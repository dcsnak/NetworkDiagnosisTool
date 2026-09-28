import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from network_tool.capture import read_pcap_file, capture_live
from network_tool.diagnostics import analyze_packets, export_report


class NetworkDiagnosisApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title('Network Diagnosis Tool')
        self.root.geometry('1100x700')
        self.root.minsize(900, 600)

        self.packet_data = []

        self._build_ui()

    def _build_ui(self):
        main = ttk.Frame(self.root, padding=12)
        main.pack(fill='both', expand=True)

        topbar = ttk.Frame(main)
        topbar.pack(fill='x', pady=(0, 8))

        ttk.Button(topbar, text='Load PCAP', command=self.load_pcap).pack(side='left', padx=(0, 8))
        ttk.Button(topbar, text='Live Capture', command=self.live_capture).pack(side='left', padx=(0, 8))
        ttk.Button(topbar, text='Analyze', command=self.analyze_packets).pack(side='left', padx=(0, 8))
        ttk.Button(topbar, text='Save Report', command=self.save_report).pack(side='left')

        info = ttk.LabelFrame(main, text='Capture Summary')
        info.pack(fill='x', pady=(0, 8))

        self.summary_var = tk.StringVar(value='No packet data loaded.')
        ttk.Label(info, textvariable=self.summary_var, wraplength=1000, justify='left').pack(anchor='w', padx=10, pady=8)

        split = ttk.Panedwindow(main, orient='horizontal')
        split.pack(fill='both', expand=True)

        left = ttk.Frame(split)
        right = ttk.Frame(split)
        split.add(left, weight=3)
        split.add(right, weight=2)

        table_frame = ttk.LabelFrame(left, text='Packet List')
        table_frame.pack(fill='both', expand=True, padx=(0, 8))

        columns = ('index', 'protocol', 'src', 'dst', 'length', 'flags')
        self.tree = ttk.Treeview(table_frame, columns=columns, show='headings')
        for column in columns:
            self.tree.heading(column, text=column.upper())
            self.tree.column(column, width=120, anchor='center')
        self.tree.pack(fill='both', expand=True, padx=8, pady=8)

        detail_frame = ttk.LabelFrame(right, text='Diagnosis Results')
        detail_frame.pack(fill='both', expand=True)

        self.result_text = tk.Text(detail_frame, wrap='word', state='disabled', font=('Consolas', 10))
        self.result_text.pack(fill='both', expand=True, padx=8, pady=8)

    def _load_packet_table(self):
        for row in self.tree.get_children():
            self.tree.delete(row)

        for item in self.packet_data[:200]:
            self.tree.insert('', 'end', values=(
                item.get('index', 0),
                item.get('protocol', 'UNKNOWN'),
                item.get('src', 'unknown'),
                item.get('dst', 'unknown'),
                item.get('length', 0),
                item.get('flags', '---'),
            ))

    def load_pcap(self):
        path = filedialog.askopenfilename(title='Select a PCAP file', filetypes=[('PCAP files', '*.pcap;*.pcapng;*.cap')])
        if not path:
            return
        try:
            self.packet_data = read_pcap_file(path)
            self.summary_var.set(f'Loaded {len(self.packet_data)} packets from {os.path.basename(path)}')
            self._load_packet_table()
            messagebox.showinfo('Success', f'Loaded {len(self.packet_data)} packets from the file.')
        except Exception as exc:  # pragma: no cover - GUI error handling
            messagebox.showerror('PCAP Load Failed', str(exc))

    def live_capture(self):
        try:
            self.packet_data = capture_live(timeout=8, packet_count=250)
            self.summary_var.set(f'Captured {len(self.packet_data)} packets in live mode.')
            self._load_packet_table()
            self.analyze_packets()
            messagebox.showinfo('Live Capture', f'Captured {len(self.packet_data)} packets.')
        except Exception as exc:  # pragma: no cover - GUI error handling
            messagebox.showerror('Live Capture Failed', f'{exc}\nRun the app with administrator rights and ensure Npcap is installed.')

    def analyze_packets(self):
        if not self.packet_data:
            self.result_text.config(state='normal')
            self.result_text.delete(1.0, 'end')
            self.result_text.insert('end', 'No packet data available. Load a PCAP or start a capture.')
            self.result_text.config(state='disabled')
            return

        result = analyze_packets(self.packet_data)
        diagnosis = result[0] if result else {'issues': []}
        summary = diagnosis.get('summary', {})
        issues = diagnosis.get('issues', [])

        output = [
            'Network Diagnosis Summary',
            '========================',
            f'Total packets: {summary.get("total_packets", 0)}',
            f'Protocols: {summary.get("protocols", {})}',
            f'Top sources: {summary.get("top_sources", {})}',
            f'Top destinations: {summary.get("top_destinations", {})}',
            '',
            'Findings:',
        ]

        if issues:
            for idx, issue in enumerate(issues, start=1):
                output.append(f'{idx}. [{issue.get("severity", "low").upper()}] {issue.get("title", "Issue")}')
                output.append(f'   - Detail: {issue.get("detail", "N/A")}')
                output.append(f'   - Recommendation: {issue.get("recommendation", "N/A")}')
                output.append('')
        else:
            output.append('No issues detected.')

        self.result_text.config(state='normal')
        self.result_text.delete(1.0, 'end')
        self.result_text.insert('end', '\n'.join(output))
        self.result_text.config(state='disabled')

    def save_report(self):
        if not self.packet_data:
            messagebox.showwarning('No Data', 'Load a PCAP or capture data before saving a report.')
            return

        report = export_report(self.packet_data)
        file_path = filedialog.asksaveasfilename(
            defaultextension='.txt',
            filetypes=[('Text files', '*.txt')],
            title='Save diagnosis report',
        )
        if not file_path:
            return

        with open(file_path, 'w', encoding='utf-8') as handle:
            handle.write(report)

        messagebox.showinfo('Saved', f'Report saved to {file_path}')


def run_app():
    root = tk.Tk()
    app = NetworkDiagnosisApp(root)
    root.mainloop()
