import tkinter as tk
from tkinter import ttk

# Initialize GUI
root = tk.Tk()
root.title("Advanced Port Scanner Tool")
root.geometry("800x600")
root.configure(bg="black")
# Create a canvas and scrollbar
canvas = tk.Canvas(root)
scrollbar = ttk.Scrollbar(root, orient="vertical", command=canvas.yview)
scrollable_frame = ttk.Frame(canvas)

# Configure the scrollbar
scrollable_frame.bind(
    "<Configure>",
    lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
)

canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
canvas.configure(yscrollcommand=scrollbar.set)

# Pack the canvas and scrollbar
canvas.pack(side="left", fill="both", expand=True)
scrollbar.pack(side="right", fill="y")

# Add your existing widgets inside the 'frame' (the scrollable area)
heading = tk.Label(scrollable_frame, text="Advanced Port Scanner Tool", fg="green", bg="black", font=("Helvetica", 24, "bold"))
heading.grid(row=0, column=0, columnspan=2, pady=10, sticky="nsew")

label_target = tk.Label(scrollable_frame, text="Target (IP or Domain):", fg="red", bg="black", font=("Helvetica", 12))
label_target.grid(row=1, column=0, padx=5, pady=5, sticky="w")

entry_target = tk.Entry(scrollable_frame, fg="green", bg="black", insertbackground="green", font=("Helvetica", 12))
entry_target.grid(row=1, column=1, padx=5, pady=5, sticky="ew")

label_resolved_ip = tk.Label(scrollable_frame, text="Resolved IP: ", fg="red", bg="black", font=("Helvetica", 12))
label_resolved_ip.grid(row=2, column=0, pady=5, sticky="w")

label_resolved_ip_value = tk.Label(scrollable_frame, text="", fg="green", bg="black", font=("Helvetica", 12))
label_resolved_ip_value.grid(row=2, column=1, pady=5, sticky="w")

label_protocol = tk.Label(scrollable_frame, text="Select Protocol:", fg="red", bg="black", font=("Helvetica", 12))
label_protocol.grid(row=3, column=0, padx=5, pady=5, sticky="w")

selected_protocol = tk.StringVar(value="Both")
protocol_options = ttk.Combobox(scrollable_frame, textvariable=selected_protocol, values=["TCP", "UDP", "Both"], state="readonly", font=("Helvetica", 12))
protocol_options.grid(row=3, column=1, padx=5, pady=5, sticky="ew")

label_ports = tk.Label(scrollable_frame, text="Ports (comma separated):", fg="red", bg="black", font=("Helvetica", 12))
label_ports.grid(row=4, column=0, padx=5, pady=5, sticky="w")

entry_ports = tk.Entry(scrollable_frame, fg="green", bg="black", insertbackground="green", font=("Helvetica", 12))
entry_ports.grid(row=4, column=1, padx=5, pady=5, sticky="ew")

label_start_port = tk.Label(scrollable_frame, text="Start Port:", fg="red", bg="black", font=("Helvetica", 12))
label_start_port.grid(row=5, column=0, padx=5, pady=5, sticky="w")

entry_start_port = tk.Entry(scrollable_frame, fg="green", bg="black", insertbackground="green", font=("Helvetica", 12))
entry_start_port.grid(row=5, column=1, padx=5, pady=5, sticky="ew")

label_end_port = tk.Label(scrollable_frame, text="End Port:", fg="red", bg="black", font=("Helvetica", 12))
label_end_port.grid(row=6, column=0, padx=5, pady=5, sticky="w")

entry_end_port = tk.Entry(scrollable_frame, fg="green", bg="black", insertbackground="green", font=("Helvetica", 12))
entry_end_port.grid(row=6, column=1, padx=5, pady=5, sticky="ew")

scan_all_ports_var = tk.BooleanVar()
scan_all_ports_check = tk.Checkbutton(scrollable_frame, text="Scan All Ports (1-65535)", variable=scan_all_ports_var, fg="red", bg="black", font=("Helvetica", 12), selectcolor="black")
scan_all_ports_check.grid(row=7, column=0, columnspan=2, pady=5, sticky="nsew")

button_scan = tk.Button(scrollable_frame, text="Scan", command=lambda: print("Scan clicked"), fg="black", bg="green", font=("Helvetica", 12, "bold"))
button_scan.grid(row=8, column=0, columnspan=2, pady=10, sticky="nsew")

tree = ttk.Treeview(scrollable_frame, columns=("Port", "Service", "Protocol", "Status", "Banner"), show="headings", style="Custom.Treeview")
tree.heading("Port", text="Port")
tree.heading("Service", text="Service")
tree.heading("Protocol", text="Protocol")
tree.heading("Status", text="Status")
tree.heading("Banner", text="Banner")
tree.tag_configure("open_port", background="green")
tree.tag_configure("closed_port", background="red")
tree.grid(row=9, column=0, columnspan=2, pady=5, sticky="nsew")

scrollbar_tree = ttk.Scrollbar(scrollable_frame, orient="vertical", command=tree.yview)
tree.configure(yscrollcommand=scrollbar_tree.set)
scrollbar_tree.grid(row=9, column=2, sticky="ns")
root.mainloop()
