all_logs = []  # global list to hold all logs
import matplotlib
matplotlib.use("TkAgg")  # ensure Tkinter backend
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import requests
import csv
import time
import os
import matplotlib.pyplot as plt


API_BASE = "http://127.0.0.1:5000"   # Flask runs locally on port 5000

# Track shown alerts to avoid repeat popups
shown_alerts = set()
current_filter = "All"  # Default severity filter
search_keyword = ""     # Default search keyword

# GUI setup
root = tk.Tk()
root.title("CyberBridge Threat Detection")
root.geometry("1000x700")
root.configure(bg="#1e3d59")  # dark teal background

# Title
title = tk.Label(root, text="Threat Detection Dashboard",
                 font=("Arial", 18, "bold"), fg="white", bg="#1e3d59")
title.pack(pady=10)

# Threat Summary Frame
summary_frame = tk.Frame(root, bg="#1e3d59")
summary_frame.pack(pady=10)

low_label = tk.Label(summary_frame, text="Low: 0", font=("Arial", 12, "bold"), fg="lightgreen", bg="#1e3d59")
low_label.grid(row=0, column=0, padx=20)

medium_label = tk.Label(summary_frame, text="Medium: 0", font=("Arial", 12, "bold"), fg="yellow", bg="#1e3d59")
medium_label.grid(row=0, column=1, padx=20)

high_label = tk.Label(summary_frame, text="High: 0", font=("Arial", 12, "bold"), fg="red", bg="#1e3d59")
high_label.grid(row=0, column=2, padx=20)

# Filter Frame
filter_frame = tk.Frame(root, bg="#1e3d59")
filter_frame.pack(pady=5)

filter_label = tk.Label(filter_frame, text="Filter by Severity:", font=("Arial", 12, "bold"), fg="white", bg="#1e3d59")
filter_label.grid(row=0, column=0, padx=10)

def set_filter(severity):
    global current_filter
    current_filter = severity
    load_events()

tk.Button(filter_frame, text="All", width=10, command=lambda: set_filter("All")).grid(row=0, column=1, padx=5)
tk.Button(filter_frame, text="Low", width=10, command=lambda: set_filter("Low")).grid(row=0, column=2, padx=5)
tk.Button(filter_frame, text="Medium", width=10, command=lambda: set_filter("Medium")).grid(row=0, column=3, padx=5)
tk.Button(filter_frame, text="High", width=10, command=lambda: set_filter("High")).grid(row=0, column=4, padx=5)

# Search Frame
search_frame = tk.Frame(root, bg="#1e3d59")
search_frame.pack(pady=5)

search_label = tk.Label(search_frame, text="Search Keyword:", font=("Arial", 12, "bold"), fg="white", bg="#1e3d59")
search_label.grid(row=0, column=0, padx=10)

search_entry = tk.Entry(search_frame, width=30)
search_entry.grid(row=0, column=1, padx=10)

search_keyword = ""  # global variable to hold current search term

def apply_search():
    global search_keyword
    search_keyword = search_entry.get().strip().lower()
    load_events()   # reload table with filter applied

def clear_search():
    global search_keyword
    search_entry.delete(0, tk.END)
    search_keyword = ""
    load_events()   # reload full table

def view_analytics():
    try:
        global all_logs

        if not all_logs:
            messagebox.showwarning("Analytics", "No logs loaded yet. Please refresh first.")
            return

        # Count severity distribution
        severity_counts = {"Low": 0, "Medium": 0, "High": 0}
        timestamps = []
        severities = []

        for event in all_logs:
            sev = event.get("severity", "").capitalize()
            if sev in severity_counts:
                severity_counts[sev] += 1
            timestamps.append(event.get("timestamp", ""))
            severities.append(sev)

        # Update labels
        low_label.config(text=f"Low: {severity_counts['Low']}")
        medium_label.config(text=f"Medium: {severity_counts['Medium']}")
        high_label.config(text=f"High: {severity_counts['High']}")

        # Charts
        import matplotlib
        matplotlib.use("TkAgg")   # ensure Tkinter backend
        import matplotlib.pyplot as plt

        plt.figure(figsize=(10,4))

        # Bar chart
        plt.subplot(1,2,1)
        plt.bar(severity_counts.keys(), severity_counts.values(), color=["green","yellow","red"])
        plt.title("Severity Distribution")

        # Line chart
        plt.subplot(1,2,2)
        plt.plot(range(len(timestamps)),
                 [1 if s=="Low" else 2 if s=="Medium" else 3 for s in severities],
                 marker="o", linestyle="-")
        plt.title("Threats Over Time")
        plt.yticks([1,2,3], ["Low","Medium","High"])

        plt.tight_layout()
        plt.show()

    except Exception as e:
        messagebox.showerror("Analytics Error", f"Error generating analytics: {e}")

tk.Button(search_frame, text="Search", width=10, command=apply_search).grid(row=0, column=2, padx=5)
tk.Button(search_frame, text="Clear Search", width=12, command=clear_search).grid(row=0, column=3, padx=5)

# Table
columns = ("timestamp", "threat_type", "severity", "description")
tree = ttk.Treeview(root, columns=columns, show="headings", height=15)

for col in columns:
    tree.heading(col, text=col.capitalize())
    if col == "description":
        tree.column(col, width=500, anchor="w")   # wider for full text
    elif col == "timestamp":
        tree.column(col, width=180, anchor="center")  # enough for date/time
    elif col == "threat_type":
        tree.column(col, width=200, anchor="center")
    elif col == "severity":
        tree.column(col, width=100, anchor="center")
    else:
        tree.column(col, width=200)


tree.pack(pady=20)

# Define tag styles for severity
tree.tag_configure("Low", background="#d4edda")     # light green
tree.tag_configure("Medium", background="#fff3cd")  # light yellow
tree.tag_configure("High", background="#f8d7da")    # light red


# Buttons
button_frame = tk.Frame(root, bg="#1e3d59")
button_frame.pack(pady=10)

# --- Dropdown to toggle view mode ---
from tkinter import ttk

view_mode = tk.StringVar(value="Recent")  # default mode
mode_selector = ttk.Combobox(summary_frame, textvariable=view_mode, values=["Recent", "Full"], width=10)
mode_selector.grid(row=0, column=3, padx=20)

# --- Load events function ---
def load_events():
    try:
        global all_logs  # store logs for filtering
        global search_keyword  # use keyword set by apply_search()

        # Decide which endpoint to call based on dropdown
        if view_mode.get() == "Recent":
            response = requests.get(f"{API_BASE}/dashboard")
            if response.status_code == 200:
                data = response.json()
                logs = data["recent_activity"]
            else:
                logs = []
        else:  # Full history
            response = requests.get(f"{API_BASE}/all_logs")
            if response.status_code == 200:
                data = response.json()
                logs = data["logs"]
            else:
                logs = []

        # Save logs globally for filter buttons and search
        all_logs = logs

        # Clear table before inserting new data
        tree.delete(*tree.get_children())

        # Count severity distribution
        severity_counts = {"Low": 0, "Medium": 0, "High": 0}

        for event in logs:
            sev = event.get("severity", "").capitalize()  # normalize case
            combined = f"{event.get('timestamp','')} {event.get('threat_type','')} {sev} {event.get('description','')}".lower()

            #  Only insert if keyword matches (or no keyword set)
            if search_keyword == "" or search_keyword in combined:
                if sev in severity_counts:
                    severity_counts[sev] += 1

                tree.insert("", "end", values=(
                    event.get("timestamp", ""),
                    event.get("threat_type", ""),
                    sev,
                    event.get("description", "")
                ), tags=(sev,))

        # Update labels dynamically
        low_label.config(text=f"Low: {severity_counts['Low']}")
        medium_label.config(text=f"Medium: {severity_counts['Medium']}")
        high_label.config(text=f"High: {severity_counts['High']}")

    except Exception as e:
        messagebox.showerror("Load Error", f"Error loading events: {e}")

def export_to_csv():
    try:
        response = requests.get(f"{API_BASE}/dashboard")
        if response.status_code == 200:
            data = response.json()
            file_path = filedialog.asksaveasfilename(defaultextension=".csv",
                                                     filetypes=[("CSV files", "*.csv")])
            if file_path:
                with open(file_path, mode="w", newline="", encoding="utf-8") as file:
                    writer = csv.writer(file)
                    writer.writerow(["Timestamp", "Threat Type", "Severity", "Description"])
                    for event in data["recent_activity"]:
                        description = event["description"].lower()
                        threat_type = event["threat_type"].lower()
                        if (current_filter == "All" or event["severity"] == current_filter) and \
                                (
                                        search_keyword == "" or search_keyword in description or search_keyword in threat_type):
                            writer.writerow([event["timestamp"], event["threat_type"],
                                             event["severity"], event["description"]])
                messagebox.showinfo("Export Successful", f"Threat logs exported to {file_path}")
    except Exception as e:
        messagebox.showerror("Export Failed", f"Error: {e}")

def export_all_logs():
    try:
        response = requests.get(f"{API_BASE}/all_logs")
        if response.status_code == 200:
            data = response.json()
            file_path = filedialog.asksaveasfilename(defaultextension=".csv",
                                                     filetypes=[("CSV files", "*.csv")])
            if file_path:
                with open(file_path, mode="w", newline="", encoding="utf-8") as file:
                    writer = csv.writer(file)
                    writer.writerow(["Timestamp", "Threat Type", "Severity", "Description"])
                    for event in data["logs"]:  # full history returned
                        writer.writerow([event["timestamp"], event["threat_type"],
                                         event["severity"], event["description"]])
                messagebox.showinfo("Export Successful", f"All logs exported to {file_path}")
    except Exception as e:
        messagebox.showerror("Export Failed", f"Error: {e}")


def auto_export():
    try:
        response = requests.get(f"{API_BASE}/dashboard")
        if response.status_code == 200:
            data = response.json()
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            file_path = os.path.join(os.getcwd(), f"threat_logs_{timestamp}.csv")
            with open(file_path, mode="w", newline="", encoding="utf-8") as file:
                writer = csv.writer(file)
                writer.writerow(["Timestamp", "Threat Type", "Severity", "Description"])
                for event in data["recent_activity"]:
                    description = event["description"].lower()
                    threat_type = event["threat_type"].lower()
                    if (current_filter == "All" or event["severity"] == current_filter) and \
                            (search_keyword == "" or search_keyword in description or search_keyword in threat_type):
                        writer.writerow([event["timestamp"], event["threat_type"],
                                         event["severity"], event["description"]])
            print(f"Auto-exported logs to {file_path}")
    except Exception as e:
        print("Auto-export failed:", e)
    finally:
        # Schedule next auto-export in 1 hour (3600000 ms)
        root.after(3600000, auto_export)


refresh_btn = tk.Button(button_frame, text="Refresh", bg="#4CAF50", fg="white", width=12,
                        command=load_events)
refresh_btn.grid(row=0, column=0, padx=10)

clear_btn = tk.Button(button_frame, text="Clear", bg="#f44336", fg="white", width=12,
                      command=lambda: tree.delete(*tree.get_children()))
clear_btn.grid(row=0, column=1, padx=10)

export_btn = tk.Button(button_frame, text="Export", bg="#2196F3", fg="white", width=12,
                       command=export_to_csv)
export_btn.grid(row=0, column=2, padx=10)

# New button for full history export
export_all_btn = tk.Button(button_frame, text="Export All Logs", bg="#FF9800", fg="white", width=15,
                           command=export_all_logs)
export_all_btn.grid(row=0, column=3, padx=10)

analytics_btn = tk.Button(button_frame, text="View Analytics", bg="#9C27B0", fg="white", width=15,
                          command=view_analytics)
analytics_btn.grid(row=0, column=4, padx=10)

# Auto-refresh every 5 seconds
def auto_refresh():
    load_events()
    root.after(5000, auto_refresh)  # refresh every 5000 ms (5 seconds)


# Initial load + start auto-refresh + auto-export
load_events()
auto_refresh()
auto_export()

root.mainloop()

def export_all_logs():
    try:
        # Directly query the Flask API endpoint for all logs
        response = requests.get(f"{API_BASE}/all_logs")
        if response.status_code == 200:
            data = response.json()
            file_path = filedialog.asksaveasfilename(defaultextension=".csv",
                                                     filetypes=[("CSV files", "*.csv")])
            if file_path:
                with open(file_path, mode="w", newline="", encoding="utf-8") as file:
                    writer = csv.writer(file)
                    writer.writerow(["Timestamp", "Threat Type", "Severity", "Description"])
                    for event in data["logs"]:  # full history returned
                        writer.writerow([event["timestamp"], event["threat_type"],
                                         event["severity"], event["description"]])
                messagebox.showinfo("Export Successful", f"All logs exported to {file_path}")
    except Exception as e:
        messagebox.showerror("Export Failed", f"Error: {e}")
