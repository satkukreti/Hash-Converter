import requests
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog as fd

headers = {
    "accept": "application/json",
    "x-apikey": "" #Enter your API key from your VirusTotal Account
}

'''Gets the file path: uses a graphical interface'''
def open_text_file():
    filetypes = (('text files', '*.txt'), ('All files', '*.*'))
    try:
        f = fd.askopenfilename(filetypes=filetypes, initialdir="D:/Downloads")
        convertHash(f)
    except FileNotFoundError as e:
        progress = "File not found or selected"
        t.delete("1.0", "end")
        t.insert(tk.END, progress)

'''Converts the hashes'''
def convertHash(filepath):
    nfile = open("sha1conversion.txt", "w")
    progress = "Getting file " + filepath
    t.delete("1.0", "end")
    t.insert(tk.END, progress)
    with open(filepath, 'r') as f:
        for line in f:
            h = line.strip()
            url = "https://www.virustotal.com/api/v3/files/" + h

            try:
                response = requests.get(url, headers=headers)
                d = response.json()
                ht = clicked.get().lower()
                temp = d["data"]["attributes"][ht]
                nfile.write(f"{temp}\n")

            except Exception as e:
                nfile.write("Not Found\n")
    progress = progress + " ...DONE"
    t.delete("1.0", "end")
    t.insert(tk.END, progress)

'''Creating the GUI'''
app = tk.Tk()
app.title("Hash Converter")
app.geometry("300x150")

l = tk.Label(app, font=("Calibri", 12), text="Select a file and hash type", height=10)
l.place(relx=0.50, rely=0.15, anchor="center")

progress = "Please select a text file"

t = tk.Text(app, height=2, width=35, wrap="char")
t.place(relx=0.50, rely=0.40, anchor="center")
t.insert(tk.END, progress)

clicked = tk.StringVar(app)
clicked.set("SHA256")
drop = tk.OptionMenu(app, clicked, "SHA256", "MD5")
drop.place(relx=0.70, rely=0.75, anchor="center")

open_button = ttk.Button(app, text="Choose File", command=open_text_file)
open_button.place(relx=0.30, rely=0.75, anchor="center")
app.mainloop()
