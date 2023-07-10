#Author: Satvik Kukreti

import requests
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog as fd
from PIL import Image, ImageTk

headers = {
    "accept": "application/json",
    "x-apikey": "" #Enter your API key from your VirusTotal Account
}


'''Gets the file path using a graphical interface'''
def open_text_file(progress):
    t.delete("1.0", "end")
    progress = "Getting file: "
    t.insert(tk.END, progress);
    filetypes = (('text files', '*.txt'), ('All files', '*.*'))
    try:
        f = fd.askopenfilename(filetypes=filetypes, initialdir="D:/Downloads")
        convertHash(f)
    except FileNotFoundError as e:
        progress = "File not found or selected"
        t.insert(tk.END, progress)

'''Converts the hashes'''
def convertHash(filepath):
    nfile = open("hashconverstion.txt", "w")
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
    progress = filepath + " - " + clicked.get()
    t.insert(tk.END, progress)

'''Creating the GUI'''
app = tk.Tk()
app.title("Hash Converter")
app.geometry("300x150")
app.resizable(False, False)

p = Image.open("HashConverter.png")
render = ImageTk.PhotoImage(p)
app.iconphoto(False, render)

l = tk.Label(app, font=("Calibri", 12), text="Select a file and hash type", height=10)
l.place(relx=0.50, rely=0.15, anchor="center")

t = tk.Text(app, height=2, width=35, wrap="char")
t.place(relx=0.50, rely=0.40, anchor="center")
progress = "Please select a text file"
t.insert(tk.END, progress)

clicked = tk.StringVar(app)
clicked.set("SHA256")
drop = tk.OptionMenu(app, clicked, "SHA256", "MD5")
drop.place(relx=0.70, rely=0.75, anchor="center")

open_button = ttk.Button(app, text="Choose File", command=lambda: open_text_file(progress))
open_button.place(relx=0.30, rely=0.75, anchor="center")
app.mainloop()
