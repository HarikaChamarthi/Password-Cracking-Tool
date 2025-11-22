import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from PIL import Image, ImageTk
import hashlib, json, os, threading

# ---------- Config ----------
BG_PATH = os.path.join("assets", "bg.png")           # background image
RAINBOW_PATH = os.path.join("data", "rainbow_table.json")  # rainbow table file


# ---------- UI Helpers ----------
def load_background(win, width, height):
    """Apply background image to any window."""
    if os.path.exists(BG_PATH):
        img = Image.open(BG_PATH).resize((width, height))
        bg = ImageTk.PhotoImage(img)
        label = tk.Label(win, image=bg)
        label.image = bg  # keep reference
        label.place(x=0, y=0, relwidth=1, relheight=1)
    else:
        print(f"❌ Background not found at {BG_PATH}. Using plain background.")
        win.configure(bg="#0f1115")  # deep charcoal


def select_file(entry):
    path = filedialog.askopenfilename(
        title="Select File",
        filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
    )
    if path:
        entry.delete(0, tk.END)
        entry.insert(0, path)


# ---------- Wordlist Attack ----------
def wordlist_attack_window():
    win = tk.Toplevel(root)
    win.title("Password Cracking Toolkit – Wordlist Attack")
    win.geometry("1000x650")
    load_background(win, 1000, 650)

    card = tk.Frame(win, bg="#0f1115", padx=20, pady=20, highlightthickness=1, highlightbackground="#1f2937")
    card.place(relx=0.5, rely=0.5, anchor="center")

    tk.Label(card, text="Hash File (.txt, one hash per line)", fg="white", bg="#0f1115",
             font=("Segoe UI", 12, "bold")).pack(pady=(0, 6), anchor="w")
    hash_entry = tk.Entry(card, width=80)
    hash_entry.pack(pady=(0, 6))
    tk.Button(card, text="Browse", command=lambda: select_file(hash_entry),
              bg="#2563eb", fg="white", font=("Segoe UI", 10, "bold")).pack(pady=(0, 12), anchor="w")

    tk.Label(card, text="Wordlist File (.txt, one password per line)", fg="white", bg="#0f1115",
             font=("Segoe UI", 12, "bold")).pack(pady=(0, 6), anchor="w")
    wordlist_entry = tk.Entry(card, width=80)
    wordlist_entry.pack(pady=(0, 6))
    tk.Button(card, text="Browse", command=lambda: select_file(wordlist_entry),
              bg="#2563eb", fg="white", font=("Segoe UI", 10, "bold")).pack(pady=(0, 12), anchor="w")

    out = scrolledtext.ScrolledText(card, width=90, height=18, bg="#0b0f14", fg="#00ff9c", font=("Consolas", 10))
    out.pack(pady=10)

    def run_attack():
        hash_file = hash_entry.get().strip()
        word_file = wordlist_entry.get().strip()
        if not (os.path.exists(hash_file) and os.path.exists(word_file)):
            messagebox.showerror("Input Error", "Please choose valid files for both hash & wordlist.")
            return

        def crack():
            out.insert(tk.END, "🔎 Starting Wordlist Attack...\n\n")
            try:
                with open(hash_file, "r", encoding="latin-1") as hf:
                    hashes = [h.strip() for h in hf if h.strip()]
                with open(word_file, "r", encoding="latin-1") as wf:
                    words = [w.strip() for w in wf if w.strip()]

                for h in hashes:
                    found = False
                    for w in words:
                        if hashlib.md5(w.encode()).hexdigest() == h:
                            out.insert(tk.END, f"✅ Password found for {h}: {w}\n\n")
                            found = True
                            break
                    if not found:
                        out.insert(tk.END, f"❌ Password not found for {h}\n\n")

                out.insert(tk.END, "✔ Wordlist Attack Completed.\n")
            except Exception as e:
                out.insert(tk.END, f"⚠ Error: {e}\n")

        threading.Thread(target=crack, daemon=True).start()

    tk.Button(card, text="Start Wordlist Attack", command=run_attack,
              bg="#2563eb", fg="white", font=("Segoe UI", 12, "bold"), width=22).pack(pady=6)


# ---------- Rainbow Table Attack ----------
class RainbowPasswordCracker:
    def __init__(self, table_path=RAINBOW_PATH):
        self.table_path = table_path
        self.table = self._load()

    def _load(self):
        if os.path.exists(self.table_path):
            with open(self.table_path, "r", encoding="utf-8") as f:
                return json.load(f)
        return {}

    def lookup(self, h):
        return self.table.get(h)


def rainbow_attack_window():
    win = tk.Toplevel(root)
    win.title("Password Cracking Toolkit – Rainbow Table Attack")
    win.geometry("900x520")
    load_background(win, 900, 520)

    card = tk.Frame(win, bg="#0f1115", padx=20, pady=20, highlightthickness=1, highlightbackground="#1f2937")
    card.place(relx=0.5, rely=0.5, anchor="center")

    tk.Label(card, text="Enter Hash (MD5 / SHA-256 / SHA-512)", fg="white", bg="#0f1115",
             font=("Segoe UI", 12, "bold")).pack(pady=(0, 8), anchor="w")
    hash_entry = tk.Entry(card, width=70)
    hash_entry.pack(pady=(0, 12))

    out = scrolledtext.ScrolledText(card, width=80, height=12, bg="#0b0f14", fg="#7dd3fc", font=("Consolas", 10))
    out.pack(pady=10)

    cracker = RainbowPasswordCracker()

    def run_lookup():
        h = hash_entry.get().strip()
        if not h:
            messagebox.showwarning("Input Error", "Please paste a hash value.")
            return
        pw = cracker.lookup(h)
        if pw:
            out.insert(tk.END, f"✅ Cracked Password: {pw}\n\n")
        else:
            out.insert(tk.END, "❌ Not found in rainbow table.\n\n")

    tk.Button(card, text="Start Rainbow Attack", command=run_lookup,
              bg="#2563eb", fg="white", font=("Segoe UI", 12, "bold"), width=22).pack(pady=6)


# ---------- Main Window ----------
root = tk.Tk()
root.title("Password Cracking Toolkit")
root.geometry("1000x600")
load_background(root, 1000, 600)

title = tk.Label(root, text="🔐 Password Cracking Toolkit", font=("Segoe UI", 20, "bold"),
                 bg="#0f1115", fg="white")
title.pack(pady=30)

btn1 = tk.Button(root, text="Wordlist Attack", command=wordlist_attack_window,
                 font=("Segoe UI", 14, "bold"), bg="#2563eb", fg="white", width=22)
btn1.pack(pady=12)

btn2 = tk.Button(root, text="Rainbow Table Attack", command=rainbow_attack_window,
                 font=("Segoe UI", 14, "bold"), bg="#2563eb", fg="white", width=22)
btn2.pack(pady=12)

root.mainloop()
