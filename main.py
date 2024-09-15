import tkinter as tk
import cv2
import numpy as np
from PIL import Image, ImageTk
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import pyperclip
# ===window=====
root = tk.Tk()
root.title('Secure Message')
root.resizable(True, True)
root.iconbitmap('C:\\Users\\DELL\\Desktop\\photo.py\\myIcon.ico')

# ====video======
video_path = "C:\\Users\\DELL\\Desktop\\photo.py\\vid2.mp4"
cap = cv2.VideoCapture(video_path)

# ====play video====
def play_video():
    ret, frame = cap.read()
    if ret:
        frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        img = Image.fromarray(frame)
        img = ImageTk.PhotoImage(img)

        label.config(image=img)
        label.image = img

        if cap.get(cv2.CAP_PROP_POS_FRAMES) == cap.get(cv2.CAP_PROP_FRAME_COUNT):
            cap.set(cv2.CAP_PROP_POS_FRAMES, 0)

    label.after(30, play_video)

# ====display-vid=====
label = tk.Label(root)
label.pack(fill="both", expand=True)

#===interface-base====
play_video()

framFcit = tk.Frame(root, width=400, height=600, bg='#ffffff', highlightbackground='#0a213b', highlightcolor='#500007',
                    highlightthickness=2)
framFcit.place(x=60, y=60)

# ===photo====
photo2 = Image.open("C:\\Users\\DELL\\Downloads\\CS2.png")
photo2 = photo2.resize((200, 200))
photo2 = ImageTk.PhotoImage(photo2)

image2 = tk.Label(framFcit, image=photo2, bg='#ffffff')
image2.place(x=110, y=0)

# =====title=========
inst = tk.Label(framFcit, text='Secure Message', font=('Verdana', 20, 'bold'), fg='#0a213b', bg='#ffffff')
inst.place(x=80, y=200)

# =======message-input========
textW = tk.Label(framFcit, text='Message:', font=('Arial', 13), fg='#0a213b', bg='#ffffff')
textW.place(x=60, y=260)

enterW = tk.Entry(framFcit, width=20, bg='#b3aeb4', fg='#242222', font=('Arial', 20), justify=tk.CENTER,
                  highlightbackground='#857f86', highlightcolor='#d6d5d6', highlightthickness=1)
enterW.place(x=60, y=290)

def paste_text(event):
    enterW.delete(0, tk.END)
    enterW.insert(0, root.clipboard_get())

enterW.bind("<Button-3>", paste_text)

# ======pass-input=========
textR = tk.Label(framFcit, text='Password:', font=('Arial', 13), fg='#0a213b', bg='#ffffff')
textR.place(x=60, y=335)

enterR = tk.Entry(framFcit, width=20, bg='#b3aeb4', fg='#242222', font=('Arial', 20), justify=tk.CENTER,
                  show='*', highlightbackground='#857f86', highlightcolor='#d6d5d6', highlightthickness=1)
enterR.place(x=60, y=365)

# ======output========
textS = tk.Label(framFcit, text='Result:', font=('Arial', 13), fg='#0a213b', bg='#ffffff')
textS.place(x=60, y=440)

# =======display-output=========
outputLabel = tk.Label(framFcit, text='', bg='#b3aeb4', fg='#242222', font=('Arial', 10), justify=tk.CENTER)
outputLabel.place(x=60, y=465, width=280, height=40)

# ============encryption===========

KEY = b'This is a key123'

def encrypt(plaintext, key):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
    return base64.b64encode(iv + ciphertext).decode('utf-8')

def decrypt(ciphertext, key):
    try:
        ciphertext = base64.b64decode(ciphertext)
        iv = ciphertext[:AES.block_size]
        ciphertext = ciphertext[AES.block_size:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext.decode('utf-8')
    except Exception as e:
        raise ValueError("Decrytion failed") from e

def process_message():
    message = enterW.get()
    password = enterR.get().strip()

    if password == "a26Wen0":
        try:

            decrypted_text = decrypt(message, KEY)
            outputLabel.config(text=decrypted_text)
        except ValueError:

            encrypted_text = encrypt(message, KEY)
            outputLabel.config(text=encrypted_text)
    else:
        outputLabel.config(text="Incorrect password")
# ===========================
def copy_message():
    message = outputLabel['text']
    pyperclip.copy(message)

# ======process-button=======
but = tk.Button(framFcit, width=20, bg="#500007", fg='#ffffff', text='Processing Message',
                font=('Helvetica', 10, 'bold'), command=process_message)
but.place(x=120, y=410)

# ======copy-button=======
but_copy = tk.Button(framFcit, width=20, bg="#500007", fg='#ffffff', text='Copy Message', font=('Helvetica', 10, 'bold'),
                     command=copy_message)
but_copy.place(x=120, y=510)

# ==========Run-application=========
root.mainloop()