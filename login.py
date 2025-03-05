import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageTk, ImageSequence
import json
import os
from Joystra_app import Joystra_App

# Cyberpunk Theme Colors
BG_COLOR = "#0A192F"  # Dark Blue
FG_COLOR = "#00E0FF"  # Neon Cyan
BTN_COLOR = "#007BFF"  # Neon Blue
INPUT_BG = "#112240"
INPUT_FG = "#00E0FF"
HOVER_COLOR = "#0056b3"
BORDER_COLOR = "#64ffda"  # Bright Greenish Cyan for contrast

GIF_PATH = "login.gif"  # Replace with your actual GIF file path
CREDENTIALS_FILE = "credentials.json"

def on_enter(event):
    event.widget.config(bg=HOVER_COLOR)

def on_leave(event):
    event.widget.config(bg=BTN_COLOR)

class LoginApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Cyberpunk Login")
        self.root.geometry("500x600")
        self.root.configure(bg=BG_COLOR)

        # Load credentials from file
        self.credentials = self.load_credentials()

        # Load and animate GIF
        self.load_gif()

        # Adjusted container position near bottom
        self.container = tk.Frame(root, bg=BG_COLOR, padx=20, pady=20)
        self.container.place(relx=0.5, rely=0.7, anchor="center")  # Adjusted rely for bottom position

        self.current_frame = None
        self.show_signin()

    def load_credentials(self):
        """Load credentials from a file."""
        if os.path.exists(CREDENTIALS_FILE):
            with open(CREDENTIALS_FILE, 'r') as file:
                return json.load(file)
        return {}

    def save_credentials(self):
        """Save credentials to a file."""
        with open(CREDENTIALS_FILE, 'w') as file:
            json.dump(self.credentials, file)

    def load_gif(self):
        """Load and animate GIF background, resizing it to fit the screen."""
        self.gif = Image.open(GIF_PATH)
        self.frames = []

        # Resize each frame to match the screen size
        for frame in ImageSequence.Iterator(self.gif):
            resized_frame = frame.resize((self.root.winfo_screenwidth(), self.root.winfo_screenheight()),
                                         Image.Resampling.LANCZOS)
            self.frames.append(ImageTk.PhotoImage(resized_frame))

        self.frame_idx = 0

        self.bg_label = tk.Label(self.root)
        self.bg_label.place(x=0, y=0, relwidth=1, relheight=1)

        self.animate_gif()

    def animate_gif(self):
        """Cycle through GIF frames for animation."""
        self.bg_label.config(image=self.frames[self.frame_idx])
        self.frame_idx = (self.frame_idx + 1) % len(self.frames)
        self.root.after(100, self.animate_gif)  # Adjust timing if needed

    def toggle_password(self, entry, btn):
        if entry.cget("show") == "*":
            entry.config(show="")
            btn.config(text="👁")
        else:
            entry.config(show="*")
            btn.config(text="👁‍🗨")

    def create_entry(self, parent, label_text, is_password=False):
        frame = tk.Frame(parent, bg=BG_COLOR)
        frame.pack(pady=10, padx=20, fill="x")

        label = tk.Label(frame, text=label_text, fg=FG_COLOR, bg=BG_COLOR, font=("Arial", 12, "bold"))
        label.pack(anchor="w")

        entry_frame = tk.Frame(frame, bg=BORDER_COLOR, bd=2)
        entry_frame.pack(fill="x", expand=True, pady=5)

        entry = tk.Entry(entry_frame, bg=INPUT_BG, fg=INPUT_FG, font=("Arial", 12), relief="flat",
                         insertbackground=FG_COLOR, highlightthickness=0)
        entry.pack(side="left", fill="x", expand=True, padx=5, pady=5)

        if is_password:
            entry.config(show="*")
            btn = tk.Button(entry_frame, text="👁‍🗨", command=lambda: self.toggle_password(entry, btn),
                            bg=BG_COLOR, fg=FG_COLOR, relief="flat", font=("Arial", 10))
            btn.pack(side="right", padx=5)
        else:
            btn = None
        return entry

    def show_signin(self):
        if self.current_frame:
            self.current_frame.destroy()

        self.current_frame = tk.Frame(self.container, bg=BG_COLOR, padx=20, pady=20)
        self.current_frame.pack()

        tk.Label(self.current_frame, text="Sign In", fg=FG_COLOR, bg=BG_COLOR, font=("Arial", 18, "bold")).pack(pady=10)

        self.signin_user_entry = self.create_entry(self.current_frame, "Username")
        self.signin_pass_entry = self.create_entry(self.current_frame, "Password", is_password=True)

        btn = tk.Button(self.current_frame, text="Sign In", bg=BTN_COLOR, fg="white",
                        font=("Arial", 12, "bold"), relief="flat", command=self.login)
        btn.pack(pady=20, ipadx=10, ipady=5)
        btn.bind("<Enter>", on_enter)
        btn.bind("<Leave>", on_leave)

        switch_label = tk.Label(self.current_frame, text="Don't have an account? Click here", fg=BTN_COLOR,
                                bg=BG_COLOR, font=("Arial", 10, "underline"), cursor="hand2")
        switch_label.pack()
        switch_label.bind("<Button-1>", lambda e: self.show_signup())

    def show_signup(self):
        if self.current_frame:
            self.current_frame.destroy()

        self.current_frame = tk.Frame(self.container, bg=BG_COLOR, padx=20, pady=20)
        self.current_frame.pack()

        tk.Label(self.current_frame, text="Sign Up", fg=FG_COLOR, bg=BG_COLOR, font=("Arial", 18, "bold")).pack(pady=10)

        self.signup_user_entry = self.create_entry(self.current_frame, "Username")
        self.signup_pass_entry = self.create_entry(self.current_frame, "Password", is_password=True)
        self.signup_confirm_pass_entry = self.create_entry(self.current_frame, "Confirm Password", is_password=True)
        self.signup_email_entry = self.create_entry(self.current_frame, "Email Address")

        btn = tk.Button(self.current_frame, text="Sign Up", bg=BTN_COLOR, fg="white",
                        font=("Arial", 12, "bold"), relief="flat", command=self.signup)
        btn.pack(pady=20, ipadx=10, ipady=5)
        btn.bind("<Enter>", on_enter)
        btn.bind("<Leave>", on_leave)

        switch_label = tk.Label(self.current_frame, text="Already have an account? Click here", fg=BTN_COLOR,
                                bg=BG_COLOR, font=("Arial", 10, "underline"), cursor="hand2")
        switch_label.pack()
        switch_label.bind("<Button-1>", lambda e: self.show_signin())

    def signup(self):
        username = self.signup_user_entry.get()
        password = self.signup_pass_entry.get()
        confirm_password = self.signup_confirm_pass_entry.get()
        email = self.signup_email_entry.get()

        if username and password and confirm_password and email:
            if password == confirm_password:
                self.credentials[username] = password
                self.save_credentials()
                messagebox.showinfo("Success", "Account created successfully!")
                self.show_signin()
            else:
                messagebox.showerror("Error", "Passwords do not match!")
        else:
            messagebox.showerror("Error", "All fields are required!")

    def login(self):
        username = self.signin_user_entry.get()
        password = self.signin_pass_entry.get()

        if username in self.credentials and self.credentials[username] == password:
            messagebox.showinfo("Success", "Logging in successfully!")
            self.root.destroy()  # Close the login window
            joystra_root = tk.Tk()  # Create a new Tkinter root for Joystra
            app = Joystra_App(joystra_root)  # Launch the Joystra
            joystra_root.mainloop()
        else:
            messagebox.showerror("Error", "Invalid username or password!")


if __name__ == "__main__":
    root = tk.Tk()
    app = LoginApp(root)
    root.mainloop()