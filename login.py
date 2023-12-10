import customtkinter as ctk
import tkinter.messagebox as tkmb
import ldap
import hashlib

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

app = ctk.CTk()
app.geometry("400x400")
app.title("TekupLive")

LDAP_BASE_DN = "ou=users,dc=tekuplive"

def login():
    username = user_entry.get()
    password = user_pass.get()

    user_dn = f"cn={username},{LDAP_BASE_DN}"
    search_filter = f"(cn={username})"
    hashed_pwd = hashlib.sha256(password.encode("UTF-8")).hexdigest()

    ldap_client = ldap.initialize("ldap://localhost:389")

    try:
        ldap_client.bind_s(user_dn, hashed_pwd)
        tkmb.showinfo(title="Login Successful", message="You have logged in Successfully")
    except ldap.INVALID_CREDENTIALS:
        tkmb.showwarning(title='Wrong password', message='Invalid username or password')
    except ldap.LDAPError as e:
        tkmb.showerror(title="Login Failed", message=f"LDAP Error: {e}")
    finally:
        ldap_client.unbind_s()


def toggle_password_visibility():
    current_state = password_var.get()
    user_pass.configure(show="" if current_state else "*")
label = ctk.CTkLabel(app, text="TekupLive")
label.pack(pady=20)

frame = ctk.CTkFrame(master=app)
frame.pack(pady=20, padx=40, fill='both', expand=True)

user_entry = ctk.CTkEntry(master=frame, placeholder_text="Login")
user_entry.pack(pady=12, padx=10)

user_pass = ctk.CTkEntry(master=frame, placeholder_text="Password", show="*")
user_pass.pack(pady=12, padx=10)

password_var = ctk.BooleanVar()
password_checkbutton = ctk.CTkCheckBox(master=frame, text='afficher le mot de passe', variable=password_var, command=toggle_password_visibility)
password_checkbutton.pack(pady=5, padx=10)

button = ctk.CTkButton(master=frame, text='Login', command=login)
button.pack(pady=12, padx=10)

checkbox = ctk.CTkCheckBox(master=frame, text='afficher le mot de passe')
checkbox.pack(pady=12, padx=10)

app.mainloop()
