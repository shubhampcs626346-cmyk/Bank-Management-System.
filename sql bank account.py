import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
import pymysql
from decimal import Decimal
import hashlib, os, binascii, csv


DB_HOST = "localhost"
DB_USER = "root"
DB_PASS = "Shubh626346"  
DB_NAME = "BankDB"

SALT_BYTES = 16
PBKDF2_ROUNDS = 120000



def connect_db():
    return pymysql.connect(
        host=DB_HOST,
        user=DB_USER,
        passwd=DB_PASS,
        database=DB_NAME,
        autocommit=True,
        connect_timeout=10
    )



def _hash_password(password: str, salt: bytes = None) -> str:
    if salt is None:
        salt = os.urandom(SALT_BYTES)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return binascii.hexlify(salt).decode() + ":" + binascii.hexlify(dk).decode()


def _verify_password(stored: str, password: str) -> bool:
    try:
        salt_hex, dk_hex = stored.split(":")
        salt = binascii.unhexlify(salt_hex)
        expected = binascii.unhexlify(dk_hex)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)
        return hashlib.compare_digest(dk, expected)
    except Exception:
        return False



def ensure_schema():
    con = pymysql.connect(host=DB_HOST, user=DB_USER, passwd=DB_PASS, autocommit=True)
    cur = con.cursor()
    cur.execute(f"CREATE DATABASE IF NOT EXISTS {DB_NAME}")
    cur.execute(f"USE {DB_NAME}")

    
    cur.execute("""
        CREATE TABLE IF NOT EXISTS accounts (
            accid VARCHAR(32) PRIMARY KEY,
            holder VARCHAR(150),
            acct_type VARCHAR(50),
            balance DECIMAL(18,2),
            status VARCHAR(30),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    
    cur.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            txid BIGINT AUTO_INCREMENT PRIMARY KEY,
            accid VARCHAR(32),
            type VARCHAR(30),
            amount DECIMAL(18,2),
            balance_after DECIMAL(18,2),
            note VARCHAR(255),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            userid INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(100) UNIQUE,
            password VARCHAR(512),
            role VARCHAR(50),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        cur.execute(
            "INSERT INTO users (username, password, role) VALUES (%s, %s, %s)",
            ("Hritik", _hash_password("260604"), "general manager")
        )
    con.close()



def create_account_db(accid, holder, acct_type, balance, status):
    con = connect_db()
    cur = con.cursor()
    cur.execute("INSERT INTO accounts (accid, holder, acct_type, balance, status) VALUES (%s,%s,%s,%s,%s)",
                (accid, holder, acct_type, Decimal(balance), status))
    cur.execute("INSERT INTO transactions (accid, type, amount, balance_after, note) VALUES (%s,%s,%s,%s,%s)",
                (accid, "Account Open", Decimal(balance), Decimal(balance), "Created"))
    con.commit()
    con.close()


def get_accounts_db():
    con = connect_db()
    cur = con.cursor()
    cur.execute("SELECT accid, holder, acct_type, balance, status, created_at FROM accounts ORDER BY created_at DESC")
    rows = cur.fetchall()
    con.close()
    return rows


def get_transactions_db(accid):
    con = connect_db()
    cur = con.cursor()
    cur.execute("SELECT txid, type, amount, balance_after, note, created_at FROM transactions WHERE accid=%s ORDER BY created_at DESC", (accid,))
    rows = cur.fetchall()
    con.close()
    return rows


def deposit_db(accid, amount):
    con = connect_db()
    cur = con.cursor()
    cur.execute("SELECT balance, status FROM accounts WHERE accid=%s", (accid,))
    row = cur.fetchone()
    if not row:
        con.close()
        return False, "Account not found"
    if row[1].lower() == "closed":
        con.close()
        return False, "Account closed"

    new_bal = Decimal(row[0]) + Decimal(amount)
    cur.execute("UPDATE accounts SET balance=%s WHERE accid=%s", (new_bal, accid))
    cur.execute("INSERT INTO transactions (accid, type, amount, balance_after, note) VALUES (%s,%s,%s,%s,%s)",
                (accid, "Deposit", Decimal(amount), new_bal, "Deposit"))
    con.commit()
    con.close()
    return True, new_bal


def withdraw_db(accid, amount):
    con = connect_db()
    cur = con.cursor()
    cur.execute("SELECT balance, status FROM accounts WHERE accid=%s", (accid,))
    row = cur.fetchone()
    if not row:
        con.close()
        return False, "Account not found"
    if row[1].lower() == "closed":
        con.close()
        return False, "Account closed"
    if Decimal(row[0]) < Decimal(amount):
        con.close()
        return False, "Insufficient funds"

    new_bal = Decimal(row[0]) - Decimal(amount)
    cur.execute("UPDATE accounts SET balance=%s WHERE accid=%s", (new_bal, accid))
    cur.execute("INSERT INTO transactions (accid, type, amount, balance_after, note) VALUES (%s,%s,%s,%s,%s)",
                (accid, "Withdraw", Decimal(amount), new_bal, "Withdrawal"))
    con.commit()
    con.close()
    return True, new_bal


def transfer_db(src, dst, amount):
    con = connect_db()
    cur = con.cursor()
    cur.execute("SELECT balance,status FROM accounts WHERE accid=%s", (src,))
    s = cur.fetchone()
    cur.execute("SELECT balance,status FROM accounts WHERE accid=%s", (dst,))
    t = cur.fetchone()
    if not s or not t:
        con.close()
        return False, "Source or destination not found"
    if s[1].lower() == "closed" or t[1].lower() == "closed":
        con.close()
        return False, "One account closed"
    if Decimal(s[0]) < Decimal(amount):
        con.close()
        return False, "Insufficient funds"

    new_s = Decimal(s[0]) - Decimal(amount)
    new_t = Decimal(t[0]) + Decimal(amount)
    cur.execute("UPDATE accounts SET balance=%s WHERE accid=%s", (new_s, src))
    cur.execute("UPDATE accounts SET balance=%s WHERE accid=%s", (new_t, dst))
    cur.execute("INSERT INTO transactions (accid,type,amount,balance_after,note) VALUES (%s,%s,%s,%s,%s)",
                (src, "Transfer Out", Decimal(amount), new_s, f"Transfer to {dst}"))
    cur.execute("INSERT INTO transactions (accid,type,amount,balance_after,note) VALUES (%s,%s,%s,%s,%s)",
                (dst, "Transfer In", Decimal(amount), new_t, f"Transfer from {src}"))
    con.commit()
    con.close()
    return True, (new_s, new_t)


def update_account_db(accid, field, value):
    con = connect_db()
    cur = con.cursor()
    cur.execute(f"UPDATE accounts SET {field}=%s WHERE accid=%s", (value, accid))
    con.commit()
    affected = cur.rowcount
    con.close()
    return affected


def delete_account_db(accid):
    con = connect_db()
    cur = con.cursor()
    cur.execute("DELETE FROM transactions WHERE accid=%s", (accid,))
    cur.execute("DELETE FROM accounts WHERE accid=%s", (accid,))
    affected = cur.rowcount
    con.commit()
    con.close()
    return affected


def export_accounts_csv(path):
    rows = get_accounts_db()
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Account ID","Holder","Type","Balance","Status","Created At"])
        w.writerows(rows)



class App(tk.Tk):
    def __init__(self):
        super().__init__()
        ensure_schema()
        self.title("🏦 Bank Management System")
        self.geometry("1100x700")
        self.configure(bg="#f0f5fb")
        self.create_ui()
        self.load_accounts()

    def create_ui(self):
        title = tk.Label(self, text="🏦 Bank Management System", font=("Segoe UI", 22, "bold"), bg="#2c3e50", fg="white")
        title.pack(fill="x")

        sidebar = tk.Frame(self, bg="#ecf0f1", width=200)
        sidebar.pack(side="left", fill="y")

        actions = [
            ("Create", self.open_create),
            ("Deposit", self.open_deposit),
            ("Withdraw", self.open_withdraw),
            ("Transfer", self.open_transfer),
            ("Change Status", self.open_status),
            ("Delete Account", self.open_delete),
            ("Export CSV", self.export_csv),
            ("Refresh", self.load_accounts)
        ]
        for txt, cmd in actions:
            b = ttk.Button(sidebar, text=txt, command=cmd)
            b.pack(fill="x", pady=6, padx=10)

        main = tk.Frame(self, bg="#f0f5fb")
        main.pack(side="right", fill="both", expand=True)

        self.tree = ttk.Treeview(main, columns=("accid","holder","type","balance","status","created"), show="headings")
        for c, w in (("accid",120),("holder",220),("type",120),("balance",100),("status",100),("created",150)):
            self.tree.heading(c, text=c.title())
            self.tree.column(c, width=w, anchor="center")
        self.tree.pack(fill="both", expand=True, padx=10, pady=10)
        self.tree.bind("<Double-1>", self.on_account_double)

    def load_accounts(self):
        try:
            rows = get_accounts_db()
            for i in self.tree.get_children():
                self.tree.delete(i)
            for r in rows:
                self.tree.insert("", "end", values=r)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def open_create(self):
        w = tk.Toplevel(self)
        w.title("Create Account")

        tk.Label(w, text="Account ID").grid(row=0,column=0,padx=6,pady=6)
        e1=tk.Entry(w); e1.grid(row=0,column=1,padx=6,pady=6)

        tk.Label(w, text="Holder").grid(row=1,column=0,padx=6,pady=6)
        e2=tk.Entry(w); e2.grid(row=1,column=1,padx=6,pady=6)

        tk.Label(w, text="Type").grid(row=2,column=0,padx=6,pady=6)
        box1=ttk.Combobox(w,values=["Savings","Current","Fixed Deposit"],state="readonly"); box1.set("Savings"); box1.grid(row=2,column=1)

        tk.Label(w, text="Balance").grid(row=3,column=0,padx=6,pady=6)
        e3=tk.Entry(w); e3.grid(row=3,column=1,padx=6,pady=6)

        tk.Label(w, text="Status").grid(row=4,column=0,padx=6,pady=6)
        box2=ttk.Combobox(w,values=["Active","Dormant","Closed"],state="readonly"); box2.set("Active"); box2.grid(row=4,column=1)

        def go():
            try:
                create_account_db(e1.get(), e2.get(), box1.get(), Decimal(e3.get()), box2.get())
                messagebox.showinfo("Success","Account created successfully!")
                w.destroy()
                self.load_accounts()
            except Exception as e:
                messagebox.showerror("Error", str(e))

        ttk.Button(w,text="Create",command=go).grid(row=5,column=0,columnspan=2,pady=10)

    def open_deposit(self):
        acc = simpledialog.askstring("Deposit","Account ID:")
        amt = simpledialog.askfloat("Deposit","Amount:")
        if not acc or not amt: return
        ok,res = deposit_db(acc, Decimal(amt))
        messagebox.showinfo("Result", f"New balance: ₹{res}" if ok else res)
        self.load_accounts()

    def open_withdraw(self):
        acc = simpledialog.askstring("Withdraw","Account ID:")
        amt = simpledialog.askfloat("Withdraw","Amount:")
        if not acc or not amt: return
        ok,res = withdraw_db(acc, Decimal(amt))
        messagebox.showinfo("Result", f"New balance: ₹{res}" if ok else res)
        self.load_accounts()

    def open_transfer(self):
        src = simpledialog.askstring("Transfer","From Account:")
        dst = simpledialog.askstring("Transfer","To Account:")
        amt = simpledialog.askfloat("Transfer","Amount:")
        if not src or not dst or not amt: return
        ok,res = transfer_db(src,dst,Decimal(amt))
        messagebox.showinfo("Result", f"Transfer successful!\nFrom: ₹{res[0]} → To: ₹{res[1]}" if ok else res)
        self.load_accounts()

    def open_status(self):
        acc = simpledialog.askstring("Status","Account ID:")
        if not acc: return
        new = simpledialog.askstring("Status","New Status (Active/Dormant/Closed):")
        if not new: return
        res = update_account_db(acc,"status",new)
        messagebox.showinfo("Result", "Status updated" if res else "Account not found")
        self.load_accounts()

    def open_delete(self):
        acc = simpledialog.askstring("Delete","Account ID to delete:")
        if not acc: return
        if messagebox.askyesno("Confirm", f"Delete account {acc}?"):
            res = delete_account_db(acc)
            messagebox.showinfo("Result", "Deleted" if res else "Account not found")
            self.load_accounts()

    def on_account_double(self, event):
        sel=self.tree.selection()
        if not sel: return
        acc=self.tree.item(sel[0],"values")[0]
        rows=get_transactions_db(acc)
        w=tk.Toplevel(self); w.title(f"Transactions - {acc}")
        t=ttk.Treeview(w,columns=("txid","type","amt","bal","note","created"),show="headings")
        for c,wid in (("txid",80),("type",120),("amt",100),("bal",100),("note",220),("created",160)):
            t.heading(c,text=c.title()); t.column(c,width=wid,anchor="center")
        t.pack(fill="both",expand=True)
        for r in rows: t.insert("", "end", values=r)

    def export_csv(self):
        path=filedialog.asksaveasfilename(defaultextension=".csv",filetypes=[("CSV files","*.csv")])
        if not path: return
        export_accounts_csv(path)
        messagebox.showinfo("Export","Accounts exported successfully!")


if __name__ == "__main__":
    App().mainloop()
    
