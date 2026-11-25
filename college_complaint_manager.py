"""
CampusVoice - College Complaint Manager (GreenFuture Hack, Project #23)
FastHTML + SQLite | Student & Manager portals | PBKDF2 password hashing
Run:  python app.py        (optional demo data:  SEED=1 python app.py)
"""
import csv, hashlib, hmac, io, os, re, secrets, sqlite3, time
from contextlib import closing
from datetime import datetime
from fasthtml.common import *

DB = "complaints.db"
STATUSES = ["Pending", "In Progress", "Resolved", "Closed"]
PRIORITIES = ["Low", "Medium", "High"]
OVERDUE_DAYS = 7
DEFAULT_CATEGORIES = ["Hostel", "Academics", "Library", "Canteen", "Transport", "Infrastructure", "Harassment / Safety", "Other"]
now = lambda: datetime.now().strftime("%Y-%m-%d %H:%M")

# ───────────────────────── Database ─────────────────────────
def conn():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON"); return c

def q(sql, *a):
    with closing(conn()) as c:
        rows = c.execute(sql, a).fetchall(); c.commit(); return rows

def one(sql, *a):
    r = q(sql, *a); return r[0] if r else None

def ex(sql, *a):
    with closing(conn()) as c:
        cur = c.execute(sql, a); c.commit(); return cur.lastrowid

def init_db():
    with closing(conn()) as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS students(id INTEGER PRIMARY KEY, name TEXT NOT NULL, roll TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE, pw_hash TEXT NOT NULL, created TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS managers(id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, pw_hash TEXT NOT NULL, created TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS categories(id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE);
        CREATE TABLE IF NOT EXISTS complaints(id INTEGER PRIMARY KEY, student_id INTEGER NOT NULL REFERENCES students(id),
            category_id INTEGER NOT NULL REFERENCES categories(id), title TEXT NOT NULL, description TEXT NOT NULL,
            priority TEXT NOT NULL DEFAULT 'Medium', status TEXT NOT NULL DEFAULT 'Pending', created TEXT NOT NULL, updated TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS updates(id INTEGER PRIMARY KEY, complaint_id INTEGER NOT NULL REFERENCES complaints(id) ON DELETE CASCADE,
            actor TEXT NOT NULL, status TEXT NOT NULL, note TEXT, created TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS activity(id INTEGER PRIMARY KEY, actor TEXT NOT NULL, action TEXT NOT NULL, created TEXT NOT NULL);
        """)
        if not c.execute("SELECT 1 FROM categories").fetchone():
            c.executemany("INSERT INTO categories(name) VALUES(?)", [(n,) for n in DEFAULT_CATEGORIES])
        c.commit()

def log(actor, action): ex("INSERT INTO activity(actor,action,created) VALUES(?,?,?)", actor, action, now())

# ───────────────────────── Security ─────────────────────────
def hash_pw(pw, salt=None):
    salt = salt or secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 240_000).hex()
    return f"{salt}${h}"

def check_pw(pw, stored):
    try: salt, _ = stored.split("$"); return hmac.compare_digest(hash_pw(pw, salt), stored)
    except Exception: return False

def strong(pw): return len(pw) >= 8 and re.search(r"[A-Za-z]", pw) and re.search(r"\d", pw)

FAILS = {}  # simple brute-force lockout: key -> (count, locked_until)
def locked(key): _, until = FAILS.get(key, (0, 0)); return until > time.time()
def fail(key):
    c, _ = FAILS.get(key, (0, 0)); c += 1
    FAILS[key] = (c, time.time() + 120 if c >= 5 else 0)
    if c >= 5: FAILS[key] = (0, time.time() + 120)

OPEN_PATHS = {"/student/login", "/student/register", "/manager/login", "/manager/setup"}
def guard(req, sess):
    p, role = req.url.path, sess.get("role")
    if p.startswith("/manager") and p not in OPEN_PATHS and role != "manager": return RedirectResponse("/manager/login", status_code=303)
    if p.startswith("/student") and p not in OPEN_PATHS and role != "student": return RedirectResponse("/student/login", status_code=303)

# ───────────────────────── Styling ─────────────────────────
CSS = """
:root{--ink:#12263A;--ink2:#1B3A57;--paper:#F4F6F8;--card:#fff;--teal:#0E7C7B;--teal2:#14A3A1;--saffron:#F2A33A;--red:#C8433A;--green:#2E9E5B;--blue:#3B72C9;--muted:#6B7C8C;--line:#E3E8ED}
*{box-sizing:border-box}body{margin:0;font-family:'Nunito Sans',system-ui,sans-serif;background:var(--paper);color:var(--ink);line-height:1.5}
h1,h2,h3,.brand{font-family:'Sora',sans-serif;letter-spacing:-.02em;margin:0}a{color:var(--teal);text-decoration:none}
.shell{display:grid;grid-template-columns:250px 1fr;min-height:100vh}
.side{background:var(--ink);color:#cfe0ee;padding:24px 16px;position:sticky;top:0;height:100vh;display:flex;flex-direction:column;gap:6px}
.brand{color:#fff;font-size:1.3rem;padding:0 10px 18px}.brand i{color:var(--saffron);margin-right:8px}
.side a{color:#b9cde0;padding:11px 14px;border-radius:10px;display:flex;gap:12px;align-items:center;transition:.2s}
.side a:hover{background:var(--ink2);color:#fff}.side a.on{background:var(--teal);color:#fff}.side .sp{flex:1}
.main{padding:28px 34px;min-width:0}.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:22px;gap:12px}
.top h2{font-size:1.6rem}.who{color:var(--muted);font-size:.9rem}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:16px;margin-bottom:24px}
.stat{background:var(--card);border-radius:14px;padding:18px;border:1px solid var(--line);border-left:5px solid var(--teal)}
.stat b{font-family:'Sora';font-size:2rem;display:block}.stat span{color:var(--muted);font-size:.9rem}
.stat.s2{border-left-color:var(--saffron)}.stat.s3{border-left-color:var(--blue)}.stat.s4{border-left-color:var(--green)}.stat.s5{border-left-color:var(--red)}
.panel{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:22px;margin-bottom:22px}
.panel h3{margin-bottom:14px;font-size:1.1rem}.grid2{display:grid;grid-template-columns:1fr 1fr;gap:22px}
.tw{overflow-x:auto}table{width:100%;border-collapse:collapse;font-size:.93rem}
th{text-align:left;color:var(--muted);font-weight:600;padding:10px;border-bottom:2px solid var(--line);white-space:nowrap}
td{padding:11px 10px;border-bottom:1px solid var(--line);vertical-align:middle}tr:hover td{background:#fafcfd}.empty{text-align:center;color:var(--muted);padding:26px}
.btn{display:inline-flex;gap:8px;align-items:center;border:0;cursor:pointer;background:var(--teal);color:#fff;padding:11px 18px;border-radius:10px;font:600 .95rem 'Nunito Sans';transition:.2s}
.btn:hover{background:var(--teal2);transform:translateY(-1px);color:#fff}.btn.sm{padding:6px 12px;font-size:.85rem}.btn.red{background:var(--red)}.btn.ghost{background:#e9eff4;color:var(--ink)}
input,select,textarea{width:100%;padding:11px 13px;border:1.5px solid var(--line);border-radius:10px;font:inherit;background:#fff;color:var(--ink)}
input:focus,select:focus,textarea:focus,.btn:focus-visible,a:focus-visible{outline:3px solid #14a3a155;border-color:var(--teal)}
label{font-weight:600;font-size:.88rem;display:block;margin-bottom:5px}.fld{margin-bottom:15px}
.badge{padding:3px 11px;border-radius:99px;font-size:.78rem;font-weight:700;white-space:nowrap}
.b-Pending{background:#FFF1D6;color:#9A6200}.b-InProgress{background:#DCE8FB;color:#2455A4}.b-Resolved{background:#D8F3E3;color:#1C7040}.b-Closed{background:#E6EAEE;color:#4A5A68}
.p-High{color:var(--red);font-weight:700}.p-Medium{color:#9A6200}.p-Low{color:var(--muted)}
.flash{background:#E4F6F5;border-left:5px solid var(--teal);padding:12px 16px;border-radius:10px;margin-bottom:18px}.flash.err{background:#FBE7E5;border-color:var(--red)}
.bar{display:flex;align-items:center;gap:10px;margin:9px 0;font-size:.9rem}.bar em{width:130px;font-style:normal}.bar div{flex:1;background:#edf1f4;border-radius:99px;height:11px;overflow:hidden}
.bar div i{display:block;height:100%;background:linear-gradient(90deg,var(--teal),var(--teal2));border-radius:99px;transition:width 1s}.bar small{width:30px;text-align:right;color:var(--muted)}
.tl{border-left:3px solid var(--line);margin-left:8px;padding-left:20px}.tl div{position:relative;margin-bottom:18px}
.tl div:before{content:'';position:absolute;left:-28px;top:5px;width:12px;height:12px;border-radius:50%;background:var(--teal);border:3px solid #fff;box-shadow:0 0 0 2px var(--teal)}
.tl small{color:var(--muted)}.filters{display:grid;grid-template-columns:2fr 1fr 1fr 1fr auto;gap:10px;margin-bottom:16px}
.warn{color:var(--saffron);margin-left:6px}.navtoggle,.burger{display:none}
/* auth pages */
.auth{display:grid;grid-template-columns:1.1fr 1fr;min-height:100vh}
.hero{background:linear-gradient(155deg,var(--ink) 0%,var(--teal) 130%);color:#fff;padding:60px;display:flex;flex-direction:column;justify-content:center;gap:18px}
.hero h1{font-size:3rem;line-height:1.05}.hero p{color:#cfe6e8;max-width:46ch;font-size:1.05rem}.hero ul{list-style:none;padding:0;color:#d7ecee}.hero li{margin:8px 0}.hero li i{color:var(--saffron);margin-right:10px}
.formside{display:flex;align-items:center;justify-content:center;padding:34px;background:#fff}.formbox{width:100%;max-width:410px}
.formbox h2{font-size:1.7rem;margin-bottom:6px}.formbox .sub{color:var(--muted);margin-bottom:22px}.formbox .btn{width:100%;justify-content:center}.alt{text-align:center;margin-top:16px;font-size:.92rem}
.portals{display:grid;gap:14px;margin-top:10px}.portal{display:flex;gap:16px;align-items:center;padding:20px;border:1.5px solid var(--line);border-radius:14px;color:var(--ink);transition:.2s}
.portal:hover{border-color:var(--teal);transform:translateX(4px);box-shadow:0 6px 20px #12263a14}.portal i.ic{font-size:1.6rem;color:var(--teal);width:36px;text-align:center}.portal b{font-family:'Sora';display:block}.portal span{color:var(--muted);font-size:.9rem}
.hero{animation:rise .7s both}@keyframes rise{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:none}}
@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
@media(max-width:900px){.shell{grid-template-columns:1fr}.side{position:fixed;left:-270px;width:250px;z-index:20;transition:.25s}.navtoggle:checked~.side{left:0}
.burger{display:inline-block;font-size:1.4rem;cursor:pointer}.main{padding:18px}.grid2,.auth{grid-template-columns:1fr}.hero{padding:34px;min-height:auto}.hero h1{font-size:2.2rem}.filters{grid-template-columns:1fr 1fr}}
"""
HDRS = (Link(rel="preconnect", href="https://fonts.googleapis.com"),
        Link(rel="stylesheet", href="https://fonts.googleapis.com/css2?family=Nunito+Sans:wght@400;600;700&family=Sora:wght@600;700&display=swap"),
        Link(rel="stylesheet", href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css"),
        Style(CSS))
app, rt = fast_app(pico=False, hdrs=HDRS, before=Beforeware(guard, skip=[r"/favicon\.ico"]), title="CampusVoice")

# ───────────────────────── UI helpers ─────────────────────────
def ico(n): return I(cls=f"fa-solid fa-{n}")
def badge(s): return Span(s, cls=f"badge b-{s.replace(' ', '')}")
def field(label, name, type="text", **kw): return Div(Label(label, fr=name), Input(id=name, name=name, type=type, **kw), cls="fld")
def toast(sess):
    m = sess.pop("flash", None)
    return Div(m[1], cls="flash err" if m[0] == "err" else "flash") if m else ""
def say(sess, msg, kind="ok"): sess["flash"] = (kind, msg)
def go(path): return RedirectResponse(path, status_code=303)

NAV = {"student": [("dashboard", "Dashboard", "gauge"), ("new", "New complaint", "pen-to-square"), ("complaints", "My complaints", "list-check")],
       "manager": [("dashboard", "Dashboard", "chart-pie"), ("complaints", "All complaints", "inbox"), ("students", "Students", "user-graduate"),
                   ("categories", "Categories", "tags"), ("activity", "Activity log", "clock-rotate-left"), ("report.csv", "Download report", "file-arrow-down")]}

def shell(sess, role, active, title, *body):
    links = [A(ico(i), l, href=f"/{role}/{p}", cls="on" if p == active else "") for p, l, i in NAV[role]]
    name = sess.get("name", "")
    return (Title(f"{title} • CampusVoice"),
            Div(Input(type="checkbox", id="nav", cls="navtoggle"),
                Div(Div(ico("bullhorn"), "CampusVoice", cls="brand"), *links, Div(cls="sp"),
                    A(ico("right-from-bracket"), "Log out", href="/logout"), cls="side"),
                Div(Div(Div(Label(ico("bars"), fr="nav", cls="burger"), H2(title)), Div(f"{name} · {role.title()}", cls="who"), cls="top"),
                    toast(sess), *body, cls="main"), cls="shell"))

def auth_page(title, sub, form, alt, sess, who="Student"):
    pts = ["Raise a complaint in under a minute", "Follow every status change on a timeline", "Overdue issues are flagged automatically"] if who == "Student" else \
          ["One inbox for every complaint", "Search, filter and export reports", "Every action is logged for audit"]
    return (Title(f"{title} • CampusVoice"),
            Div(Div(H1("Say it.", Br(), "Track it.", Br(), "Get it fixed."), P("CampusVoice connects students and college administration so no complaint gets lost."),
                    Ul(*[Li(ico("circle-check"), t) for t in pts]), cls="hero"),
                Div(Div(H2(title), P(sub, cls="sub"), toast(sess), form, Div(*alt, cls="alt"), cls="formbox"), cls="formside"), cls="auth"))

def stat(n, label, cls=""): return Div(B(n), Span(label), cls=f"stat {cls}")

def bars(rows):
    top = max([r[1] for r in rows] + [1])
    return Div(*[Div(Em(k), Div(I(style=f"width:{v / top * 100:.0f}%")), Small(v), cls="bar") for k, v in rows]) if rows else P("No data yet.", cls="empty")

BASE = """SELECT c.*, k.name category, s.name student, s.roll,
 (c.status IN ('Pending','In Progress') AND julianday('now','localtime')-julianday(c.created)>%d) overdue
 FROM complaints c JOIN categories k ON k.id=c.category_id JOIN students s ON s.id=c.student_id""" % OVERDUE_DAYS

def ctable(rows, role):
    head = ["#", "Title"] + (["Student"] if role == "manager" else []) + ["Category", "Priority", "Status", "Date", ""]
    body = [Tr(Td(r["id"]), Td(r["title"], Span(ico("triangle-exclamation"), cls="warn", title="Overdue") if r["overdue"] else ""),
               *([Td(r["student"])] if role == "manager" else []), Td(r["category"]), Td(r["priority"], cls=f"p-{r['priority']}"),
               Td(badge(r["status"])), Td(r["created"][:10]), Td(A("Open", href=f"/{role}/complaint/{r['id']}", cls="btn sm"))) for r in rows]
    return Div(Table(Thead(Tr(*[Th(h) for h in head])), Tbody(*(body or [Tr(Td("No complaints found.", colspan=len(head), cls="empty"))]))), cls="tw")

def timeline(cid):
    return Div(*[Div(Div(badge(u["status"]), f"  {u['actor']}"), P(u["note"] or "—", style="margin:4px 0"), Small(u["created"])) for u in
                 q("SELECT * FROM updates WHERE complaint_id=? ORDER BY id DESC", cid)], cls="tl")

# ───────────────────────── Public ─────────────────────────
@rt("/")
def home(sess):
    form = Div(A(I(cls="fa-solid fa-user-graduate ic"), Div(B("Student portal"), Span("Register, submit and track complaints")), href="/student/login", cls="portal"),
               A(I(cls="fa-solid fa-user-shield ic"), Div(B("Manager portal"), Span("Review, update and report")), href="/manager/login", cls="portal"), cls="portals")
    return auth_page("Welcome", "Choose how you want to sign in.", form, [], sess)

@rt("/logout")
def logout(sess):
    sess.clear(); return go("/")

# ───────────────────────── Student auth ─────────────────────────
@rt("/student/register", methods=["GET"])
def student_register(sess):
    f = Form(field("Full name", "name", required=True), field("Roll number", "roll", required=True), field("College email", "email", "email", required=True),
             field("Password (8+ chars, letters and digits)", "password", "password", required=True, minlength=8), Button(ico("user-plus"), "Create account", cls="btn"), method="post")
    return auth_page("Create student account", "Register once, then log in anytime.", f, ["Already registered? ", A("Log in", href="/student/login")], sess)

@rt("/student/register", methods=["POST"])
def student_register_post(sess, name: str, roll: str, email: str, password: str):
    name, roll, email = name.strip(), roll.strip().upper(), email.strip().lower()
    if not name or not roll or not re.match(r"^[^@\s]+@[^@\s]+\.\w+$", email): say(sess, "Enter a valid name, roll number and email.", "err"); return go("/student/register")
    if not strong(password): say(sess, "Password needs 8+ characters with at least one letter and one digit.", "err"); return go("/student/register")
    if one("SELECT 1 FROM students WHERE email=? OR roll=?", email, roll): say(sess, "That email or roll number is already registered.", "err"); return go("/student/register")
    ex("INSERT INTO students(name,roll,email,pw_hash,created) VALUES(?,?,?,?,?)", name, roll, email, hash_pw(password), now())
    log(f"Student {roll}", "Registered account"); say(sess, "Account created. Please log in."); return go("/student/login")

@rt("/student/login", methods=["GET"])
def student_login(sess):
    f = Form(field("College email", "email", "email", required=True), field("Password", "password", "password", required=True), Button(ico("right-to-bracket"), "Log in", cls="btn"), method="post")
    return auth_page("Student login", "Log in to track your complaints.", f, ["New here? ", A("Create an account", href="/student/register"), Br(), A("Manager? Log in here", href="/manager/login")], sess)

@rt("/student/login", methods=["POST"])
def student_login_post(sess, email: str, password: str):
    key = "s:" + email.lower()
    if locked(key): say(sess, "Too many attempts. Try again in 2 minutes.", "err"); return go("/student/login")
    s = one("SELECT * FROM students WHERE email=?", email.strip().lower())
    if not s or not check_pw(password, s["pw_hash"]): fail(key); say(sess, "Incorrect email or password.", "err"); return go("/student/login")
    FAILS.pop(key, None); sess.clear(); sess.update(role="student", uid=s["id"], name=s["name"]); log(f"Student {s['roll']}", "Logged in")
    return go("/student/dashboard")

# ───────────────────────── Student pages ─────────────────────────
@rt("/student/dashboard")
def student_dashboard(sess):
    uid = sess["uid"]; rows = q(BASE + " WHERE c.student_id=? ORDER BY c.id DESC", uid)
    cnt = lambda s: sum(r["status"] == s for r in rows)
    return shell(sess, "student", "dashboard", f"Hello, {sess['name'].split()[0]}",
                 Div(stat(len(rows), "Submitted"), stat(cnt("Pending"), "Pending", "s2"), stat(cnt("In Progress"), "In progress", "s3"), stat(cnt("Resolved") + cnt("Closed"), "Resolved / closed", "s4"), cls="cards"),
                 Div(H3("Recent complaints"), ctable(rows[:5], "student"), A(ico("plus"), "New complaint", href="/student/new", cls="btn"), cls="panel"))

@rt("/student/new", methods=["GET"])
def student_new(sess):
    cats = q("SELECT * FROM categories ORDER BY name")
    f = Form(Div(Label("Category", fr="category_id"), Select(*[Option(c["name"], value=c["id"]) for c in cats], id="category_id", name="category_id"), cls="fld"),
             field("Title", "title", required=True, maxlength=120, placeholder="e.g. Water cooler broken on 2nd floor"),
             Div(Label("Describe the problem", fr="description"), Textarea(id="description", name="description", rows=6, required=True, minlength=15, placeholder="What happened, where, and since when?"), cls="fld"),
             Div(Label("Priority", fr="priority"), Select(*[Option(p, selected=p == "Medium") for p in PRIORITIES], id="priority", name="priority"), cls="fld"),
             Button(ico("paper-plane"), "Submit complaint", cls="btn"), method="post")
    return shell(sess, "student", "new", "New complaint", Div(f, cls="panel", style="max-width:680px"))

@rt("/student/new", methods=["POST"])
def student_new_post(sess, category_id: int, title: str, description: str, priority: str):
    title, description = title.strip(), description.strip()
    if len(title) < 5 or len(description) < 15 or priority not in PRIORITIES or not one("SELECT 1 FROM categories WHERE id=?", category_id):
        say(sess, "Title needs 5+ characters and the description 15+.", "err"); return go("/student/new")
    t = now(); cid = ex("INSERT INTO complaints(student_id,category_id,title,description,priority,created,updated) VALUES(?,?,?,?,?,?,?)", sess["uid"], category_id, title, description, priority, t, t)
    ex("INSERT INTO updates(complaint_id,actor,status,note,created) VALUES(?,?,?,?,?)", cid, "You", "Pending", "Complaint submitted", t)
    log(f"Student {sess['name']}", f"Submitted complaint #{cid}"); say(sess, f"Complaint #{cid} submitted."); return go(f"/student/complaint/{cid}")

@rt("/student/complaints")
def student_complaints(sess):
    return shell(sess, "student", "complaints", "My complaints", Div(ctable(q(BASE + " WHERE c.student_id=? ORDER BY c.id DESC", sess["uid"]), "student"), cls="panel"))

@rt("/student/complaint/{cid}")
def student_complaint(sess, cid: int):
    c = one(BASE + " WHERE c.id=? AND c.student_id=?", cid, sess["uid"])  # ownership enforced
    if not c: say(sess, "Complaint not found.", "err"); return go("/student/complaints")
    return shell(sess, "student", "complaints", f"Complaint #{cid}",
                 Div(H3(c["title"]), P(badge(c["status"]), f"  {c['category']} · Priority: {c['priority']} · Filed {c['created']}"), P(c["description"], style="white-space:pre-wrap"), cls="panel"),
                 Div(H3("Status updates"), timeline(cid), cls="panel"))

# ───────────────────────── Manager auth ─────────────────────────
@rt("/manager/setup", methods=["GET"])
def manager_setup(sess):
    if one("SELECT 1 FROM managers"): return go("/manager/login")
    f = Form(field("Choose a username", "username", required=True), field("Create a secure password (8+ chars, letters and digits)", "password", "password", required=True, minlength=8),
             field("Confirm password", "confirm", "password", required=True), Button(ico("shield-halved"), "Create manager account", cls="btn"), method="post")
    return auth_page("First-time manager setup", "No manager exists yet. Create the administrator account.", f, [], sess, "Manager")

@rt("/manager/setup", methods=["POST"])
def manager_setup_post(sess, username: str, password: str, confirm: str):
    if one("SELECT 1 FROM managers"): return go("/manager/login")
    if password != confirm or not strong(password) or len(username.strip()) < 3: say(sess, "Passwords must match, be 8+ characters with letters and digits; username 3+ characters.", "err"); return go("/manager/setup")
    ex("INSERT INTO managers(username,pw_hash,created) VALUES(?,?,?)", username.strip().lower(), hash_pw(password), now())
    log(f"Manager {username}", "Manager account created"); say(sess, "Manager account created. Please log in."); return go("/manager/login")

@rt("/manager/login", methods=["GET"])
def manager_login(sess):
    if not one("SELECT 1 FROM managers"): return go("/manager/setup")
    f = Form(field("Username", "username", required=True), field("Password", "password", "password", required=True), Button(ico("lock"), "Log in", cls="btn"), method="post")
    return auth_page("Manager login", "Authorised staff only.", f, [A("Student? Log in here", href="/student/login")], sess, "Manager")

@rt("/manager/login", methods=["POST"])
def manager_login_post(sess, username: str, password: str):
    key = "m:" + username.lower()
    if locked(key): say(sess, "Too many attempts. Try again in 2 minutes.", "err"); return go("/manager/login")
    m = one("SELECT * FROM managers WHERE username=?", username.strip().lower())
    if not m or not check_pw(password, m["pw_hash"]): fail(key); log(f"Manager {username}", "Failed login attempt"); say(sess, "Incorrect username or password.", "err"); return go("/manager/login")
    FAILS.pop(key, None); sess.clear(); sess.update(role="manager", uid=m["id"], name=m["username"]); log(f"Manager {m['username']}", "Logged in")
    return go("/manager/dashboard")

# ───────────────────────── Manager pages ─────────────────────────
@rt("/manager/dashboard")
def manager_dashboard(sess):
    n = lambda sql: q(sql)[0][0]
    total = n("SELECT COUNT(*) FROM complaints"); res = n("SELECT COUNT(*) FROM complaints WHERE status IN ('Resolved','Closed')")
    by_status = [(s, n(f"SELECT COUNT(*) FROM complaints WHERE status='{s}'")) for s in STATUSES]
    by_cat = [(r[0], r[1]) for r in q("SELECT k.name, COUNT(c.id) FROM categories k JOIN complaints c ON c.category_id=k.id GROUP BY k.id ORDER BY 2 DESC")]
    by_pri = [(p, n(f"SELECT COUNT(*) FROM complaints WHERE priority='{p}'")) for p in PRIORITIES]
    all_overdue = [r for r in q(BASE + " ORDER BY c.created") if r["overdue"]]
    overdue = all_overdue[:5]
    return shell(sess, "manager", "dashboard", "Dashboard",
                 Div(stat(total, "Total complaints"), stat(by_status[0][1], "Pending", "s2"), stat(by_status[1][1], "In progress", "s3"), stat(res, "Resolved / closed", "s4"),
                     stat(f"{res / total * 100:.0f}%" if total else "0%", "Resolution rate"), stat(n("SELECT COUNT(*) FROM students"), "Students", "s3"),
                     stat(len(all_overdue), f"Overdue (> {OVERDUE_DAYS} days)", "s5"), cls="cards"),
                 Div(Div(H3("By status"), bars(by_status), cls="panel"), Div(H3("By category"), bars(by_cat), cls="panel"), cls="grid2"),
                 Div(Div(H3("By priority"), bars(by_pri), cls="panel"), Div(H3(ico("triangle-exclamation"), " Needs attention"), ctable(overdue, "manager"), cls="panel"), cls="grid2"))

@rt("/manager/complaints")
def manager_complaints(sess, qs: str = "", status: str = "", category: str = "", priority: str = ""):
    w, a = [], []
    if qs: w.append("(c.title LIKE ? OR c.description LIKE ? OR s.name LIKE ? OR s.roll LIKE ?)"); a += [f"%{qs}%"] * 4
    if status in STATUSES: w.append("c.status=?"); a.append(status)
    if category.isdigit(): w.append("c.category_id=?"); a.append(int(category))
    if priority in PRIORITIES: w.append("c.priority=?"); a.append(priority)
    rows = q(BASE + (" WHERE " + " AND ".join(w) if w else "") + " ORDER BY c.id DESC", *a)
    cats = q("SELECT * FROM categories ORDER BY name")
    f = Form(Input(name="qs", value=qs, placeholder="Search title, text, student or roll no."),
             Select(Option("All statuses", value=""), *[Option(s, selected=s == status) for s in STATUSES], name="status"),
             Select(Option("All categories", value=""), *[Option(c["name"], value=c["id"], selected=str(c["id"]) == category) for c in cats], name="category"),
             Select(Option("All priorities", value=""), *[Option(p, selected=p == priority) for p in PRIORITIES], name="priority"),
             Button(ico("magnifying-glass"), "Filter", cls="btn"), method="get", cls="filters")
    return shell(sess, "manager", "complaints", "All complaints", Div(f, P(f"{len(rows)} result(s)", cls="who"), ctable(rows, "manager"), cls="panel"))

@rt("/manager/complaint/{cid}", methods=["GET"])
def manager_complaint(sess, cid: int):
    c = one(BASE + " WHERE c.id=?", cid)
    if not c: say(sess, "Complaint not found.", "err"); return go("/manager/complaints")
    upd = Form(Div(Label("Status", fr="status"), Select(*[Option(s, selected=s == c["status"]) for s in STATUSES], id="status", name="status"), cls="fld"),
               Div(Label("Note for the student", fr="note"), Textarea(id="note", name="note", rows=3, placeholder="What has been done or what happens next?"), cls="fld"),
               Button(ico("floppy-disk"), "Update status", cls="btn"), method="post", action=f"/manager/complaint/{cid}/status")
    dele = Form(Button(ico("trash"), "Delete complaint", cls="btn red", onclick="return confirm('Delete this complaint permanently?')"), method="post", action=f"/manager/complaint/{cid}/delete")
    return shell(sess, "manager", "complaints", f"Complaint #{cid}",
                 Div(H3(c["title"], Span(ico("triangle-exclamation"), cls="warn") if c["overdue"] else ""),
                     P(badge(c["status"]), f"  {c['category']} · Priority: {c['priority']} · Filed {c['created']}"),
                     P(c["description"], style="white-space:pre-wrap"),
                     P(ico("user"), " ", A(f"{c['student']} ({c['roll']})", href=f"/manager/student/{c['student_id']}")), cls="panel"),
                 Div(Div(H3("Manage"), upd, Div(dele, style="margin-top:14px"), cls="panel"), Div(H3("History"), timeline(cid), cls="panel"), cls="grid2"))

@rt("/manager/complaint/{cid}/status", methods=["POST"])
def manager_status(sess, cid: int, status: str, note: str = ""):
    if status not in STATUSES or not one("SELECT 1 FROM complaints WHERE id=?", cid): say(sess, "Invalid update.", "err"); return go("/manager/complaints")
    ex("UPDATE complaints SET status=?, updated=? WHERE id=?", status, now(), cid)
    ex("INSERT INTO updates(complaint_id,actor,status,note,created) VALUES(?,?,?,?,?)", cid, f"Manager {sess['name']}", status, note.strip(), now())
    log(f"Manager {sess['name']}", f"Set complaint #{cid} to {status}"); say(sess, f"Complaint #{cid} is now {status}."); return go(f"/manager/complaint/{cid}")

@rt("/manager/complaint/{cid}/delete", methods=["POST"])
def manager_delete(sess, cid: int):
    ex("DELETE FROM complaints WHERE id=?", cid); log(f"Manager {sess['name']}", f"Deleted complaint #{cid}"); say(sess, f"Complaint #{cid} deleted."); return go("/manager/complaints")

@rt("/manager/students")
def manager_students(sess):
    rows = q("SELECT s.*, COUNT(c.id) n FROM students s LEFT JOIN complaints c ON c.student_id=s.id GROUP BY s.id ORDER BY s.name")
    t = Table(Thead(Tr(*[Th(h) for h in ["Name", "Roll no.", "Email", "Joined", "Complaints", ""]])),
              Tbody(*([Tr(Td(r["name"]), Td(r["roll"]), Td(r["email"]), Td(r["created"][:10]), Td(r["n"]), Td(A("View", href=f"/manager/student/{r['id']}", cls="btn sm"))) for r in rows]
                      or [Tr(Td("No students yet.", colspan=6, cls="empty"))])))
    return shell(sess, "manager", "students", "Students", Div(Div(t, cls="tw"), cls="panel"))

@rt("/manager/student/{sid}")
def manager_student(sess, sid: int):
    s = one("SELECT * FROM students WHERE id=?", sid)
    if not s: return go("/manager/students")
    return shell(sess, "manager", "students", s["name"],
                 Div(H3("Student details"), P(B("Roll no: "), s["roll"]), P(B("Email: "), s["email"]), P(B("Registered: "), s["created"]), cls="panel"),
                 Div(H3("Complaints"), ctable(q(BASE + " WHERE c.student_id=? ORDER BY c.id DESC", sid), "manager"), cls="panel"))

@rt("/manager/categories", methods=["GET"])
def manager_categories(sess):
    rows = q("SELECT k.*, COUNT(c.id) n FROM categories k LEFT JOIN complaints c ON c.category_id=k.id GROUP BY k.id ORDER BY k.name")
    t = Table(Thead(Tr(Th("Category"), Th("Complaints"), Th(""))),
              Tbody(*[Tr(Td(r["name"]), Td(r["n"]), Td(Form(Button(ico("trash"), cls="btn sm red", title="Delete"), method="post", action=f"/manager/categories/{r['id']}/delete"))) for r in rows]))
    add = Form(Div(Input(name="name", placeholder="New category name", required=True, maxlength=40), cls="fld"), Button(ico("plus"), "Add category", cls="btn"), method="post")
    return shell(sess, "manager", "categories", "Categories", Div(Div(H3("Add category"), add, cls="panel"), Div(H3("Existing categories"), Div(t, cls="tw"), cls="panel"), cls="grid2"))

@rt("/manager/categories", methods=["POST"])
def manager_category_add(sess, name: str):
    name = name.strip()
    if not name or one("SELECT 1 FROM categories WHERE lower(name)=lower(?)", name): say(sess, "Enter a new, unique category name.", "err")
    else: ex("INSERT INTO categories(name) VALUES(?)", name); log(f"Manager {sess['name']}", f"Added category '{name}'"); say(sess, "Category added.")
    return go("/manager/categories")

@rt("/manager/categories/{kid}/delete", methods=["POST"])
def manager_category_delete(sess, kid: int):
    if one("SELECT 1 FROM complaints WHERE category_id=?", kid): say(sess, "This category has complaints and cannot be deleted.", "err")
    else: ex("DELETE FROM categories WHERE id=?", kid); log(f"Manager {sess['name']}", f"Deleted category #{kid}"); say(sess, "Category deleted.")
    return go("/manager/categories")

@rt("/manager/activity")
def manager_activity(sess):
    rows = q("SELECT * FROM activity ORDER BY id DESC LIMIT 200")
    t = Table(Thead(Tr(Th("When"), Th("Who"), Th("Action"))), Tbody(*[Tr(Td(r["created"]), Td(r["actor"]), Td(r["action"])) for r in rows]))
    return shell(sess, "manager", "activity", "Activity log", Div(Div(t, cls="tw"), cls="panel"))

@rt("/manager/report.csv")
def manager_report(sess):
    buf = io.StringIO(); w = csv.writer(buf)
    w.writerow(["ID", "Student", "Roll", "Category", "Title", "Description", "Priority", "Status", "Overdue", "Created", "Updated"])
    for r in q(BASE + " ORDER BY c.id"): w.writerow([r["id"], r["student"], r["roll"], r["category"], r["title"], r["description"], r["priority"], r["status"], "Yes" if r["overdue"] else "No", r["created"], r["updated"]])
    log(f"Manager {sess['name']}", "Downloaded CSV report")
    return Response(buf.getvalue(), media_type="text/csv", headers={"Content-Disposition": f"attachment; filename=complaints_{datetime.now():%Y%m%d}.csv"})

# ───────────────────────── Demo data & launch ─────────────────────────
def seed():
    import random
    if q("SELECT 1 FROM students"): return
    names = ["Aarav Reddy", "Priya Sharma", "Kiran Kumar", "Sneha Rao", "Rahul Verma", "Meera Nair"]
    for i, n in enumerate(names, 1):
        ex("INSERT INTO students(name,roll,email,pw_hash,created) VALUES(?,?,?,?,?)", n, f"22CS{100 + i}", f"student{i}@college.edu", hash_pw("Student123"), now())
    cats = [r["id"] for r in q("SELECT id FROM categories")]; sample = ["Wi-Fi not working in hostel", "Broken projector in Lab 3", "Library AC not working", "Canteen hygiene issue", "Bus arrives late daily", "Water leakage in corridor", "Exam timetable clash", "Street light out near gate"]
    for _ in range(35):
        t = datetime.fromtimestamp(time.time() - random.randint(0, 20) * 86400).strftime("%Y-%m-%d %H:%M"); st = random.choice(STATUSES)
        cid = ex("INSERT INTO complaints(student_id,category_id,title,description,priority,status,created,updated) VALUES(?,?,?,?,?,?,?,?)", random.randint(1, 6), random.choice(cats),
                 random.choice(sample), "This has been affecting students for several days and needs attention.", random.choice(PRIORITIES), st, t, t)
        ex("INSERT INTO updates(complaint_id,actor,status,note,created) VALUES(?,?,?,?,?)", cid, "You", "Pending", "Complaint submitted", t)

init_db()
if os.getenv("SEED"): seed()
if __name__ == "__main__": serve(port=int(os.getenv("PORT", 5001)))