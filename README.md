# 🔐 Python Encrypter

**A Telegram bot that locks your Python code and only unlocks it when you approve.**

You send the bot a `.py` or `.zip` file. It gives you back a locked file you can
hand to anyone. When that file runs on their machine, **you** get an
Approve / Reject button on Telegram. Nothing runs until you tap it.

---

## What it does

- 🔒 **Locks your code** — the key is never inside the file you give away.
- 📲 **Asks you first** — every run sends you an Approve / Reject button.
- ⏱️ **30-second window** — no answer means it stops by itself.
- 🚫 **Kill switch** — ban a user or delete the key and their file dies.
- ⏳ **Auto expiry** — every licence ends by itself after 7 days.
- 📊 **Daily quota** — 5 files per user per day, you can change it.
- 📦 **Whole folders** — send a `.zip` and every file inside is protected.
- 🛠️ **Admin panel** — status, ban list, limits, broadcast, force-subscribe.

---

## How it works

```
   YOU / CUSTOMER                 THE BOT                    FIREBASE
        │                            │                          │
        │  send project.py  ───────► │                          │
        │                            │  makes a key             │
        │                            │  keeps the key  ───────► │  stores key
        │  ◄───── locked file ────── │  (key NOT in the file)   │
        │                            │                          │
        │  run locked file                                      
        │  asks the server  ───────────────► you get a Telegram DM
        │  ◄──────────── you tap ✅ Approve ───────────────
        │  key comes back, code runs                            
```

**Three parts do the work:** the **bot** shows you the button, the **server**
hands out the key, and the **database** keeps the key safe. Remove any one of
them and the Approve button stops working.

---

## Setup (5 steps)

1. **Get a bot token** — message `@BotFather` on Telegram, run `/newbot`, copy the token.
2. **Get your admin ID** — message `@userinfobot`, copy the number.
3. **Create a Firebase database** — [console.firebase.google.com](https://console.firebase.google.com)
   → Realtime Database → copy the URL.
4. **Fill in your settings** — copy `.env.example` to `.env` and put your values in.
   **Never share this file.**
5. **Start it**
   ```bash
   pip install -r requirements.txt
   python bot.py
   ```
   Then host `api/index.py` on Vercel (or any host) and put that URL in `API_SERVER_URL`.

**Requirements:** Python 3.9+ · `pip install -r requirements.txt` · internet on the
customer's side, every time the file runs.

---

## ✅ Advantages

| | In plain words |
|---|---|
| **Your code stays hidden** | Customers get a locked file, not your source. |
| **You decide who runs it** | Nothing starts without your tap. |
| **You can switch it off** | Ban a user or delete the key — instantly dead. |
| **Licences expire by themselves** | 7 days, automatic, no work for you. |
| **Limits stop abuse** | 5 files per day per user, adjustable. |
| **Folders work** | Send a whole project as a zip, not just one file. |
| **You get a real admin panel** | Users, bans, limits, broadcast — all from chat. |
| **No app to install** | It's just Telegram, on your phone. |

---

## ⚠️ Problems — please read these honestly

| | In plain words |
|---|---|
| **A skilled person can still copy your code** | Any Python file that runs on someone else's machine can be copied by them. About 9 lines of code is enough. This is true of every pure-Python tool, including this one. |
| **It needs internet, always** | No server = code will not run. Your server being down stops your customers. |
| **Your server is the weak point** | If it leaks, every key is out. Rate limiting is not included by default. |
| **Secrets in the wrong place are fatal** | Your bot token and database secret are the keys to everything. Leak them and the whole system is open. |
| **Admin decrypt shows the key in chat** | The key is printed in the Telegram message. Delete those messages. |
| **Zipped projects can't be recovered** | If the database record is lost, the owner cannot get a zipped project back. |
| **Zipped projects can't read extra files** | Files like `config.json` or templates inside the zip are not available at runtime. |
| **7 days only** | Licences die after 7 days by design. Change this if you need longer. |

### The one-sentence truth

> This is a **lock and a remote switch**, not a vault.
> It stops casual copying. It does not stop a determined person.

That is still useful — people pay to be able to switch something off — but sell
it honestly and you will keep your customers.

---

## 🔐 Security checklist before you go live

- [ ] `.env` is **never** committed, zipped, or screenshotted
- [ ] `.gitignore` includes `.env`
- [ ] Bot token is fresh (revoke any token that was ever shared)
- [ ] Firebase is protected with **Security Rules**, not a public secret
- [ ] `ADMIN_ID` is your private account, not a shared one
- [ ] Add rate limiting to `POST /api/get-key`
- [ ] Delete Telegram messages that contain decryption keys

---

## Files

```
pyencrypt/
├── bot.py               Telegram bot: upload flow, encryption, admin panel
├── api/index.py         FastAPI server: approval requests + key delivery
├── database.py          Firebase Realtime Database client
├── models.py            Database schema and queries
├── requirements.txt     Dependencies
├── vercel.json          Deployment config
├── .env.example         Settings template  ← copy to .env and fill in
└── README.md            This file
```

---

## Commands

**Everyone:** `/start` · `/help`

**Admin only:**
`/status` `/banlist` `/ban <id>` `/unban <id>` `/limit <id> <n>` `/setdefault <n>`
`/userstatus <id>` `/resetuser <id>` `/delete <file_id>` `/broadcast <text>`
`/add <channel_id> <link> <name>` `/remove <channel_id>` `/list`

---

*Built with Python, aiogram and FastAPI. Use it responsibly and tell your
customers what it can and cannot do.*
