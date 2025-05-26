# NeoBox

> Your all-in-one productivity toolkit — Swiss Army Knife for the web. Built as a CS50 Final Project.

NeoBox is a sleek, modern, and powerful web app that consolidates dozens of everyday tools into one unified platform. Whether you're a student, professional, or just someone who loves productivity, NeoBox is your companion for staying organized, focused, and efficient.

![NeoBox Screenshot](https://your-screenshot-link.com/)

---

## 🎓 CS50 Final Project

This project was created as part of **CS50 — Harvard University's Introduction to Computer Science** . It reflects months of learning, experimenting, building, and dreaming.

**Note on Assistance:**

Some parts of this project were developed using **GitHub Copilot** and **ChatGPT** for generating ideas, boilerplate code, and enhancing functionality. All code was reviewed, customized, and authored by me (Arsalan), in full accordance with CS50's [Academic Honesty Policy](https://cs50.harvard.edu/x/2024/honesty/).

---

## 🔧 Features

### ✅ Core Functionality

- 🧮 Calculator
- 🔁 Unit Converter
- 💱 Currency Converter
- 📝 Notes
- 🛠️ Tools Directory with Live Search
- ☁️ Cloud Sync for Registered Users
- 🌐 Google Login Integration
- 🔐 Secure User Authentication (Password & OAuth)
- 🎨 Light/Dark Theme Toggle with Persistence
- 🌍 Multilingual Support (English, Urdu, Arabic, Español)
- ✉️ Email Notifications (Password Reset, Account Verification)
- 🔔 Notifications System (Admin/User)
- 📊 Admin Panel

---

## 🧠 Upcoming Tools (planned)

NeoBox is constantly evolving. Here's what we're cooking up:

| Name                  | Description                  |
| --------------------- | ---------------------------- |
| File Converter        | Convert between file formats |
| AI Chatbot            | Interact with AI responses   |
| Image Tools           | Crop, Resize, Compress       |
| PDF Tools             | Merge, Split, Annotate       |
| Flashcards            | Study smarter                |
| Pomodoro Timer        | Stay focused in bursts       |
| Habit Tracker         | Build lasting habits         |
| Budget Tracker        | Track finances easily        |
| World Clock & Planner | Schedule meetings globally   |
| Voice Tools           | Text-to-speech & vice versa  |
| Color Tools           | Gradient/Palette Generator   |

_(+ over 50 more upcoming mini-tools!)_

---

## 🛠️ Tech Stack

- **Backend:** Python, Flask, SQLAlchemy, SQLite
- **Frontend:** HTML, CSS, Bootstrap, JavaScript
- **Auth:** Google OAuth2, Flask-Session, Werkzeug
- **Localization:** Flask-Babel
- **Email:** Flask-Mail (Gmail SMTP)
- **PWA Ready:** Coming soon 🚀

---

## 🚀 Running Locally

### Prerequisites

- Python 3.10+
- `pipenv` or `venv`
- Node.js (optional, for frontend builds)

### Setup

```bash
# Clone the repo
$ git clone https://github.com/ars2711/neobox.git
$ cd neobox

# Create virtual environment
$ python3 -m venv .venv
$ source .venv/bin/activate  # or .venv\Scripts\activate on Windows

# Install dependencies
$ pip install -r requirements.txt

# Set up environment variables (create .env file)
SECRET_KEY=your-secret-key
MAIL_USERNAME=your@gmail.com
MAIL_PASSWORD=your-password
GOOGLE_CLIENT_ID=your-client-id
GOOGLE_CLIENT_SECRET=your-client-secret

# Run the app
$ flask run
```

---

## 🌍 Deployment

- Can be deployed to **Render** , **Vercel (via FastAPI Gateway)** , **Heroku** , or **Replit** .
- Supports SQLite but can be upgraded to PostgreSQL easily.

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork this repo
2. Create a branch (`feature/awesome`)
3. Commit your changes
4. Push & open a PR

---

## 📜 License

MIT License © Arsalan — [@ars2711](https://github.com/ars2711)

---

## 💡 Inspiration

NeoBox was born from a simple idea: **"One place for everything useful on the web."**

Inspired by tools like Notion, Google Keep, and online converters, but built to be privacy-focused, distraction-free, and totally yours.

> “If you’re building the future, why not make it beautiful, helpful, and open-source?”

---

## 🧠 Want to Learn More?

- CS50: [cs50.harvard.edu/x](https://cs50.harvard.edu/x)
- Flask: [https://flask.palletsprojects.com/](https://flask.palletsprojects.com/)
- Bootstrap: [https://getbootstrap.com/](https://getbootstrap.com/)
- Babel: [https://python-babel.github.io/](https://python-babel.github.io/)

---

_This project was built with passion, curiosity, and a lot of midnight coffee. Thanks to CS50 for making computer science feel like art._
