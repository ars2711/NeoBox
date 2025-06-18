# NeoBox

NeoBox is your digital Swiss Army knife for productivity. Developed as my final project for **CS50x 2024** , NeoBox brings together a wide array of everyday tools into a single elegant web application. Whether you're a student, professional, or curious learner, NeoBox is designed to save you time, reduce clutter, and streamline your digital life.

---

## 🌟 Key Features

### ✅ Implemented Features

- **User Authentication**
  - Registration, login, logout
  - Password reset via email
  - Language & theme preferences
- **Productivity Tools**
  - Calculator
  - Unit Converter
  - Currency Converter (using live exchange rates)
  - Notes (persistent storage)
  - Pomodoro Timer
  - File Converter
  - Color Palette & Gradient Generator
- **User Experience**
  - Flash messaging
  - Theme toggler (light/dark)
  - Language switching (i18n)
  - Daily quotes and questions for motivation
  - Responsive design with Bootstrap 5
- **Security**
  - Hashed password storage
  - Session-based login system
  - Input validation and sanitation

### 🚀 Upcoming Tools (Planned)

> Already laid out in the structure but not yet active

- Weather Tool
- PDF Tools (merge, compress, etc.)
- QR Generator & Scanner
- AI Prompt Tool
- Voice to Text / Text to Speech
- Mind Map & Flowchart Tool
- To-Do Lists, Calendars, Reminders
- Health & Habit Trackers
- Stock Market Tracker
- Chatbot integration
- Many more... (see application.py code for full list)

---

## 🧠 Design Decisions

### Why Flask + SQLite?

Due to CS50's lectures and simply their simplicity and understanding - it made them such an easy choice.

### UI/UX

- Bootstrap 5.3 with custom CSS for a clean, minimal aesthetic.
- Responsive grid-based card layout for tools.
- Integrated dark mode with saved preferences via `localStorage`.

### User Data Handling

- Passwords hashed with Werkzeug's `generate_password_hash` (Inspired by CS50's Problem Set 9)
- Sessions securely managed using `flask-session`
- Email-based verification & reset via `Flask-Mail`

---

## 🛠 File Structure Overview

- `application.py` : Main Flask app, routing, models, logic
- `templates/` : All HTML templates (Jinja2)
- `static/` : Custom CSS, JS, logos, manifest
- `translations/` : `.po` and `.mo` files for i18n
- `helpers.py` : Utility functions (login_required, apology, etc.)
- `.env` : Environment variables (not committed/included)
- `requirements.txt` : Required packages
- `.gitignore` : Excludes sensitive/runtime files

---

## 🚧 Limitations

- Tool data and logs are not yet fully implemented
- Email templates are currently plain-text
- Heavy reliance on GitHub Copilot (see below)

---

## 🤖 About Copilot & Contributions

Large portions of this project were accelerated using **GitHub Copilot**, particularly during UI problems, recurring snippets, form handling, and code bugs. However, each section was manually reviewed, tested, and understood before integration.

> This project would not exist without CS50, but Copilot greatly improved development efficiency.

---

## 🧾 License

This project is licensed under the [MIT License](https://chatgpt.com/c/LICENSE).

---

## 🙏 Acknowledgements

- [CS50x](https://cs50.harvard.edu/x) by Harvard University & David Malan
- [Bootstrap 5](https://getbootstrap.com/)
- [Flask](https://flask.palletsprojects.com/)
- [Google OAuth](https://developers.google.com/identity)
- [Flask-Mail](https://pythonhosted.org/Flask-Mail/)
- [Undraw.co](https://undraw.co/) for illustrations
- GitHub Copilot
- ChatGPT

---

## 📦 Installation & Setup

```bash
l# Clone the repo
git clone https://github.com/yourusername/neobox.git
cd neobox

# Set up virtual environment
python3 -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows

# Install dependencies
pip install -r requirements.txt

# Set environment variables (create a .env file)
FLASK_APP=application.py
SECRET_KEY=your-secret
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-password
GOOGLE_CLIENT_ID=xxxxx
GOOGLE_CLIENT_SECRET=xxxxx

# Initialize the DB
flask shell
>>> from app import db
>>> db.create_all()
>>> exit()

# Run the app
flask run
```

---

## 📖 A Note from the Creator

Hey there! I'm Arsalan - the creator of **NeoBox**, and this web app has been my journey through learning and building with Flask, Python, and a whole lot of curiosity. NeoBox started off as just an idea for **CS50's Final Project**, but along the way, it grew to be way more and something that I thought many students and proffesionals alike would highly benefit from. While every programmer knows how to make a calculator, I thought of making something a _little_ more...

This project was never about writing perfect code. With the help of Github's Copilot (and some ChatGPT for general things), I was able to learn and write code more efficiently while being on the peak of my creative flow. I made sure to **understand**, **break**, and **fix** everything it suggested because after all; this was _my_ vision. And as I worked, I realized something powerful: building is learning, and sharing is growing, so I present this to you as a gift.

> "It ain't much but it's honest work."

Is NeoBox "done"? Not yet. But it's functional, ambitious, and built with love and that’s more than enough for me to hit submit proudly.

Thank you CS50 team for giving me a real reason to chase a dream I didn’t even know I had. This isn’t the end; it’s just the start.

> _Arsalan, 2025_

---

## 🙋‍♂️ Want to Contribute?

Pull requests are welcome. If you'd like to contribute a tool, feature, or language translation, open an issue or start a discussion!

---

## 💬 Final Notes

NeoBox is a long-term vision that started as a CS50 project but is slowly evolving into what one (I) can only dream of. While it’s far from perfect today, it’s sprouting to be even bigger and better. Thank you for checking it out!

---

> _"This is only the beginning."_
