# SecurePass - Secure Password Manager

A secure, web-based password manager built with Flask, SQLAlchemy, and AES encryption.

## Features

- **Secure Password Storage**: AES-256 encryption for all stored passwords
- **User Authentication**: Secure login/registration with bcrypt hashing
- **Password Generation**: Built-in strong password generator
- **Audit Logging**: Complete activity tracking for security
- **Admin Panel**: User management and system monitoring
- **Responsive UI**: Clean, modern web interface

## Quick Start

### Local Development

1. **Clone the repository**
   ```bash
   git clone <your-repo-url>
   cd securepass
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**
   ```bash
   python app.py
   ```

4. **Access the app**
   - Open http://localhost:5000
   - Default admin login: `admin` / `Admin@123`

### Deployment

#### Option 1: Render (Recommended)

1. **Create a Render account** at https://render.com

2. **Connect your GitHub repository**
   - Push your code to GitHub first
   - Link your GitHub repo to Render

3. **Create a new Web Service**
   - Runtime: Python 3
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `python app.py`

4. **Environment Variables** (optional):
   - `SECRET_KEY`: Random secret key for sessions
   - `DATABASE_URL`: Will be set automatically by Render

#### Option 2: Railway

1. **Create a Railway account** at https://railway.app

2. **Deploy from GitHub**
   - Connect your GitHub repository
   - Railway will auto-detect Python and install dependencies

3. **Set environment variables** if needed

#### Option 3: Heroku

1. **Install Heroku CLI**

2. **Deploy**
   ```bash
   heroku create your-app-name
   git push heroku main
   ```

## Project Structure

```
securepass/
├── app.py                 # Main Flask application
├── models.py             # Database models
├── crypto_utils.py       # Encryption utilities
├── requirements.txt      # Python dependencies
├── Procfile             # Heroku/Render deployment
├── runtime.txt          # Python version for deployment
├── .gitignore           # Git ignore rules
├── templates/           # HTML templates
│   ├── base.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   └── ...
└── static/              # Static files (CSS, JS, images)
```

## Security Features

- **AES-256 Encryption**: All passwords encrypted before storage
- **bcrypt Hashing**: Secure password hashing for user accounts
- **Session Management**: Secure Flask-Login sessions
- **Audit Logging**: All user actions logged for monitoring
- **CSRF Protection**: Built-in Flask-WTF protection
- **SQL Injection Prevention**: SQLAlchemy ORM protection

## API Endpoints

- `GET /api/generate-password?length=16` - Generate strong password
- `POST /credential/add` - Add new credential
- `GET /credential/view/<id>` - View credential
- `POST /credential/edit/<id>` - Edit credential
- `POST /credential/delete/<id>` - Delete credential

## Default Credentials

- **Admin User**: `admin` / `Admin@123`
- Change the default password after first login!

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is open source and available under the MIT License.
