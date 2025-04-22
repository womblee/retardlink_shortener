# 🔗 RetardLink - Minimalist URL Shortener  
*A lightweight, self-hosted URL shortener built with PHP & MySQL. No accounts, no bloat—just short links.*  

<img src="https://github.com/user-attachments/assets/51ba61ad-70d7-4ede-9e36-24560957f5e9?raw=true" alt="Dashboard" width="70%" />

## ✨ Features  
✔ **Anonymous** – No login required  
✔ **Passwords** – Add passwords to your URLs  
✔ **CRUD Operations** – Create, edit, or delete links anytime  
✔ **Minimalist Design** – Zero bloat, maximum efficiency  
✔ **Self-Hosted** – Full control over your data  

## 🖥️ Showcase  
<div align="left">
  <img src="https://github.com/user-attachments/assets/51ba61ad-70d7-4ede-9e36-24560957f5e9" alt="Dashboard" width="50%" />
  <br>
  <img src="https://github.com/user-attachments/assets/38b91d40-efe3-478b-aa60-760abbd741bb" alt="Link Management" width="50%" />
  <br>
  <img src="https://github.com/user-attachments/assets/789987a1-bc66-4e9a-8179-14f2a20b4206" alt="Edit Interface" width="50%" />
  <br>
  <img src="https://github.com/user-attachments/assets/f4b4ad9c-d1bd-4610-bb94-9ba22af45d99" alt="Mobile View" width="50%" />
</div>

## 🛠️ Installation  
### 1. Configure  
```bash
# Edit the config file
nano config.php  # Set your DB credentials and base URL
```
### 2. Database setup
```bash
mysql -u root -p < db.sql  # Import the schema
```
### 3. Server prep (Apache)
```bash
mv htaccess.file .htaccess  # Enable clean URLs
```

### 4. Directory Note
ℹ If installed in a subdirectory (e.g., `/ls/`), update paths in:

- `.htaccess`
- `config.php`

## 🚀 Usage
Just deploy and start shortening! No complex setup.
