"""
Django settings for myproject project.

Đã được tối ưu hóa cho môi trường Production trên Render.
"""

from pathlib import Path
import os
import dj_database_url # Thêm thư viện để cấu hình CSDL từ biến môi trường

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# --- CẤU HÌNH BẢO MẬT & MÔI TRƯỜNG (BẮT BUỘC) ---

# SECURITY WARNING: Lấy SECRET_KEY từ biến môi trường. 
# BẮT BUỘC phải đặt biến này trên Render!
SECRET_KEY = os.environ.get('SECRET_KEY', 'your-fallback-insecure-secret-key-for-local-dev')

# Lấy giá trị DEBUG từ biến môi trường (An toàn hơn cho Production)
DEBUG = os.environ.get('DEBUG', 'False') == 'True'

# Lấy danh sách HOSTS từ biến môi trường (Bao gồm domain .onrender.com)
# Sẽ hoạt động tốt nhất nếu bạn đặt ALLOWED_HOSTS là domain Render của bạn
ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', '127.0.0.1,localhost').split(',')
if RENDER_EXTERNAL_HOSTNAME := os.environ.get('RENDER_EXTERNAL_HOSTNAME'):
    ALLOWED_HOSTS.append(RENDER_EXTERNAL_HOSTNAME)


# --- APPLICATION DEFINITION ---

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'corsheaders', # THÊM: Cần cho django-cors-headers
    'myproject.scanner',
    # Thêm các apps khác (như djangorestframework) nếu bạn cài đặt chúng
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'corsheaders.middleware.CorsMiddleware', # THÊM: Đặt ngay sau SecurityMiddleware
    'whitenoise.middleware.WhiteNoiseMiddleware', # Phục vụ static files (Đã đúng)
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'myproject.urls'

# ... (TEMPLATES giữ nguyên) ...

WSGI_APPLICATION = 'myproject.wsgi.application'


# --- DATABASE (QUAN TRỌNG CHO RENDER) ---

# SỬA HOÀN TOÀN: Cấu hình CSDL để đọc biến môi trường DATABASE_URL của Render.
# Nếu biến không tồn tại (chạy cục bộ), nó sẽ quay về dùng SQLite.
DATABASES = {
    'default': dj_database_url.config(
        default=f'sqlite:///{BASE_DIR / "db.sqlite3"}',
        conn_max_age=600,
        conn_health_check=True
    )
}

# ... (Password validation, Internationalization giữ nguyên) ...

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True


# --- STATIC FILES VÀ WHITENOISE ---

# Cấu hình Whitenoise và Static files đã đúng
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / "staticfiles" 

STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage" 


# --- CẤU HÌNH CORS VÀ CSRF ---

# Cấu hình CORS: Bạn phải chỉ định rõ miền Frontend của mình để bảo mật
# Thay vì CORS_ALLOW_ALL_ORIGINS = True, hãy dùng danh sách dưới đây:
CORS_ALLOWED_ORIGINS = [
    # 'https://ten-mien-frontend-cua-ban.onrender.com', 
    # 'http://localhost:3000', # Cho phát triển cục bộ
    # Thêm các miền khác nếu cần
]

# Nếu bạn đang test và chưa biết domain frontend, hãy tạm bật:
# CORS_ALLOW_ALL_ORIGINS = True

CSRF_TRUSTED_ORIGINS = ['https://*.onrender.com'] # Đã đúng

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'