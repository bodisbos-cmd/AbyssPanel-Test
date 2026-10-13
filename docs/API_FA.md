# راهنمای API پنل Abyss Tunnel

این API برای اتصال ربات تلگرام یا سرویس فروش به پنل است. آدرس پایه همان دامنه HTTPS پنل است. تمام درخواست‌های ربات باید با کلید API ساخته‌شده در داشبورد احراز هویت شوند.

## امنیت کلید
- کلید را از داشبورد در بخش «API و اتصال ربات» بساز.
- کلید کامل فقط یک بار نشان داده می‌شود؛ آن را در متغیر محیطی امن ربات نگه دار.
- کلید را در کد منبع، GitHub، پیام عمومی یا گزارش خطا قرار نده.
- برای ربات، فقط مجوزهای لازم را انتخاب کن. کلید قابل لغو است.
- احراز هویت: Authorization: Bearer YOUR_API_TOKEN

## مسیرها
همه پاسخ‌ها JSON هستند. شناسه مشتری UUID است.

| Method | Path | Permission | کار |
|---|---|---|---|
| GET | /api/v1/health | clients:read | بررسی کلید و API |
| GET | /api/v1/clients | clients:read | فهرست مشتریان و مصرف/اعتبار |
| POST | /api/v1/clients | clients:write | ساخت مشتری |
| PATCH | /api/v1/clients/{id} | clients:write | تغییر نام، یادداشت، فعال‌بودن، مدت یا حجم |
| DELETE | /api/v1/clients/{id} | clients:write | حذف دسترسی و سرویس |
| POST | /api/v1/clients/{id}/reset-usage | clients:write | صفرکردن مصرف ثبت‌شده |
| GET | /api/v1/clients/{id}/subscription | subscriptions:read | دریافت لینک صفحه، اشتراک و QR |

## ساخت مشتری
درخواست POST /api/v1/clients:
~~~json
{
  "name": "Customer 123",
  "duration_days": 30,
  "quota_gb": 20,
  "note": "Telegram order 123"
}
~~~
- name اجباری و حداکثر ۶۴ نویسه است.
- duration_days اختیاری و عدد صحیح ۱ تا ۳۶۵۰ است؛ حذف یا null یعنی بدون انقضا.
- quota_gb اختیاری و از ۱ تا ۱۰۰۰۰۰ گیگابایت است؛ حذف یا null یعنی نامحدود.
- note اختیاری و حداکثر ۳۰۰ نویسه است.
- پاسخ شامل id، subscription_url و subscription_page_url است. لینک اشتراک را فقط به خریدار همان سرویس بده.

## نمونه cURL
~~~sh
curl -H "Authorization: Bearer $ABYSS_API_TOKEN" \
  https://YOUR-PANEL-DOMAIN/api/v1/clients
~~~

ساخت مشتری:
~~~sh
curl -X POST \
  -H "Authorization: Bearer $ABYSS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Customer 123","duration_days":30,"quota_gb":20}' \
  https://YOUR-PANEL-DOMAIN/api/v1/clients
~~~

### تمدید و تغییر حجم
برای تمدید سرویس یا تغییر سهمیه، به PATCH همان مشتری درخواست بده. مثال:
~~~json
{
  "duration_days": 30,
  "quota_gb": 50
}
~~~
مقادیر بر اساس زمان فعلی دوباره محاسبه می‌شوند. ارسال null برای duration_days یا quota_gb به‌ترتیب انقضا یا سقف حجم را نامحدود می‌کند. برای صفرکردن مصرف از POST /api/v1/clients/{id}/reset-usage استفاده کن؛ این کار آمار مصرف را ریست می‌کند و مصرف واقعی قبلی را از گزارش پنل حذف می‌کند.

## کدهای خطا
- 401: کلید نامعتبر، لغوشده یا ارسال‌نشده.
- 403: مجوز کافی برای این مسیر وجود ندارد.
- 404: مشتری/کلید پیدا نشد.
- 422: داده ارسالی معتبر نیست.
- 429: محدودیت درخواست در بازه زمانی اعمال شده.
- 503: هسته Xray نتوانسته تغییر را اعمال کند.

## محدودیت مهم
این API جایگزین API داخلی Xray نیست و فعلاً مدیریت یک پنل و یک مدیر اصلی را هدف می‌گیرد. برای عملیات حساس، نتیجه هر درخواست را بررسی کن؛ صرفاً دریافت HTTP 200 از ربات را موفقیت فروش تلقی نکن.
