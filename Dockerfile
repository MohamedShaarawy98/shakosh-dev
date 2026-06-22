# استخدام بيئة بناء مستقرة ومحدثة
FROM ubuntu:22.04

# منع طلب أي تداخل أثناء التثبيت
ENV DEBIAN_FRONTEND=noninteractive

# تحديث السيرفر وتثبيت أدوات المترجم ومكتبات التشفير وقاعدة البيانات
RUN apt-get update && apt-get install -y \
    g++ \
    make \
    libssl-dev \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# تحديد مجلد العمل
WORKDIR /app

# نسخ الكود بالكامل
COPY . .

# أمر بناء الكود الشامل لجميع مكتبات الاتصال الآمن وقاعدة البيانات (مهم جداً)
RUN g++ -O3 main.cpp -o server -lssl -lcrypto -lpq -pthread

# فتح منفذ السيرفر
EXPOSE 8080

# تشغيل السيرفر
CMD ["./server"]
