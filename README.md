# MTProto Proxy Server с обходом DPI через реальный веб-сайт

MTProto прокси-сервер на Python, который маскируется под обычный HTTPS веб-сайт.
При попытке доступа из браузера или при обнаружении DPI проверки, сервер
проксирует запрос на **реальный веб-сайт** (например, Wikipedia).

## Особенности

- 🔒 **Полное TLS/SSL шифрование** - порт 443 (стандартный HTTPS)
- 🌐 **Реальный веб-сайт** - при доступе из браузера открывается настоящий сайт
- 🛡️ **Обход DPI** - системы глубокой проверки видят реальный HTTPS трафик
- 🎭 **SNI поддержка** - определение домена из ClientHello
- 📡 **MTProto 2.0** - нативная поддержка Telegram
- ⚡ **Асинхронная архитектура** - высокая производительность

## Как это работает

### Определение типа трафика

```
                    Входящее соединение (порт 443)
                              │
                              ▼
                    ┌─────────────────┐
                    │  Анализ первых  │
                    │  байтов данных  │
                    └────────┬────────┘
                             │
         ┌───────────────────┼───────────────────┐
         │                   │                   │
         ▼                   ▼                   ▼
   ┌───────────┐       ┌───────────┐       ┌───────────┐
   │  Браузер  │       │ Telegram  │       │   DPI     │
   │  (HTTP)   │       │ (MTProto) │       │  (Probe)  │
   └─────┬─────┘       └─────┬─────┘       └─────┬─────┘
         │                   │                   │
         ▼                   ▼                   ▼
   ┌───────────┐       ┌───────────┐       ┌───────────┐
   │  Реальный │       │ Telegram  │       │  Реальный │
   │  сайт     │       │  Сервер   │       │  сайт     │
   │ (Wikipedia)│      │           │       │ (Wikipedia)│
   └───────────┘       └───────────┘       └───────────┘
```

### Сценарии использования

| Тип подключения | Поведение |
|-----------------|-----------|
| **Веб-браузер** | Проксирует на www.wikipedia.org (или другой сайт) |
| **Telegram клиент** | Проксирует на серверы Telegram |
| **DPI сканирование** | Возвращает контент реального сайта |
| **Неизвестный трафик** | Проксирует на реальный сайт (безопасно) |

## Установка

### Быстрая установка

```bash
cd /home/aiagent/mtproto-proxy

# Установка зависимостей
pip install -r requirements.txt

# Генерация конфигурации
python3 generate_config.py

# Запуск (требуется root для порта 443)
sudo python3 mtproto_proxy.py
```

### Автоматическая установка

```bash
# Запуск скрипта установки
sudo ./install.sh

# Или вручную:
bash install.sh
```

### Настройка прав для порта 443 (без root)

```bash
# Дать Python право bind на порт 443
sudo setcap 'cap_net_bind_service=+ep' $(which python3)

# Теперь можно запускать без sudo
python3 mtproto_proxy.py
```

## Конфигурация

### config.json

```json
{
  "proxy": {
    "host": "0.0.0.0",
    "port": 443,
    "secret": "ваш-секретный-ключ"
  },
  "tls": {
    "cert_path": "cert.pem",
    "key_path": "key.pem"
  },
  "telegram": {
    "host": "149.154.167.50",
    "port": 443
  },
  "dpi_bypass": {
    "enabled": true,
    "real_website_host": "www.wikipedia.org",
    "real_website_port": 443,
    "fake_domain": "www.wikipedia.org",
    "timeout": 2.0
  }
}
```

### Рекомендуемые сайты для маскировки

| Сайт | Преимущества |
|------|--------------|
| `www.wikipedia.org` | Легитимный, высокий трафик, не блокируется |
| `www.cloudflare.com` | CDN, выглядит как обычный трафик |
| `www.mozilla.org` | Доверенный сайт, HTTPS |
| `www.example.com` | Простой, лёгкий |

## Telegram Data Centers

| Регион | Адрес | Порт |
|--------|-------|------|
| Европа | 149.154.167.50 | 443 |
| Азия | 149.154.175.50 | 443 |
| США | 149.154.161.50 | 443 |

## Запуск в Docker

```bash
# Сборка образа
docker build -t mtproto-proxy .

# Запуск контейнера
docker run -d \
  --name mtproto-proxy \
  -p 443:443 \
  --restart unless-stopped \
  mtproto-proxy
```

## Установка как systemd сервис

```bash
# Копирование сервиса
sudo cp mtproto-proxy.service /etc/systemd/system/

# Включение и запуск
sudo systemctl daemon-reload
sudo systemctl enable mtproto-proxy
sudo systemctl start mtproto-proxy

# Проверка статуса
sudo systemctl status mtproto-proxy

# Просмотр логов
sudo journalctl -u mtproto-proxy -f
```

## Настройка клиента Telegram

### Telegram Desktop

1. Откройте **Settings** → **Advanced** → **Connection Type**
2. Выберите **Use Custom Proxy**
3. Выберите **MTProto Proxy**
4. Введите параметры:
   - **Host**: ваш-домен.com
   - **Port**: 443
   - **Secret**: секрет из config.json

### Telegram Android/iOS

Используйте ссылку для быстрого подключения:

```
https://t.me/proxy?server=ваш-домен.com&port=443&secret=ваш-секрет
```

## Проверка работы

### 1. Проверка веб-доступа

Откройте в браузере:
```
https://ваш-сервер.com/
```

Должен открыться **реальный сайт** (Wikipedia или другой настроенный).

### 2. Проверка MTProto

Подключитесь через Telegram клиент с настройками прокси.

### 3. Проверка DPI обхода

```bash
# Эмуляция DPI probe (неполный TLS handshake)
echo -n -e '\x16\x03\x01' | openssl s_client -connect ваш-сервер:443

# Должен вернуться контент реального сайта
```

## Безопасность

### Рекомендации

1. **Используйте реальный SSL сертификат** от Let's Encrypt:

```bash
sudo apt install certbot
sudo certbot certonly --standalone -d ваш-домен.com
```

2. **Настройте firewall**:
```bash
sudo ufw allow 443/tcp
sudo ufw enable
```

3. **Регулярно меняйте секрет**:
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

4. **Мониторьте логи**:
```bash
sudo journalctl -u mtproto-proxy -f
```

## Мониторинг

### Активные подключения
```bash
sudo netstat -an | grep :443
```

### Использование ресурсов
```bash
htop -p $(pgrep -f mtproto_proxy)
```

### Статистика подключений
```bash
# Просмотр логов в реальном времени
sudo journalctl -u mtproto-proxy -f | grep -E '\[MTProto\]|\[Web\]|\[DPI\]'
```

## Устранение неполадок

### Ошибка: Permission denied (порт 443)

```bash
# Вариант 1: Запуск от root
sudo python3 mtproto_proxy.py

# Вариант 2: setcap
sudo setcap 'cap_net_bind_service=+ep' $(which python3)
python3 mtproto_proxy.py
```

### Ошибка: Certificate not found

```bash
# Перегенерировать сертификат
python3 -c "from mtproto_proxy import TLSContextManager; TLSContextManager.generate_self_signed_cert('cert.pem', 'key.pem')"
```

### Медленное соединение

1. Проверьте пинг до сервера Telegram:
```bash
ping 149.154.167.50
```

2. Попробуйте другой DC в config.json

3. Проверьте нагрузку на сервер:
```bash
top -u root
```

## Архитектура

```
┌─────────────────────────────────────────────────────────────────┐
│                     MTProto Proxy Server                        │
│                         (Порт 443)                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │ SNI Parser  │  │ DPI Detector│  │ MTProto Detector        │ │
│  └──────┬──────┘  └──────┬──────┘  └───────────┬─────────────┘ │
│         │                │                      │               │
│         ▼                ▼                      ▼               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │ Real Website│  │ Real Website│  │   Telegram Relay        │ │
│  │   Proxy     │  │   Proxy     │  │   (MTProto → DC)        │ │
│  │ (Wikipedia) │  │ (Wikipedia) │  │                         │ │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘ │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Лицензия

MIT License - свободное использование и модификация.

## Предупреждение

Используйте этот прокси ответственно и в соответствии с законодательством вашей страны.
Авторы не несут ответственности за неправильное использование данного ПО.

## Благодарности

- MTProto протокол - Telegram
- Идея DPI bypass - сообщество обхода цензуры
