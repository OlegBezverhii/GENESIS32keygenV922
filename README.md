## Readme
А че тут говорить - название говорит само за себя. Файловый генератор лицензий на базе CryptKey V7.7 (с правками для ICONICS).
Данная информация представлена в ознакомительных целях и не является руководством к действиям.

Полностью автономный скрипт — один файл, внутри всё:

- mailslot-клиент NGN (handshake, InitCrypkey, GetSiteCode, SaveSiteKey, Set/GetCustomInfoBytes);
- транспорт (CRC16, XOR-поток, hex);
- кодек ключей v5 (decrypt/encrypt/CRC, build_key);
- перебор siteCodeId при установке ключа;
- раскладка 86 полей → 500 байт custom info;
- парсинг/сборка .glic + CRC32 + подбор токена (на будущее);
- запись SiteKey.txt.
Импорты — только стандартные (argparse, ctypes, os, re, struct, subprocess, time). 

Запуск:

python ck_activate.py                 # всё сразу с дефолтами

python ck_activate.py --list-fields

python ck_activate.py --client-units 5000 --product-limit 1000000

python ck_activate.py --field 24=5000 --field 25=0x00DB0040

python ck_activate.py --glic "C:\Analiz\genesis\demo.glic"

python ck_activate.py --dry-run

python ck_activate.py --no-start      # сервер уже запущен
