# v-Guard Linux Tek Dosya Runner

Knk Linux tarafında Windows BAT gibi tek dosya:

```bash
chmod +x VGUARD_ONE_CLICK_ALL_LINUX.sh
./VGUARD_ONE_CLICK_ALL_LINUX.sh
```

Gerçek NFQUEUE/DPI için sudo önerilir:

```bash
sudo ./VGUARD_ONE_CLICK_ALL_LINUX.sh
```

KVM/Mininet lab dahil çalıştırmak için:

```bash
sudo RUN_MININET=1 ./VGUARD_ONE_CLICK_ALL_LINUX.sh
```

Script şunları yapar:

- `.venv` oluşturur
- Python paketlerini kurar
- Linux NFQUEUE için apt paketlerini dener
- patchleri uygular
- React build alır, npm yoksa mevcut dist ile devam eder
- dashboard başlatır
- honeypot başlatır
- engine watchdog başlatır
- demo/export çalıştırır
- dashboard’u tarayıcıda açar

Loglar:

```text
launcher_logs/linux_oneclick_last_run.log
launcher_logs/dashboard.log
launcher_logs/dpi_engine.log
launcher_logs/engine_watchdog.log
```

Dashboard:

```text
http://127.0.0.1:5000/login
```
