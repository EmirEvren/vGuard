# Tek BAT + KVM Lab Dashboard

Tek çalıştırman gereken Windows dosyası:

```bat
VGUARD_ONE_CLICK_ALL_WINDOWS.bat
```

Bu tek dosya kurulum, patch, frontend build, dashboard, honeypot, engine watchdog, demo/export işlerini yapar.

Dashboard sekmeleri:

- Validation
- KVM Lab

## KVM Lab

Windows üzerinde Mininet/KVM doğrudan çalışmaz. KVM Lab sekmesi admin için lab durumunu, Linux komutlarını ve artifact downloadlarını gösterir.

Gerçek KVM/Mininet lab için Linux VM'de:

```bash
sudo RUN_MININET=1 ./run_vguard_final_all_in_one_linux.sh
```
