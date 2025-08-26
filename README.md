```markdown
# ROCS WinSAT Tron v3.7

Zaawansowany skrypt diagnostyczno-bezpieczeństwowy w stylu cyberpunk, przeznaczony do kompleksowej analizy wydajności i bezpieczeństwa systemów Windows.

## 🚀 Funkcje

- **Diagnostyka Wydajności**: Kompleksowy skan WinSAT z oceną komponentów systemowych
- **Analiza Bezpieczeństwa**: Monitoring stanu Windows Defender, procesów i dysków
- **Integracja z VirusTotal**: Sprawdzanie plików i adresów IP pod kątem złośliwego oprogramowania
- **Monitoring Sieci**: Analiza aktywnych połączeń sieciowych i wykrywanie anomalii
- **Raporty HTML/JSON**: Generowanie szczegółowych raportów z wykresami i zaleceniami
- **Powiadomienia Email**: Alerty bezpieczeństwa wysyłane przez SMTP
- **Automatyczne Aktualizacje**: System aktualizacji Windows i aplikacji via Winget
- **Planowanie Zadań**: Konfiguracja automatycznych skanów przez Task Scheduler

## 📋 Wymagania

- Windows 10/11 z uprawnieniami administratora
- PowerShell 5.1 lub nowszy
- Dostęp do Internetu (dla funkcji VirusTotal i aktualizacji)
- Moduły PowerShell: `PSWindowsUpdate`, `MicrosoftDefender`

## ⚙️ Konfiguracja

### Instalacja modułów
```powershell
Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser
Install-Module -Name MicrosoftDefender -Force -Scope CurrentUser
```

### Pierwsze uruchomienie
1. Pobierz klucz API z [VirusTotal](https://www.virustotal.com/)
2. Skonfiguruj ustawienia SMTP w pliku `CyberPunk_Config.json`
3. Uruchom skrypt jako administrator

## 🎮 Użycie

### Podstawowe uruchomienie
```powershell
.\ROCS_WinSAT_Tron.ps1
```

### Pełny skan z wymuszeniem WinSAT
```powershell
.\ROCS_WinSAT_Tron.ps1 -FullScan
```

### Z własną ścieżką konfiguracji
```powershell
.\ROCS_WinSAT_Tron.ps1 -ConfigPath "D:\sciezka\do\config.json"
```

## 📊 Menu Główne

Skrypt oferuje interaktywne menu z opcjami:
1. **Skan wydajności** - Test WinSAT komponentów systemu
2. **Skan bezpieczeństwa** - Analiza Defender, procesów i dysków
3. **Skan błędów** - Przegląd logów systemowych
4. **Aktualizacje** - Aktualizacja systemu i aplikacji
5. **Sterowniki** - Weryfikacja aktualności sterowników
6. **Sieć** - Monitoring połączeń sieciowych
7. **Planowanie** - Konfiguracja zaplanowanych skanów
8. **Raport** - Generowanie raportu HTML
9. **Wszystkie** - Pełny skan kompleksowy
10. **Wyjście** - Zakończenie pracy skryptu

## 🔧 Konfiguracja Zaawansowana

Plik `CyberPunk_Config.json` pozwala skonfigurować:
- Klucz API VirusTotal (szyfrowany)
- Ustawienia serwera SMTP do powiadomień
- Progi alarmowe dla CPU i wykryć złośliwego oprogramowania
- Adresy email do alertów

## 📈 Przykładowe Wyjście

Skrypt generuje kolorowe, szczegółowe raporty w konsoli oraz:
- Pliki HTML z interaktywnymi wykresami
- Pliki JSON z pełnymi danymi skanu
- Logi błędów w formacie tekstowym
- Raporty CSV z błędami systemowymi

## 🛡️ Bezpieczeństwo

- Wszystkie połączenia API wykorzystują HTTPS
- Klucze API są szyfrowane i przechowywane bezpiecznie
- Skrypt wymaga potwierdzenia dla krytycznych operacji
- Implementowane są limity zapytań API

## ⚠️ Uwagi

- Skrypt wymaga uprawnień administratora dla pełnej funkcjonalności
- Niektóre funkcje mogą wymagać dodatkowej konfiguracji
- Integracja z VirusTotal podlega limitom API
- Automatyczne aktualizacje wymagają potwierdzenia użytkownika

## 📞 Wsparcie

W przypadku problemów lub pytań dotyczących skryptu, prosimy o kontakt przez repozytorium GitHub lub bezpośrednio z ROCyber Solutions.

---

**Powered by ROCyber Solutions** | *Wersja 3.7 - Neonowy Rdzeń*
```

Ten plik README:
1. Jest w języku polskim zgodnie z życzeniem
2. Zawiera wszystkie istotne informacje o skrypcie
3. Jest formatowany w profesjonalny sposób z użyciem emoji i sekcji
4. Wyjaśnia wszystkie główne funkcje skryptu
5. Zawiera instrukcje instalacji i użycia
6. Wspomina o wymaganiach i ograniczeniach
7. Zachowuje cyberpunkowy styl nazewnictwa
8. Zawiera informacje o bezpieczeństwie i wsparciu

Czy chciałbyś wprowadzić jakieś zmiany lub uzupełnienia do tego pliku README?
