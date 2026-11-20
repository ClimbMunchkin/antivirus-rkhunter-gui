#!/bin/bash
# GUI-проверка системы на вирусы с помощью rkhunter (Zenity)
# Использование:
#   ./antivirus.sh          — обычный режим (2 пункта)
#   ./antivirus.sh -a       — расширенный режим (4 пункта)
#   ./antivirus.sh --advanced

LOG="/home/jazzzman/antivirus-report.log"
TITLE="Антивирусная проверка системы"
ADVANCED=0

# ---------- Разбор аргументов ----------
for arg in "$@"; do
    case "$arg" in
        -a|--advanced) ADVANCED=1 ;;
        -h|--help)
            echo "Использование: $0 [-a|--advanced]"
            echo "  -a, --advanced   расширенное меню (4 пункта)"
            echo "  без ключа        обычное меню (2 пункта)"
            exit 0
            ;;
        *)
            echo "Неизвестный аргумент: $arg"
            echo "Использование: $0 [-a|--advanced]"
            exit 1
            ;;
    esac
done

# ---------- Проверка зависимостей ----------
if ! command -v zenity &>/dev/null; then
    echo "Zenity не установлен. Установите: sudo apt install zenity"
    exit 1
fi

if ! command -v rkhunter &>/dev/null; then
    zenity --error --title="$TITLE" \
        --text="rkhunter не установлен.\nУстановите: sudo apt install rkhunter"
    exit 1
fi

# ---------- Проверка sudo заранее ----------
if ! sudo -n true 2>/dev/null; then
    PASS=$(zenity --password --title="$TITLE" \
        --text="Введите пароль sudo для запуска проверки:")
    [ -z "$PASS" ] && exit 0
    echo "$PASS" | sudo -S -v 2>/dev/null || {
        zenity --error --title="$TITLE" --text="Неверный пароль sudo."
        exit 1
    }
fi

# ---------- Функция обновления ----------
Update() {
    (
        echo "5"; echo "# Проверка версии rkhunter..."
        sudo rkhunter --versioncheck >/dev/null 2>&1

        echo "50"; echo "# Обновление антивирусной базы..."
        sudo rkhunter --update >/dev/null 2>&1

        echo "100"; echo "# Обновление завершено."
    ) | zenity --progress --title="$TITLE" \
        --text="Обновление антивируса..." --width=400  \
        --percentage=0 --auto-close --no-cancel
}

# ---------- Функция проверки ----------
Check() {
    local out_file
    out_file=$(mktemp)

    (
        echo "10"; echo "# Запуск проверки rkhunter (может занять время)..."
        sleep 1
        echo "30"; echo "# Сканирование системы..."

        sudo rkhunter --check --skip-keypress \
            --report-warnings-only --logfile "$LOG" > "$out_file" 2>&1

        echo "90"; echo "# Анализ результатов..."
        sleep 1
        echo "100"; echo "# Готово."
    ) | zenity --progress --title="$TITLE" \
        --text="Поиск уязвимостей..." --width=400 \ 
        --percentage=0 --auto-close --pulsate

    local err
    err=$(cat "$out_file")
    rm -f "$out_file"

    sudo chown "$(id -u):$(id -g)" "$LOG" 2>/dev/null

    if [ -n "$err" ]; then
        echo "$err" | zenity --text-info \
            --title="⚠ Обнаружены предупреждения" \
            --width=800 --height=500 \
            --foreground="#cc0000" 2>/dev/null

        zenity --warning --title="$TITLE" --width=450 \
            --text="<b><span color='red' size='large'>Внимание!</span></b>\n\nОбнаружены возможные угрозы.\nПодробности — в отчёте:\n<tt>$LOG</tt>" \
            --ok-label="Закрыть"
        return 1
    else
        zenity --info --title="$TITLE" --width=450 \
            --text="<b><span color='green' size='large'>✔ Проверка прошла успешно</span></b>\n\nВирусных угроз не обнаружено.\nОтчёт сохранён в:\n<tt>$LOG</tt>" \
            --ok-label="Закрыть"
        return 0
    fi
}

# ---------- Показать отчёт ----------
ShowReport() {
    if [ -f "$LOG" ]; then
        zenity --text-info --title="Отчёт антивируса" \
            --filename="$LOG" --width=900 --height=600
    else
        zenity --warning --title="$TITLE" \
            --text="Файл отчёта не найден:\n$LOG"
    fi
}

# ---------- Главное меню ----------
while true; do
    if [ "$ADVANCED" -eq 1 ]; then
        # ----- Расширенный режим: 4 пункта -----
        ACTION=$(zenity --list --title="$TITLE" \
            --text="Выберите действие:" \
            --column="Действие" --column="Описание" \
            "🔍 Обновить и проверить" "Обновить базу и запустить полную проверку" \
            "✅ Только проверить"     "Запустить проверку без обновления" \
            "🔄 Только обновить"      "Обновить антивирусную базу" \
            "📄 Показать отчёт"       "Открыть последний отчёт ($LOG)" \
            --width=680 --height=250 \
            --ok-label="Выполнить" --cancel-label="Выход") || exit 0

        case "$ACTION" in
            "🔍 Обновить и проверить") Update; Check ;;
            "✅ Только проверить")     Check ;;
            "🔄 Только обновить")      Update
                                       zenity --info --title="$TITLE" \
                                           --text="Обновление завершено." ;;
            "📄 Показать отчёт")       ShowReport ;;
            *) continue ;;
        esac
    else
        # ----- Обычный режим: 2 пункта -----
        ACTION=$(zenity --list --title="$TITLE" \
            --text="Выберите действие:" \
            --column="Действие" --column="Описание" \
            "🔍 Обновить и проверить" "Обновить базу и запустить проверку" \
            "📄 Показать отчёт"       "Открыть последний отчёт ($LOG)" \
            --width=680 --height=170 \
            --ok-label="Выполнить" --cancel-label="Выход") || exit 0

        case "$ACTION" in
            "🔍 Обновить и проверить") Update; Check ;;
            "📄 Показать отчёт")       ShowReport ;;
            *) continue ;;
        esac
    fi
done