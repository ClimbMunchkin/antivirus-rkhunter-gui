#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GUI-проверка системы на вирусы с помощью rkhunter (PyQt5)

Запуск через sudo:
    sudo ./rkhunter-gui.py
    sudo ./rkhunter-gui.py -a
    sudo ./rkhunter-gui.py --advanced
"""

import os
import re
import sys
import shutil
import argparse
from pathlib import Path

from PyQt5.QtCore import (
    Qt, QProcess, QProcessEnvironment, QTimer, pyqtSignal, QObject
)
from PyQt5.QtGui import QTextCursor
from PyQt5.QtWidgets import (
    QApplication, QDialog, QVBoxLayout, QHBoxLayout,
    QPushButton, QMessageBox, QPlainTextEdit, QFrame, QLabel,
    QProgressBar
)


# ---------- Домашний каталог реального пользователя ----------
def detect_real_user_and_home():
    real_user = os.environ.get("SUDO_USER") or os.environ.get("USER") or "root"
    try:
        import pwd
        pw = pwd.getpwnam(real_user)
        return real_user, pw.pw_dir, pw.pw_uid, pw.pw_gid
    except (ImportError, KeyError):
        return real_user, os.path.expanduser("~"), os.getuid(), os.getgid()


REAL_USER, REAL_HOME, REAL_UID, REAL_GID = detect_real_user_and_home()
LOG_PATH = Path(REAL_HOME) / "antivirus-report.log"
TITLE = "Антивирусная проверка системы"


# ---------- Стили ----------
STYLE = """
QDialog { background: #f7f8fa; }

QFrame#card {
    background: #ffffff;
    border: 1px solid #e3e6ea;
    border-radius: 10px;
}

QPushButton {
    background: #ffffff;
    border: 1px solid #d0d4da;
    border-radius: 8px;
    padding: 8px 16px;
    font-size: 10pt;
    color: #1a1a1a;
}
QPushButton:hover { background: #f2f5f9; border-color: #b9bec6; }
QPushButton:pressed { background: #e6eaef; }
QPushButton:disabled { color: #a0a0a0; border-color: #e3e6ea; }

QPushButton#primary {
    background: #2d6cdf; color: #ffffff; border: none;
    font-weight: 600;
}
QPushButton#primary:hover { background: #2459b8; }
QPushButton#primary:pressed { background: #1e4a99; }
QPushButton#primary:disabled { background: #a9bce0; color: #f0f0f0; }

QProgressBar {
    background: #eef1f5;
    border: 1px solid #e3e6ea;
    border-radius: 4px;
    height: 18px;
    text-align: center;
    color: #555555;
    font-size: 9pt;
}
QProgressBar::chunk {
    background: #2d6cdf;
    border-radius: 4px;
}
QProgressBar[state="busy"] { color: #c0392b; }
QProgressBar[state="ok"]   { color: #ffffff; }
QProgressBar[state="ok"]::chunk   { background: #2f9e44; }
QProgressBar[state="err"]  { color: #c0392b; }
QProgressBar[state="err"]::chunk  { background: #c0392b; }

QPlainTextEdit {
    background: #1e1e1e;
    color: #d4d4d4;
    border: none;
    border-radius: 8px;
    padding: 8px;
    font-family: Consolas, monospace;
    font-size: 9.5pt;
}
"""


# ---------- ANSI -> HTML ----------
# Цветовые последовательности вида ESC[0;35m, ESC[1;32m, ESC[39m и т.п.
_ANSI_SGR_RE = re.compile(r"\x1b\[([0-9;]*)m")
# Курсорные последовательности вида ESC[34C (вправо на N позиций)
_ANSI_CURSOR_RE = re.compile(r"\x1b\[(\d*)C")
# Прочие escape-последовательности, которые нам не нужны (K, H, J и пр.)
# ВАЖНО: 'm' исключён, но к моменту применения этой регулярки SGR уже разобраны.
_ANSI_OTHER_RE = re.compile(r"\x1b\[[0-9;]*[A-LN-Za-ln-z]")

# Сопоставление SGR-кодов (в виде строки "0;35") с цветами.
# None = сброс цвета.
_ANSI_COLORS = {
    "0": None, "39": None, "": None,
    "0;30": "#1e1e1e", "0;31": "#ff6b6b", "0;32": "#7ddc8f",
    "0;33": "#ffcc66", "0;34": "#7ec4ff", "0;35": "#c792ea",
    "0;36": "#89ddff", "0;37": "#d4d4d4",
    "1;30": "#5a5a5a", "1;31": "#ff4d4d", "1;32": "#3fe06a",
    "1;33": "#ffd633", "1;34": "#5aa9ff", "1;35": "#e0a3ff",
    "1;36": "#a5e8ff", "1;37": "#ffffff",
}


def _html_escape(s: str) -> str:
    return (s.replace("&", "&amp;")
              .replace("<", "&lt;")
              .replace(">", "&gt;"))


def _wrap_html(text: str, color) -> str:
    """Обернуть текст в span, сохранив пробелы и, опционально, цвет."""
    safe = _html_escape(text).replace(" ", "&nbsp;")
    if color:
        return (f"<span style='color:{color}; white-space:pre-wrap;'>"
                f"{safe}</span>")
    return f"<span style='white-space:pre-wrap;'>{safe}</span>"


def ansi_to_html(text: str) -> str:
    """
    Преобразует строку с ANSI escape-последовательностями в HTML-фрагмент,
    который можно скормить QPlainTextEdit.appendHtml().

    Порядок операций ВАЖЕН:
      1) курсорные [NN C -> пробелы;
      2) разбор SGR-цветов (пока коды ещё в тексте);
      3) вырезание прочих CSI (K, H, J и т.п.).
    """
    # 1) Курсорные [NN C -> соответствующее число пробелов
    def _cursor_repl(m):
        n = int(m.group(1)) if m.group(1) else 1
        return " " * n

    text = _ANSI_CURSOR_RE.sub(_cursor_repl, text)

    # 2) Построчный разбор SGR с сохранением текущего цвета
    out_parts = []
    pos = 0
    current_color = None
    for m in _ANSI_SGR_RE.finditer(text):
        chunk = text[pos:m.start()]
        if chunk:
            out_parts.append(_wrap_html(chunk, current_color))
        code = m.group(1)
        current_color = _ANSI_COLORS.get(code)  # неизвестный -> None (сброс)
        pos = m.end()
    tail = text[pos:]
    if tail:
        out_parts.append(_wrap_html(tail, current_color))

    # 3) Только теперь вырезаем прочие CSI-последовательности
    html = "".join(out_parts)
    html = _ANSI_OTHER_RE.sub("", html)
    return html


# ---------- Обёртка над QProcess ----------
class CommandRunner(QObject):
    line_output = pyqtSignal(str)
    finished = pyqtSignal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._proc = QProcess(self)
        self._proc.setProcessChannelMode(QProcess.MergedChannels)
        self._proc.readyReadStandardOutput.connect(self._read_output)
        self._proc.finished.connect(self._on_finished)
        self._proc.errorOccurred.connect(self._on_error)
        self._buffer = b""

    def start(self, program, args, env=None):
        self._buffer = b""
        if env is not None:
            self._proc.setProcessEnvironment(env)
        self._proc.start(program, args)

    def _read_output(self):
        data = bytes(self._proc.readAllStandardOutput())
        self._buffer += data
        while b"\n" in self._buffer:
            line, self._buffer = self._buffer.split(b"\n", 1)
            text = line.decode("utf-8", errors="replace").rstrip("\r")
            self.line_output.emit(text)

    def _on_finished(self, code, _status):
        if self._buffer:
            self.line_output.emit(
                self._buffer.decode("utf-8", errors="replace").rstrip("\r")
            )
            self._buffer = b""
        self.finished.emit(code)

    def _on_error(self, _err):
        self.line_output.emit(
            f"[!] Ошибка запуска процесса: {self._proc.errorString()}"
        )

    def kill(self):
        try:
            self._proc.kill()
        except Exception:
            pass


# ---------- Парсер отчёта rkhunter ----------
_RKH_LINE_RE = re.compile(
    r"^\[\d{2}:\d{2}:\d{2}\]\s+(?P<msg>.+?)\s+\[\s*(?P<status>[A-Za-z ]+?)\s*\]\s*$"
)
_RKH_SECTION_RE = re.compile(
    r"^\[\d{2}:\d{2}:\d{2}\]\s+"
    r"(?:Checking for|Performing|Running|Starting test name)\s+(?P<title>.+?)"
    r"(?:\.\.\.)?\s*$"
)
# Всё, что НЕ в этом списке, считаем подозрительным
_GOOD_STATUSES = {"ok", "not found", "none found", "skipped", "whitelisted"}


def parse_rkhunter_report(text: str):
    """
    Возвращает список словарей:
        {"section": str, "line": str, "reason": str}
    по всем подозрительным/предупреждающим строкам отчёта.
    """
    findings = []
    current_section = ""

    # 1) Основной проход по строкам
    for raw in text.splitlines():
        line = raw.rstrip()

        m_sec = _RKH_SECTION_RE.match(line)
        if m_sec:
            current_section = m_sec.group("title").strip()
            continue

        m = _RKH_LINE_RE.match(line)
        if m:
            status = m.group("status").strip().lower()
            msg = m.group("msg").strip()
            if status not in _GOOD_STATUSES:
                findings.append({
                    "section": current_section,
                    "line": msg,
                    "reason": f"status: {status}",
                })
            continue

        # Текстовые Warning вне [ ... ]
        low = line.lower()
        if " warning" in low or low.startswith("warning"):
            findings.append({
                "section": current_section,
                "line": line,
                "reason": "warning",
            })

    # 2) Финальная секция "Warnings" в конце лога — если есть,
    #    она авторитетнее, но чтобы не дублировать — только дедуплицируем.
    tail = text[-4000:]
    has_warnings_section = bool(re.search(r"^\s*Warnings\s*$", tail, re.M))
    if has_warnings_section:
        m = re.search(
            r"^\s*Warnings\s*$\n(.*?)(?=^\s*System checks summary|\Z)",
            tail, re.M | re.S
        )
        if m:
            for ln in m.group(1).splitlines():
                ln = ln.strip()
                if ln and not ln.lower().startswith("warning"):
                    if not any(f["line"] == ln for f in findings):
                        findings.append({
                            "section": "Warnings",
                            "line": ln,
                            "reason": "warnings section",
                        })

    return findings


# ---------- Главное окно ----------
class AntivirusApp(QDialog):
    def __init__(self, advanced=False):
        super().__init__()
        self.advanced = advanced
        self.current_runner = None
        self._busy = False

        self.setWindowTitle(TITLE)
        self.resize(690, 660)
        self.setStyleSheet(STYLE)

        self._build_ui()

        if os.geteuid() != 0:
            QTimer.singleShot(0, self._warn_not_root)

    # ---------- Построение UI ----------
    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(18, 16, 18, 12)
        root.setSpacing(10)

        # --- Панель кнопок ---
        btns = QHBoxLayout()
        btns.setSpacing(10)

        self.btn_update_check = QPushButton("🔍  Обновить и проверить")
        self.btn_update_check.setObjectName("primary")
        self.btn_update_check.setMinimumHeight(40)
        self.btn_update_check.setCursor(Qt.PointingHandCursor)

        self.btn_check_only = QPushButton("✅  Только проверить")
        self.btn_check_only.setMinimumHeight(40)
        self.btn_check_only.setCursor(Qt.PointingHandCursor)

        self.btn_update_only = QPushButton("🔄  Только обновить")
        self.btn_update_only.setMinimumHeight(40)
        self.btn_update_only.setCursor(Qt.PointingHandCursor)

        self.btn_show_report = QPushButton("📄  Показать отчёт")
        self.btn_show_report.setMinimumHeight(40)
        self.btn_show_report.setCursor(Qt.PointingHandCursor)

        for b in (self.btn_update_check, self.btn_check_only,
                  self.btn_update_only, self.btn_show_report):
            btns.addWidget(b)
        btns.addStretch()
        root.addLayout(btns)

        if not self.advanced:
            self.btn_check_only.hide()
            self.btn_update_only.hide()

        # --- Прогресс-бар (над консолью) ---
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setFormat("Готов к запуску")
        root.addWidget(self.progress)

        # --- Карточка с консолью ---
        card = QFrame()
        card.setObjectName("card")
        card_lay = QVBoxLayout(card)
        card_lay.setContentsMargins(10, 10, 10, 10)

        self.console = QPlainTextEdit()
        self.console.setReadOnly(True)
        self.console.setMaximumBlockCount(10000)
        card_lay.addWidget(self.console)

        root.addWidget(card, 1)
        
        # --- Футер ---
        self.footer = QLabel("")
        self.footer.setStyleSheet("font-size: 9.5pt; color: #555555;")
        root.addWidget(self.footer)

        # --- Сигналы ---
        self.btn_update_check.clicked.connect(self.on_update_and_check)
        self.btn_check_only.clicked.connect(self.on_check_only)
        self.btn_update_only.clicked.connect(self.on_update_only)
        self.btn_show_report.clicked.connect(self.on_show_report)

    # ---------- Хелперы ----------
    def log_line(self, text, color=None):
        """
        Всегда выводит HTML. Если color задан — принудительно красит
        всю строку в этот цвет (заголовки скрипта). Иначе — парсит ANSI.
        """
        if color:
            safe = _html_escape(text).replace(" ", "&nbsp;")
            self.console.appendHtml(
                f"<span style='color:{color}; white-space:pre-wrap;'>"
                f"{safe}</span>"
            )
        else:
            self.console.appendHtml(ansi_to_html(text))
        self.console.moveCursor(QTextCursor.End)

    @staticmethod
    def _esc(s):
        return (s.replace("&", "&amp;")
                  .replace("<", "&lt;")
                  .replace(">", "&gt;")
                  .replace(" ", "&nbsp;"))

    def _warn_not_root(self):
        self.log_line(
            "[!] Скрипт запущен не под root. rkhunter может не работать. "
            "Запустите через sudo.", "#cc0000"
        )

    def set_progress_state(self, text, state=""):
        self.progress.setFormat(text)
        self.progress.setProperty("state", state)
        self.progress.style().unpolish(self.progress)
        self.progress.style().polish(self.progress)

    def set_busy(self, busy):
        self._busy = busy
        for b in (self.btn_update_check, self.btn_check_only,
                  self.btn_update_only, self.btn_show_report):
            b.setEnabled(not busy)
        if busy:
            self.progress.setRange(0, 0)  # бегущая полоса
            self.set_progress_state("Выполняется…", "busy")
        else:
            self.progress.setRange(0, 100)

    def make_env(self):
        env = QProcessEnvironment.systemEnvironment()
        env.insert("HOME", REAL_HOME)
        env.insert("LC_ALL", "C.UTF-8")
        return env

    def ensure_dependencies(self):
        if not shutil.which("rkhunter"):
            QMessageBox.critical(
                self, TITLE,
                "rkhunter не установлен.\n\nУстановите: sudo apt install rkhunter"
            )
            return False
        return True

    # ---------- Запуск команды ----------
    def run_command(self, program, args, on_done=None, status_text=None):
        if self._busy:
            return
        self.set_busy(True)
        if status_text:
            self.set_progress_state(status_text, "busy")

        runner = CommandRunner(self)
        runner.line_output.connect(self.log_line)
        runner.finished.connect(
            lambda code: self._on_command_done(code, on_done)
        )
        runner.start(program, args, self.make_env())
        self.current_runner = runner

    def _on_command_done(self, code, on_done):
        self.set_busy(False)
        self.current_runner = None
        if on_done is not None:
            on_done(code)

    # ---------- Действия ----------
    def on_update_and_check(self):
        if not self.ensure_dependencies():
            return
        self.log_line("=== Проверка версии rkhunter ===", color="#7ec4ff")
        self.run_command(
            "rkhunter", ["--versioncheck"],
            on_done=lambda c1: self._after_versioncheck(c1),
            status_text="Проверка версии…"
        )

    def _after_versioncheck(self, code):
        if code != 0:
            self.log_line(f"[!] versioncheck завершился с кодом {code}",
                          "#ff6b6b")
        self.log_line("=== Обновление базы ===", color="#7ec4ff")
        self.run_command(
            "rkhunter", ["--update"],
            on_done=lambda c2: self._after_update(c2, then_check=True),
            status_text="Обновление базы…"
        )

    def _after_update(self, code, then_check):
        if code != 0:
            self.log_line(f"[!] update завершился с кодом {code}", "#ff6b6b")
            self.set_progress_state(f"Ошибка обновления (код {code})", "err")
            self.progress.setValue(100)
        else:
            self.log_line("Обновление завершено.", "#7ddc8f")
            self.set_progress_state("Обновление завершено", "ok")
            self.progress.setValue(100)
        if then_check:
            QTimer.singleShot(300, self.on_check_only)
        else:
            QMessageBox.information(self, TITLE, "Обновление завершено.")
            self.progress.setValue(0)
            self.set_progress_state("Готов к запуску")

    def on_update_only(self):
        if not self.ensure_dependencies():
            return
        self.log_line("=== Только обновление ===", color="#7ec4ff")
        self.run_command(
            "rkhunter", ["--update"],
            on_done=lambda c: self._after_update(c, then_check=False),
            status_text="Обновление базы…"
        )

    def on_check_only(self):
        if not self.ensure_dependencies():
            return
        self.log_line("=== Проверка системы (может занять время) ===",
                      color="#7ec4ff")
        self.run_command(
            "rkhunter",
            [
                "--check",
                "--skip-keypress",
#                "--report-warnings-only",
                "--logfile", str(LOG_PATH),
            ],
            on_done=self._after_check,
            status_text="Сканирование системы…"
        )

    def _after_check(self, code):
        try:
            if LOG_PATH.exists():
                os.chown(LOG_PATH, REAL_UID, REAL_GID)
        except PermissionError as e:
            self.log_line(f"[!] chown не удался: {e}", "#ff6b6b")

        # --- Разбор отчёта и краткая сводка ---
        findings = []
        if LOG_PATH.exists():
            try:
                text = LOG_PATH.read_text(encoding="utf-8", errors="replace")
                findings = parse_rkhunter_report(text)
            except Exception as e:
                self.log_line(f"[!] Не удалось прочитать отчёт: {e}", "#ff6b6b")

        self.log_line("")
        self.log_line("=" * 60, color="#7ec4ff")
        if findings:
            self.log_line(
                f"⚠ Найдено предупреждений: {len(findings)}",
                color="#ffcc66"
            )
            self.log_line("-" * 60, color="#7ec4ff")
            last_section = None
            for f in findings:
                if f["section"] != last_section:
                    self.log_line(f"[{f['section'] or '—'}]", color="#7ec4ff")
                    last_section = f["section"]
                self.log_line(f"  • {f['line']}")
        else:
            self.log_line("✔ Предупреждений не найдено.", color="#7ddc8f")
        self.log_line("=" * 60, color="#7ec4ff")
        self.log_line("")

        # --- Итоговый диалог ---
        if code == 0 and not findings:
            self.log_line("Проверка завершена: угроз не обнаружено.", "#7ddc8f")
            self.set_progress_state("Проверка пройдена", "ok")
            self.progress.setValue(100)
            self.footer.setText(f"✔ Угроз не обнаружено   •   Отчёт: {LOG_PATH}")
            QMessageBox.information(
                self, TITLE,
                f"✔ Проверка прошла успешно.\n\n"
                f"Вирусных угроз не обнаружено.\n\nОтчёт: {LOG_PATH}"
            )
        else:
            count = len(findings)
            self.log_line(
                f"Проверка завершена с предупреждениями "
                f"(код {code}, найдено {count}).",
                "#ff6b6b"
            )
            self.set_progress_state("Обнаружены предупреждения", "err")
            self.progress.setValue(100)
            self.footer.setText(
                f"⚠ Предупреждений: {count}   •   Отчёт: {LOG_PATH}"
            )
            QMessageBox.warning(
                self, TITLE,
                f"⚠ Обнаружены возможные угрозы.\n\n"
                f"Найдено предупреждений: {count}\n"
                f"Подробности — в консоли и в отчёте:\n{LOG_PATH}"
            )
            self.on_show_report()

    def on_show_report(self):
        if not LOG_PATH.exists():
            QMessageBox.warning(self, TITLE,
                                f"Файл отчёта не найден:\n{LOG_PATH}")
            return

        dlg = QDialog(self)
        dlg.setWindowTitle("Отчёт антивируса")
        dlg.resize(900, 600)
        dlg.setStyleSheet("QDialog { background: #f7f8fa; }")
        v = QVBoxLayout(dlg)

        card = QFrame()
        card.setObjectName("card")
        card_lay = QVBoxLayout(card)
        card_lay.setContentsMargins(10, 10, 10, 10)

        viewer = QPlainTextEdit()
        viewer.setReadOnly(True)
        viewer.setStyleSheet("""
            QPlainTextEdit {
                background: #1e1e1e; color: #d4d4d4;
                border: none; border-radius: 8px; padding: 8px;
                font-family: Consolas, monospace; font-size: 9.5pt;
            }
        """)
        try:
            viewer.setPlainText(
                LOG_PATH.read_text(encoding="utf-8", errors="replace")
            )
        except Exception as e:
            viewer.setPlainText(f"Не удалось прочитать файл:\n{e}")
        card_lay.addWidget(viewer)
        v.addWidget(card, 1)

        close_btn = QPushButton("Закрыть")
        close_btn.clicked.connect(dlg.accept)
        close_btn.setMaximumWidth(120)
        row = QHBoxLayout()
        row.addStretch()
        row.addWidget(close_btn)
        v.addLayout(row)

        dlg.exec_()

    # ---------- Закрытие ----------
    def closeEvent(self, event):
        if self._busy and self.current_runner is not None:
            resp = QMessageBox.question(
                self, TITLE,
                "Идёт операция. Прервать и выйти?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )
            if resp != QMessageBox.Yes:
                event.ignore()
                return
            self.current_runner.kill()
        event.accept()


# ---------- main ----------
def main():
    parser = argparse.ArgumentParser(
        description="GUI-проверка системы на вирусы (rkhunter + PyQt5)"
    )
    parser.add_argument("-a", "--advanced", action="store_true",
                        help="расширенный режим (4 кнопки)")
    args = parser.parse_args()

    app = QApplication(sys.argv)
    app.setApplicationName("Antivirus GUI")
    win = AntivirusApp(advanced=args.advanced)
    win.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
