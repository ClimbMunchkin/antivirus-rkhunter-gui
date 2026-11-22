#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GUI-проверка системы на вирусы с помощью rkhunter (PyQt5)

ВНИМАНИЕ: скрипт рассчитан на запуск через sudo:
    sudo ./antivirus.py
    sudo ./antivirus.py -a
    sudo ./antivirus.py --advanced
"""

import os
import sys
import shutil
import argparse
from pathlib import Path

from PyQt5.QtCore import (
    Qt, QProcess, QProcessEnvironment, QTimer, pyqtSignal, QObject
)
from PyQt5.QtGui import QFont, QTextCursor
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QPlainTextEdit, QMessageBox, QDialog,
    QDialogButtonBox, QFrame, QStatusBar
)


# ---------- Домашний каталог реального пользователя ----------
def detect_real_user_and_home():
    """
    Скрипт запускается под sudo, поэтому SUDO_USER — это изначальный
    пользователь, а не root. Берём его домашний каталог.
    """
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


# ---------- Обёртка над QProcess с построчным выводом ----------
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

    def start(self, program: str, args: list,
              env: QProcessEnvironment = None):
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

    def _on_finished(self, code: int, _status):
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


# ---------- Основное окно ----------
class AntivirusWindow(QMainWindow):
    def __init__(self, advanced: bool = False):
        super().__init__()
        self.advanced = advanced
        self.current_runner = None
        self._busy = False

        self.setWindowTitle(TITLE)
        self.resize(900, 620)

        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)

        # --- Заголовок ---
        header = QLabel(
            "<b><span style='font-size:14pt'>Антивирусная проверка системы</span></b>"
        )
        root.addWidget(header)

        # --- Панель кнопок ---
        btn_panel = QHBoxLayout()
        btn_panel.setSpacing(8)

        self.btn_update_check = QPushButton("🔍 Обновить и проверить")
        self.btn_check_only = QPushButton("✅ Только проверить")
        self.btn_update_only = QPushButton("🔄 Только обновить")
        self.btn_show_report = QPushButton("📄 Показать отчёт")
        self.btn_clear = QPushButton("🧹 Очистить консоль")
        self.btn_exit = QPushButton("🚪 Выход")

        for b in (self.btn_update_check, self.btn_check_only,
                  self.btn_update_only, self.btn_show_report,
                  self.btn_clear, self.btn_exit):
            b.setMinimumHeight(40)
            b.setCursor(Qt.PointingHandCursor)
            btn_panel.addWidget(b)

        root.addLayout(btn_panel)

        if not self.advanced:
            self.btn_check_only.hide()
            self.btn_update_only.hide()

        # --- Консоль ---
        console_frame = QFrame()
        console_frame.setFrameShape(QFrame.StyledPanel)
        console_layout = QVBoxLayout(console_frame)
        console_layout.setContentsMargins(4, 4, 4, 4)

        console_label = QLabel("<b>Консоль (вывод в реальном времени):</b>")
        console_layout.addWidget(console_label)

        self.console = QPlainTextEdit()
        self.console.setReadOnly(True)
        mono = QFont("Monospace")
        mono.setStyleHint(QFont.TypeWriter)
        mono.setPointSize(10)
        self.console.setFont(mono)
        self.console.setMaximumBlockCount(10000)
        console_layout.addWidget(self.console)

        root.addWidget(console_frame, stretch=1)

        # --- Статус-бар ---
        self.status = QStatusBar()
        self.setStatusBar(self.status)
        self.status.showMessage(f"Лог: {LOG_PATH}")

        # --- Сигналы ---
        self.btn_update_check.clicked.connect(self.on_update_and_check)
        self.btn_check_only.clicked.connect(self.on_check_only)
        self.btn_update_only.clicked.connect(self.on_update_only)
        self.btn_show_report.clicked.connect(self.on_show_report)
        self.btn_clear.clicked.connect(self.console.clear)
        self.btn_exit.clicked.connect(self.close)

        # Проверка, что действительно root
        if os.geteuid() != 0:
            QTimer.singleShot(0, self._warn_not_root)

    # ---------- Хелперы ----------
    def log_line(self, text: str, color: str = None):
        if color:
            self.console.appendHtml(
                f"<span style='color:{color}; white-space:pre-wrap'>"
                f"{self._esc(text)}</span>"
            )
        else:
            self.console.appendPlainText(text)
        self.console.moveCursor(QTextCursor.End)

    @staticmethod
    def _esc(s: str) -> str:
        return (s.replace("&", "&amp;")
                  .replace("<", "&lt;")
                  .replace(">", "&gt;")
                  .replace(" ", "&nbsp;"))

    def _warn_not_root(self):
        self.log_line(
            "[!] Скрипт запущен не под root. rkhunter может не работать. "
            "Запустите через sudo.", "#cc0000"
        )

    def set_busy(self, busy: bool):
        self._busy = busy
        for b in (self.btn_update_check, self.btn_check_only,
                  self.btn_update_only, self.btn_show_report):
            b.setEnabled(not busy)
        QApplication.setOverrideCursor(Qt.WaitCursor if busy else Qt.ArrowCursor)

    def ensure_dependencies(self) -> bool:
        missing = []
        if not shutil.which("rkhunter"):
            missing.append("rkhunter")
        if missing:
            QMessageBox.critical(
                self, TITLE,
                "Не установлены зависимости:\n  - " + "\n  - ".join(missing)
                + "\n\nУстановите: sudo apt install " + " ".join(missing)
            )
            return False
        return True

    def make_env(self) -> QProcessEnvironment:
        env = QProcessEnvironment.systemEnvironment()
        # Принудительно — домашний каталог реального пользователя.
        env.insert("HOME", REAL_HOME)
        env.insert("LC_ALL", "C.UTF-8")
        return env

    def run_command(self, program: str, args: list, on_done=None):
        if self._busy:
            return
        self.set_busy(True)

        runner = CommandRunner(self)
        runner.line_output.connect(self.log_line)
        runner.finished.connect(
            lambda code: self._on_command_done(code, on_done)
        )
        runner.start(program, args, self.make_env())
        self.current_runner = runner

    def _on_command_done(self, code: int, on_done):
        self.set_busy(False)
        self.current_runner = None
        if on_done is not None:
            on_done(code)

    # ---------- Действия ----------
    def on_update_and_check(self):
        if not self.ensure_dependencies():
            return
        self.log_line("=== Проверка версии rkhunter ===", color="#0055cc")
        self.run_command(
            "rkhunter", ["--versioncheck"],
            on_done=lambda c1: self._after_versioncheck(c1)
        )

    def _after_versioncheck(self, code: int):
        if code != 0:
            self.log_line(f"[!] versioncheck завершился с кодом {code}",
                          "#cc0000")
        self.log_line("=== Обновление базы ===", color="#0055cc")
        self.run_command(
            "rkhunter", ["--update"],
            on_done=lambda c2: self._after_update(c2, then_check=True)
        )

    def _after_update(self, code: int, then_check: bool):
        if code != 0:
            self.log_line(f"[!] update завершился с кодом {code}", "#cc0000")
        else:
            self.log_line("Обновление завершено.", "#008800")
        if then_check:
            QTimer.singleShot(200, self.on_check_only)
        else:
            QMessageBox.information(self, TITLE, "Обновление завершено.")

    def on_update_only(self):
        if not self.ensure_dependencies():
            return
        self.log_line("=== Только обновление ===", color="#0055cc")
        self.run_command(
            "rkhunter", ["--update"],
            on_done=lambda c: self._after_update(c, then_check=False)
        )

    def on_check_only(self):
        if not self.ensure_dependencies():
            return
        self.log_line("=== Проверка системы (может занять время) ===",
                      color="#0055cc")
        self.run_command(
            "rkhunter",
            [
                "--check",
                "--skip-keypress",
                "--report-warnings-only",
                "--logfile", str(LOG_PATH),
            ],
            on_done=self._after_check
        )

    def _after_check(self, code: int):
        # Мы root — просто отдаём владение реальному пользователю.
        try:
            if LOG_PATH.exists():
                os.chown(LOG_PATH, REAL_UID, REAL_GID)
        except PermissionError as e:
            self.log_line(f"[!] chown не удался: {e}", "#cc0000")

        if code == 0:
            self.log_line("Проверка завершена: угроз не обнаружено.", "#008800")
            QMessageBox.information(
                self, TITLE,
                f"✔ Проверка прошла успешно.\n\n"
                f"Вирусных угроз не обнаружено.\n\nОтчёт: {LOG_PATH}"
            )
        else:
            self.log_line(
                f"Проверка завершена с предупреждениями (код {code}).",
                "#cc0000"
            )
            QMessageBox.warning(
                self, TITLE,
                f"⚠ Обнаружены возможные угрозы.\n\n"
                f"Подробности — в отчёте:\n{LOG_PATH}"
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
        v = QVBoxLayout(dlg)

        viewer = QPlainTextEdit()
        viewer.setReadOnly(True)
        mono = QFont("Monospace")
        mono.setStyleHint(QFont.TypeWriter)
        viewer.setFont(mono)
        try:
            viewer.setPlainText(
                LOG_PATH.read_text(encoding="utf-8", errors="replace")
            )
        except Exception as e:
            viewer.setPlainText(f"Не удалось прочитать файл:\n{e}")
        v.addWidget(viewer)

        btns = QDialogButtonBox(QDialogButtonBox.Close)
        btns.rejected.connect(dlg.reject)
        btns.accepted.connect(dlg.accept)
        v.addWidget(btns)

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
    win = AntivirusWindow(advanced=args.advanced)
    win.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()