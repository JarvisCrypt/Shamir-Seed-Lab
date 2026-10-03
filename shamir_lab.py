#!/usr/bin/env python3
"""
Shamir Seed Lab
===============

Offline tool for generating BIP-39 seed phrases and splitting them
into Shamir Secret Sharing backups (SLIP-39).

UI languages: English, Russian (selected at startup).

Security design principles:
  * One secret on screen at a time; screen + scrollback wiped after
  * Hidden input (getpass) for seed phrases and passphrases
  * Short lifetime of secrets in memory; in-place wiping of bytearrays
  * Secret fingerprint (SHA-256 prefix) verified on recovery
  * Automatic verification of shares right after creation
  * Environment checks (swap, core dumps, network, redirection)
  * No network access, no shell calls, no files written

Recovery design (v3.4):
  * The passphrase is requested up front and can be re-entered if
    decryption fails.
  * Any number of shares (>= threshold) may be entered. The reference
    combine_mnemonics() requires EXACTLY T shares per group, so this
    tool selects a valid T-subset itself, in three phases:
      Phase 1 - the whole set as entered (works when count == T,
                otherwise the library's "Expected N mnemonics" error
                reveals T);
      Phase 2 - T-sized subsets: first T, last T, then all in order;
      Phase 3 - candidate thresholds discovered by probing each share
                individually (a single T>=2 share always fails the
                count check *before* the slow KDF, naming its T),
                then subsets of those sizes.
  * Cheap failures (wrong subset size, rejected during preprocessing,
    before the passphrase KDF) never consume the expensive-attempt
    budget, so unusable combinations cannot starve the usable ones.
  * Each entered share is structurally validated immediately:
    word count (20/23/27/30/33) and SLIP-39 wordlist membership.
  * If the library's error wording ever changes, Phase 1/2 degrade
    gracefully and Phase 3 still discovers the right subsets.

Dependencies (reference implementations by SatoshiLabs):
  pip install mnemonic shamir-mnemonic

License: MIT
"""

import gc
import getpass
import hashlib
import os
import random
import re
import signal
import sys
from itertools import combinations

from mnemonic import Mnemonic
from shamir_mnemonic import generate_mnemonics, combine_mnemonics

# Optional share decoder from newer versions of the reference package
# (provides identifier / group / member info for nicer diagnostics).
# All core functionality works without it.
try:
    from shamir_mnemonic.share import decode_mnemonic as _decode_mnemonic
except ImportError:
    try:
        from shamir_mnemonic import decode_mnemonic as _decode_mnemonic
    except ImportError:
        _decode_mnemonic = None

# SLIP-39 wordlist for input validation, resolved defensively:
#   1) package-level export, 2) the shamir module, 3) wordlist.txt
# shipped inside the package. If none works, the word check is
# simply skipped (the library still rejects bad shares at combine).
_SLIP39_WORDSET = None
try:
    try:
        from shamir_mnemonic import WORDLIST as _wordlist
    except ImportError:
        from shamir_mnemonic.shamir import WORDLIST as _wordlist
    _SLIP39_WORDSET = frozenset(w.strip() for w in _wordlist)
except Exception:
    try:
        import shamir_mnemonic as _sm_package
        _wl_path = os.path.join(
            os.path.dirname(_sm_package.__file__), "wordlist.txt")
        with open(_wl_path, "r", encoding="utf-8") as _f:
            _SLIP39_WORDSET = frozenset(
                line.strip() for line in _f if line.strip())
    except Exception:
        _SLIP39_WORDSET = None


# ============================================================
# Constants
# ============================================================

APP_NAME = "Shamir Seed Lab"
APP_VERSION = "3.4"
WORDLIST_LANGUAGE = "english"   # BIP-39 wordlist (not the UI language)
BIP39_STRENGTH = 256            # 24 words
MAX_SHARES = 16                 # SLIP-39 maximum per group
ITERATION_EXPONENT = 2          # PBKDF2: 10000 * 2^2 = 40000 iterations

# combine_mnemonics() raises "Wrong number of mnemonics. Expected N
# mnemonics ..." when the subset size is wrong. That check happens
# BEFORE the slow passphrase KDF, which makes such failures cheap and
# makes the message the version-independent way to learn the threshold.
_EXPECTED_COUNT_RE = re.compile(r"Expected (\d+) mnemonics?")

# Valid SLIP-39 mnemonic lengths (words) for master secrets of
# 16/20/24/28/32 bytes: 20, 23, 27, 30, 33.
VALID_SHARE_WORD_COUNTS = frozenset((20, 23, 27, 30, 33))

# Budget of expensive (KDF-consuming) combine failures allowed per
# subset size. Cheap count-failures do not consume it.
KDF_ATTEMPT_BUDGET = 16

# Hard cap on the total number of combine calls in the subset phases,
# bounding the worst case for heavily mixed share sets.
MAX_SCAN_CALLS = 400


# ============================================================
# Translations (UI language)
# ============================================================

TRANSLATIONS = {
    "en": {
        # --- Menu ---
        "app_tagline": "BIP-39 seed phrases + SLIP-39 (Shamir) backups",
        "menu_1": "Create a new seed phrase and backup",
        "menu_2": "Split an existing seed phrase",
        "menu_3": "Recover a seed from shares",
        "menu_4": "Run the automatic test",
        "menu_5": "Check environment",
        "menu_6": "Exit",
        "menu_choice": "Select action:",
        "menu_unknown": "Unknown command.",

        # --- Common input ---
        "num_range": "Enter a number from {min} to {max}.",
        "num_invalid": "Error: enter an integer.",
        "yn_retry": "Enter 'y' (yes) or 'n' (no).",
        "enter_continue": "Press Enter to continue...",
        "input_repeat": "(repeat)",
        "input_empty": "Empty input. Try again.",
        "input_mismatch": "Input does not match. Try again.",
        "hidden_unavailable": "(Hidden input unavailable — input will be visible)",

        # --- Privacy warning ---
        "privacy_title": "⚠  CRITICAL INFORMATION  ⚠",
        "privacy_intro": "Secret data is about to be displayed.",
        "privacy_ensure": "Make sure that:",
        "privacy_1": "• Nobody can see your screen",
        "privacy_2": "• No screen recording is in progress",
        "privacy_3": "• No cameras are pointed at the screen",
        "privacy_4": "• The terminal session is not being logged",
        "privacy_5": "• You have pen and paper at hand",
        "privacy_confirm": "The environment is safe. Continue?",

        # --- Secret display ---
        "secret_write": "Write down ALL words IN ORDER on paper.",
        "secret_no_copy": "Do not photograph. Do not type into a file.",
        "secret_count": "Total words: {count}",
        "secret_fp": "Secret fingerprint: {fp}",
        "secret_fp_hint1": "Write the fingerprint on the sheet as well — it is",
        "secret_fp_hint2": "used to verify correctness during recovery.",
        "secret_entered": "Press Enter once you have written everything down...",
        "secret_confirm": "Did you write everything down correctly?",
        "secret_again": "Showing again...",

        "seed_title": "SEED PHRASE (BIP-39)",
        "seed_hint": "Store this phrase the way you plan to use the wallet.",

        "share_title": "SHARE {index} OF {total} (SCHEME {threshold}-of-{total})",
        "share_hint": "Write this share on a SEPARATE sheet of paper.",
        "share_label": 'Label the sheet: "Share {index}/{total}, scheme {threshold}-of-{total}, FP: {fp}"',
        "share_entered": "Press Enter once you have written down Share {index}...",
        "share_confirm": "Is Share {index} written down correctly?",

        # --- Scheme selection ---
        "scheme_title": "SHAMIR SCHEME SETUP",
        "scheme_t": "T = how many shares are required for recovery",
        "scheme_n": "N = how many shares are created in total",
        "scheme_examples": "Examples:",
        "scheme_ex1": "  2-of-3  → any 2 of 3 shares",
        "scheme_ex2": "  3-of-5  → any 3 of 5 shares",
        "scheme_ex3": "  5-of-10 → any 5 of 10 shares",
        "scheme_storage": "Store the shares in DIFFERENT locations (home, bank, relatives).",
        "scheme_total": "Total number of shares N (2-{max}):",
        "scheme_threshold": "Recovery threshold T (2-{total}):",
        "scheme_chosen": "Selected scheme: {threshold}-of-{total}",

        # --- Passphrase ---
        "pp_intro1": "A passphrase is a second factor for the SLIP-39 backup.",
        "pp_intro2": "Recovery will require: the shares + this passphrase.",
        "pp_warn_title": "IMPORTANT — READ CAREFULLY",
        "pp_warn1": "Losing the passphrase = losing access FOREVER,",
        "pp_warn2": "even if you have ALL the shares!",
        "pp_warn3": "Store the passphrase separately from the shares.",
        "pp_warn4": "A secret fingerprint will be shown for you to write",
        "pp_warn5": "down — it verifies the passphrase during recovery.",
        "pp_use": "Use a passphrase?",
        "pp_enter": "Passphrase:",
        "pp_confirm": "Confirm passphrase:",
        "pp_empty": "Passphrase cannot be empty.",
        "pp_mismatch": "Passphrases do not match. Try again.",

        # --- New backup ---
        "new_title": "CREATE A NEW BACKUP",
        "new_generating": "Generating seed phrase (256 bits of entropy)...",
        "splitting": "Creating a {threshold}-of-{total} split...",
        "splitting_slow": "(may take up to a minute)",
        "split_error": "ERROR: {err}",

        # --- Split existing ---
        "split_title": "SPLIT AN EXISTING SEED PHRASE",
        "split_intro1": "Enter your existing BIP-39 seed phrase (12-24 words).",
        "split_intro2": "Input is hidden. You will enter the phrase twice to confirm.",
        "seed_prompt": "Seed phrase",
        "checking": "Verifying checksum...",
        "checksum_bad": "ERROR: invalid BIP-39 checksum.",
        "checksum_check": "Check the phrase for typos and try again.",
        "checksum_ok": "Checksum is valid.",

        # --- Verification ---
        "verify_title": "AUTOMATIC VERIFICATION",
        "verify_running": "Verifying: recovery from the first {threshold} shares...",
        "verify_ok": "PASSED: {threshold} shares correctly restore the secret.",
        "verify_bad": "ERROR: the recovered secret does not match!",
        "verify_exc": "Verification error: {err}",
        "verify_failed": "VERIFICATION FAILED — do not use these shares!",

        # --- Final report ---
        "report_title": "OPERATION SUMMARY",
        "report_scheme": "Scheme:       {threshold}-of-{total}",
        "report_fp": "Fingerprint:  {fp}",
        "report_pp": "Passphrase:   {value}",
        "report_pp_yes": "YES (do not lose it!)",
        "report_pp_no": "none",
        "report_remember": "Remember:",
        "report_r1": "• Keep the shares in different physical locations",
        "report_r2": "• Write the fingerprint on every sheet (verified on recovery)",
        "report_r3": "• Keep the passphrase separately from the shares!",
        "finish_enter": "Press Enter to finish...",
        "memory_cleared": "Secrets have been removed from memory (as far as Python allows).",
        "store_advice": "Store the shares in different safe places!",

        # --- Recovery ---
        "rec_title": "SEED RECOVERY",
        "rec_intro1": "Enter the shares one at a time (each is a 20-33 word phrase).",
        "rec_intro2": "Input is VISIBLE — check for typos as you type.",
        "rec_intro3": "After each share the program tries to recover the secret.",
        "rec_intro4": "You may enter more shares than required — the program will pick a valid combination.",
        "rec_pp_used": "Was a passphrase used when this backup was created?",
        "rec_pp_prompt": "Passphrase (Enter = none):",
        "rec_share_header": "--- Share {num} ---",
        "rec_share_prompt": "Enter share (or press Enter for options):",
        "rec_first": "Enter at least one share first.",
        "rec_dup": "This share has already been entered. Enter a different one.",
        "rec_dup_slot": "Share #{member} of this set has already been entered. Enter a different share.",
        "rec_foreign": "This share belongs to a DIFFERENT backup (different identifier). Do not mix shares from different backups!",
        "rec_mixed": "This share's parameters differ from the previously entered ones — it is likely from a DIFFERENT backup. Do not mix shares from different backups!",
        "rec_invalid_share": "This is not a valid share: {err}",
        "rec_share_bad_length": "Not a valid share: expected 20, 23, 27, 30 or 33 words, got {count}.",
        "rec_share_bad_words": "Not a valid share: it contains words that are not in the SLIP-39 wordlist.",
        "rec_status": "Shares collected: {have} of {need} required.",
        "rec_accepted": "Shares accepted: {count}",
        "rec_pp_suspect_title": "Enough shares collected, but the secret cannot be decrypted.",
        "rec_pp_suspect_hint": "This almost always means the passphrase is wrong.",
        "rec_pp_retry": "Re-enter the passphrase?",
        "rec_recovered": "Secret recovered!",
        "rec_failed": "Recovery is not possible yet.",
        "rec_reasons": "Still cannot recover. Possible reasons:",
        "rec_reason1": "• Not enough shares (T are required)",
        "rec_reason2": "• Wrong passphrase",
        "rec_reason3": "• Typos in the shares",
        "rec_reason4": "• Shares from different backups",
        "rec_continue": "Continue entering shares?",
        "rec_aborted": "Recovery aborted. Secrets cleared from memory.",
        "rec_fp_intro1": "Every share sheet has the secret fingerprint on it.",
        "rec_fp_intro2": "Enter it to verify (Enter = skip):",
        "rec_fp_prompt": "Fingerprint:",
        "rec_fp_match": "MATCH ({fp}) — the secret is correct.",
        "rec_fp_mismatch": "MISMATCH!",
        "rec_fp_expected": "Expected: {fp}",
        "rec_fp_got": "Got:      {fp}",
        "rec_fp_mean1": "This means: wrong passphrase, typos in the shares, or",
        "rec_fp_mean2": "shares of a different secret. The result is WRONG — do NOT use it!",
        "rec_fp_shown": "Fingerprint of the recovered secret: {fp}",
        "rec_fp_manual": "(compare it with the share sheets manually!)",
        "rec_show_blocked": "Display blocked: the secret failed verification.",
        "rec_convert_error": "ERROR converting to BIP-39: {err}",

        # --- Tests ---
        "test_title": "AUTOMATIC TEST",
        "test_intro": "The test uses a random disposable secret.",
        "test_generating": "Generating a test secret...",
        "test_splitting": "Splitting {threshold}-of-{total} (up to a minute)...",
        "test_split_error": "Splitting error: {err}",
        "test_1": "Test 1: shares #1-{threshold}",
        "test_2": "Test 2: shares #{start}-{end}",
        "test_3": "Test 3: random shares ({threshold})",
        "test_4": "Test 4: all {total} shares at once",
        "test_5": "Test 5: {count} shares (must be rejected)",
        "test_6": "Test 6: wrong passphrase (must not match)",
        "test_7": "Test 7: fingerprint reproducibility",
        "test_8": "Test 8: shares in reverse order ({threshold})",
        "test_9": "Test 9: extra shares, threshold auto-detected",
        "test_10": "Test 10: a foreign share mixed in",
        "test_11": "Test 11: input normalization (case, spacing)",
        "test_exc": "exception — {err}",
        "test_result": "RESULT: {passed} of {total} tests passed",
        "test_all_ok": "ALL TESTS PASSED",
        "test_failed": "SOME TESTS FAILED!",

        # --- Environment ---
        "env_title": "ENVIRONMENT CHECK",
        "env_stdout_ok": "Output goes to a terminal",
        "env_stdout_bad": "stdout is redirected — secrets may leak into a file!",
        "env_stdin_ok": "Input comes from the terminal",
        "env_stdin_bad": "stdin is not a terminal — interactive input is impossible!",
        "env_swap_ok": "Swap is not active",
        "env_swap_bad": "Swap is active ({count}) — secrets may end up on disk",
        "env_swap_unknown": "Swap: could not check (not Linux?)",
        "env_core_ok": "Core dumps are disabled",
        "env_core_bad": "Core dumps are enabled — run: ulimit -c 0",
        "env_core_unknown": "Core dumps: could not check",
        "env_root_ok": "Running as a regular user",
        "env_root_bad": "Running as root — not recommended",
        "env_net_ok": "Network interfaces are down",
        "env_net_bad": "Network is active ({ifaces}) — air-gap recommended",
        "env_net_unknown": "Network: could not check",
        "env_python": "Python {ver}",
        "env_libs": "Libraries: mnemonic {a}, shamir-mnemonic {b}",
        "env_issues": "ISSUES FOUND:",
        "env_recommend": "Recommendations:",
        "env_rec_swap": "swap:   sudo swapoff -a",
        "env_rec_core": "cores:  ulimit -c 0 (the program sets this itself)",
        "env_rec_net": "net:    disable interfaces or use an air-gapped machine",
        "env_clean": "The environment looks safe.",

        # --- Exit / signals ---
        "exit_cleaning": "Clearing memory and exiting...",
        "exit_close1": "Close the terminal window as well — this guarantees that",
        "exit_close2": "any remnants are removed from the terminal's memory!",
        "sig_interrupt": "Interrupted. Cleaning up and exiting...",
        "eof_exit": "Input interrupted (EOF). Cleaning up and exiting...",
    },

    "ru": {
        # --- Меню ---
        "app_tagline": "BIP-39 seed-фразы + SLIP-39 (Шамир) бэкапы",
        "menu_1": "Создать новую seed-фразу и бэкап",
        "menu_2": "Разделить существующую seed-фразу",
        "menu_3": "Восстановить seed из долей",
        "menu_4": "Запустить автоматический тест",
        "menu_5": "Проверить окружение",
        "menu_6": "Выход",
        "menu_choice": "Выберите действие:",
        "menu_unknown": "Неизвестная команда.",

        # --- Общий ввод ---
        "num_range": "Введите число от {min} до {max}.",
        "num_invalid": "Ошибка: введите целое число.",
        "yn_retry": "Введите 'y' (да) или 'n' (нет).",
        "enter_continue": "Нажмите Enter для продолжения...",
        "input_repeat": "(повторно)",
        "input_empty": "Пустой ввод. Попробуйте снова.",
        "input_mismatch": "Ввод не совпадает. Попробуйте снова.",
        "hidden_unavailable": "(Скрытый ввод недоступен — ввод будет виден)",

        # --- Предупреждение о приватности ---
        "privacy_title": "⚠  КРИТИЧЕСКАЯ ИНФОРМАЦИЯ  ⚠",
        "privacy_intro": "Сейчас будут отображены секретные данные.",
        "privacy_ensure": "Убедитесь что:",
        "privacy_1": "• Никто не видит ваш экран",
        "privacy_2": "• Не идёт запись экрана",
        "privacy_3": "• Нет камер, направленных на экран",
        "privacy_4": "• Терминал не логируется",
        "privacy_5": "• Под рукой бумага и ручка",
        "privacy_confirm": "Окружение безопасно. Продолжить?",

        # --- Отображение секретов ---
        "secret_write": "Запишите все слова ПО ПОРЯДКУ на бумагу.",
        "secret_no_copy": "Не фотографируйте. Не копируйте в файл.",
        "secret_count": "Всего слов: {count}",
        "secret_fp": "Fingerprint секрета: {fp}",
        "secret_fp_hint1": "Запишите fingerprint на лист — он нужен для",
        "secret_fp_hint2": "проверки правильности при восстановлении.",
        "secret_entered": "Нажмите Enter когда запишете всё...",
        "secret_confirm": "Вы записали всё правильно?",
        "secret_again": "Отображаю ещё раз...",

        "seed_title": "SEED-ФРАЗА (BIP-39)",
        "seed_hint": "Храните эту фразу так, как планируете использовать кошелёк.",

        "share_title": "ДОЛЯ {index} ИЗ {total} (СХЕМА {threshold}-of-{total})",
        "share_hint": "Запишите эту долю на ОТДЕЛЬНЫЙ лист бумаги.",
        "share_label": "Пометьте лист: «Доля {index}/{total}, схема {threshold}-of-{total}, FP: {fp}»",
        "share_entered": "Нажмите Enter когда запишете Долю {index}...",
        "share_confirm": "Доля {index} записана правильно?",

        # --- Выбор схемы ---
        "scheme_title": "НАСТРОЙКА СХЕМЫ SHAMIR",
        "scheme_t": "T = сколько долей нужно для восстановления",
        "scheme_n": "N = сколько долей всего создаётся",
        "scheme_examples": "Примеры:",
        "scheme_ex1": "  2-of-3  → любые 2 доли из 3",
        "scheme_ex2": "  3-of-5  → любые 3 доли из 5",
        "scheme_ex3": "  5-of-10 → любые 5 долей из 10",
        "scheme_storage": "Храните доли в РАЗНЫХ местах (дом, банк, родственники).",
        "scheme_total": "Общее количество долей N (2-{max}):",
        "scheme_threshold": "Порог восстановления T (2-{total}):",
        "scheme_chosen": "Выбрана схема: {threshold}-of-{total}",

        # --- Passphrase ---
        "pp_intro1": "Passphrase — второй фактор для SLIP-39 бэкапа.",
        "pp_intro2": "При восстановлении понадобятся: доли + этот passphrase.",
        "pp_warn_title": "ВАЖНО ПРОЧИТАТЬ",
        "pp_warn1": "Утеря passphrase = потеря доступа НАВСЕГДА,",
        "pp_warn2": "даже при наличии ВСЕХ долей!",
        "pp_warn3": "Храните passphrase отдельно от долей.",
        "pp_warn4": "Для записи будет показан fingerprint секрета —",
        "pp_warn5": "он позволяет проверить passphrase при восстановлении.",
        "pp_use": "Использовать passphrase?",
        "pp_enter": "Passphrase:",
        "pp_confirm": "Подтвердите passphrase:",
        "pp_empty": "Passphrase не может быть пустым.",
        "pp_mismatch": "Passphrase не совпадают. Попробуйте снова.",

        # --- Новый бэкап ---
        "new_title": "СОЗДАНИЕ НОВОГО БЭКАПА",
        "new_generating": "Генерация seed-фразы (256 бит энтропии)...",
        "splitting": "Создание разделения {threshold}-of-{total}...",
        "splitting_slow": "(может занять до минуты)",
        "split_error": "ОШИБКА: {err}",

        # --- Разделение существующей ---
        "split_title": "РАЗДЕЛЕНИЕ СУЩЕСТВУЮЩЕЙ SEED-ФРАЗЫ",
        "split_intro1": "Введите существующую BIP-39 seed-фразу (12-24 слова).",
        "split_intro2": "Ввод скрыт. Фразу нужно будет ввести дважды.",
        "seed_prompt": "Seed phrase",
        "checking": "Проверка checksum...",
        "checksum_bad": "ОШИБКА: неверная BIP-39 checksum.",
        "checksum_check": "Проверьте фразу на опечатки и попробуйте снова.",
        "checksum_ok": "Checksum корректна.",

        # --- Проверка ---
        "verify_title": "АВТОМАТИЧЕСКАЯ ПРОВЕРКА",
        "verify_running": "Проверка: восстановление из первых {threshold} долей...",
        "verify_ok": "ПРОВЕРКА ПРОЙДЕНА: {threshold} долей восстанавливают секрет.",
        "verify_bad": "ОШИБКА: восстановленный секрет не совпадает!",
        "verify_exc": "Ошибка проверки: {err}",
        "verify_failed": "ПРОВЕРКА НЕ ПРОЙДЕНА — не используйте эти доли!",

        # --- Итоговый отчёт ---
        "report_title": "ИТОГ ОПЕРАЦИИ",
        "report_scheme": "Схема:        {threshold}-of-{total}",
        "report_fp": "Fingerprint:  {fp}",
        "report_pp": "Passphrase:   {value}",
        "report_pp_yes": "ДА (не потеряйте!)",
        "report_pp_no": "нет",
        "report_remember": "Запомните:",
        "report_r1": "• Доли — в разных физических местах",
        "report_r2": "• Fingerprint — на каждом листе (сверка при восстановлении)",
        "report_r3": "• Passphrase — отдельно от долей!",
        "finish_enter": "Нажмите Enter для завершения...",
        "memory_cleared": "Секреты удалены из памяти (насколько позволяет Python).",
        "store_advice": "Храните доли в разных безопасных местах!",

        # --- Восстановление ---
        "rec_title": "ВОССТАНОВЛЕНИЕ SEED-ФРАЗЫ",
        "rec_intro1": "Введите доли по одной (каждая — фраза из 20-33 слов).",
        "rec_intro2": "Ввод будет ВИДЕН — проверяйте ввод на опечатки.",
        "rec_intro3": "После каждой доли программа пробует восстановить секрет.",
        "rec_intro4": "Можно ввести больше долей, чем требуется — программа выберет подходящую комбинацию.",
        "rec_pp_used": "Использовался ли passphrase при создании этого бэкапа?",
        "rec_pp_prompt": "Passphrase (Enter = нет):",
        "rec_share_header": "--- Доля {num} ---",
        "rec_share_prompt": "Введите долю (или Enter — опции):",
        "rec_first": "Сначала введите хотя бы одну долю.",
        "rec_dup": "Эта доля уже введена. Введите другую.",
        "rec_dup_slot": "Доля №{member} из этого набора уже введена. Введите другую долю.",
        "rec_foreign": "Эта доля принадлежит ДРУГОМУ бэкапу (другой идентификатор). Не смешивайте доли из разных бэкапов!",
        "rec_mixed": "Параметры этой доли отличаются от введённых ранее — вероятно, это доля из ДРУГОГО бэкапа. Не смешивайте доли из разных бэкапов!",
        "rec_invalid_share": "Это некорректная доля: {err}",
        "rec_share_bad_length": "Некорректная доля: ожидалось 20, 23, 27, 30 или 33 слова, получено {count}.",
        "rec_share_bad_words": "Некорректная доля: содержит слова, которых нет в списке слов SLIP-39.",
        "rec_status": "Собрано долей: {have} из {need} необходимых.",
        "rec_accepted": "Принято долей: {count}",
        "rec_pp_suspect_title": "Собрано достаточно долей, но расшифровать секрет не удаётся.",
        "rec_pp_suspect_hint": "Почти всегда это означает неверный passphrase.",
        "rec_pp_retry": "Ввести passphrase заново?",
        "rec_recovered": "Секрет восстановлен!",
        "rec_failed": "Пока не удаётся восстановить.",
        "rec_reasons": "Всё ещё не удаётся. Возможные причины:",
        "rec_reason1": "• Недостаточно долей (нужно T штук)",
        "rec_reason2": "• Неверный passphrase",
        "rec_reason3": "• Опечатки в долях",
        "rec_reason4": "• Доли из разных бэкапов",
        "rec_continue": "Продолжить ввод долей?",
        "rec_aborted": "Восстановление прервано. Секреты удалены из памяти.",
        "rec_fp_intro1": "На каждом листе долей записан fingerprint секрета.",
        "rec_fp_intro2": "Введите его для проверки (Enter = пропустить):",
        "rec_fp_prompt": "Fingerprint:",
        "rec_fp_match": "СОВПАДАЕТ ({fp}) — секрет верный.",
        "rec_fp_mismatch": "НЕ СОВПАДАЕТ!",
        "rec_fp_expected": "Ожидался: {fp}",
        "rec_fp_got": "Получен:   {fp}",
        "rec_fp_mean1": "Это означает: неверный passphrase, опечатки в долях или",
        "rec_fp_mean2": "доли от другого секрета. Результат НЕВЕРЕН — не используйте его!",
        "rec_fp_shown": "Fingerprint полученного секрета: {fp}",
        "rec_fp_manual": "(сверьте с листом долей вручную!)",
        "rec_show_blocked": "Отображение отключено: секрет не прошёл проверку.",
        "rec_convert_error": "ОШИБКА конвертации в BIP-39: {err}",

        # --- Тесты ---
        "test_title": "АВТОМАТИЧЕСКИЙ ТЕСТ",
        "test_intro": "Тест использует случайный одноразовый секрет.",
        "test_generating": "Генерация тестового секрета...",
        "test_splitting": "Разделение {threshold}-of-{total} (до минуты)...",
        "test_split_error": "Ошибка разделения: {err}",
        "test_1": "Тест 1: доли №1-{threshold}",
        "test_2": "Тест 2: доли №{start}-{end}",
        "test_3": "Тест 3: случайные доли ({threshold} шт.)",
        "test_4": "Тест 4: все {total} шт. сразу",
        "test_5": "Тест 5: {count} шт. (должно отказать)",
        "test_6": "Тест 6: неверный passphrase (не должен совпасть)",
        "test_7": "Тест 7: воспроизводимость fingerprint",
        "test_8": "Тест 8: доли в обратном порядке ({threshold} шт.)",
        "test_9": "Тест 9: лишние доли, порог определяется автоматически",
        "test_10": "Тест 10: посторонняя доля в наборе",
        "test_11": "Тест 11: нормализация ввода (регистр, пробелы)",
        "test_exc": "исключение — {err}",
        "test_result": "РЕЗУЛЬТАТ: {passed} из {total} тестов пройдено",
        "test_all_ok": "ВСЕ ТЕСТЫ ПРОЙДЕНЫ",
        "test_failed": "ЕСТЬ ПРОВАЛЕННЫЕ ТЕСТЫ!",

        # --- Окружение ---
        "env_title": "ПРОВЕРКА ОКРУЖЕНИЯ",
        "env_stdout_ok": "Вывод идёт в терминал",
        "env_stdout_bad": "stdout перенаправлен — секреты могут попасть в файл!",
        "env_stdin_ok": "Ввод с терминала",
        "env_stdin_bad": "stdin не терминал — интерактивный ввод невозможен!",
        "env_swap_ok": "Swap не активен",
        "env_swap_bad": "Swap активен ({count}) — секреты могут попасть на диск",
        "env_swap_unknown": "Swap: проверить не удалось (не Linux?)",
        "env_core_ok": "Core dumps отключены",
        "env_core_bad": "Core dumps включены — выполните: ulimit -c 0",
        "env_core_unknown": "Core dumps: проверить не удалось",
        "env_root_ok": "Запуск от обычного пользователя",
        "env_root_bad": "Запуск от root — не рекомендуется",
        "env_net_ok": "Сетевые интерфейсы неактивны",
        "env_net_bad": "Сеть активна ({ifaces}) — рекомендуется air-gap",
        "env_net_unknown": "Сеть: проверить не удалось",
        "env_python": "Python {ver}",
        "env_libs": "Библиотеки: mnemonic {a}, shamir-mnemonic {b}",
        "env_issues": "ОБНАРУЖЕНЫ ПРОБЛЕМЫ:",
        "env_recommend": "Рекомендации:",
        "env_rec_swap": "swap:  sudo swapoff -a",
        "env_rec_core": "core:  ulimit -c 0 (программа делает это сама)",
        "env_rec_net": "сеть:  отключите интерфейсы или используйте air-gap",
        "env_clean": "Окружение выглядит безопасным.",

        # --- Выход / сигналы ---
        "exit_cleaning": "Очистка памяти и выход...",
        "exit_close1": "Также закройте окно терминала — это гарантирует",
        "exit_close2": "удаление остатков из памяти терминала!",
        "sig_interrupt": "Прерывание. Очистка и выход...",
        "eof_exit": "Ввод прерван (EOF). Очистка и выход...",
    },
}

TEXT = {}


def set_language(code):
    """Activate a UI language."""
    global TEXT
    TEXT = TRANSLATIONS[code]


def t(key, **kwargs):
    """Translate a key with optional {placeholders}.

    Falls back to English, then to the key itself.
    """
    source = TEXT if key in TEXT else TRANSLATIONS["en"]
    s = source.get(key, key)
    return s.format(**kwargs) if kwargs else s


def select_language():
    """Ask the user which UI language to use (English default)."""
    clear_screen()
    print()
    print("  Language / Язык")
    print()
    print("  1. English")
    print("  2. Русский")
    print()
    while True:
        choice = input("  1 / 2 [1]: ").strip().lower()
        if choice in ("", "1", "en"):
            return "en"
        if choice in ("2", "ru"):
            return "ru"
        print("  Enter 1 or 2 / Введите 1 или 2")
        print()


# ============================================================
# Terminal helpers
# ============================================================

def clear_screen():
    """Clear the screen AND the scrollback buffer (ANSI, no shell)."""
    sys.stdout.write("\033[3J\033[2J\033[H")
    sys.stdout.flush()


def print_header(title):
    """Print a section header box."""
    width = 64
    print()
    print("╔" + "═" * (width - 2) + "╗")
    print("║" + title.center(width - 2) + "║")
    print("╚" + "═" * (width - 2) + "╝")
    print()


def print_warning(lines):
    """Print a warning box."""
    width = 60
    print()
    print("┌" + "─" * (width - 2) + "┐")
    for line in lines:
        pad = max(1, width - 4 - len(line))
        print("│ " + line + " " * pad + " │")
    print("└" + "─" * (width - 2) + "┘")
    print()


# ============================================================
# Memory hygiene
# ============================================================

def zero_bytearray(buf):
    """Overwrite a bytearray with zeros in place (reliable)."""
    if isinstance(buf, bytearray) and len(buf) > 0:
        for i in range(len(buf)):
            buf[i] = 0


def wipe(*objects):
    """Wipe secrets.

    Bytearrays are zeroed in place (guaranteed). Python strings cannot
    be securely erased — callers must assign None to those variables
    after calling wipe().
    """
    for obj in objects:
        if isinstance(obj, bytearray):
            zero_bytearray(obj)
    gc.collect()
    gc.collect()


def purge_memory():
    """Best-effort garbage collection."""
    gc.collect()
    gc.collect()


# ============================================================
# Input helpers
# ============================================================

def normalize_phrase(text):
    """Normalize a pasted mnemonic phrase.

    Both the BIP-39 and SLIP-39 wordlists are all-lowercase, so
    lowercasing and collapsing whitespace is always safe and repairs
    copy/paste artifacts (CAPS LOCK, double spaces, line breaks).
    """
    return " ".join(text.lower().split())


def ask_number(prompt, minimum, maximum):
    """Ask for an integer within a range."""
    while True:
        try:
            value = int(input(prompt).strip())
            if minimum <= value <= maximum:
                return value
            print("  " + t("num_range", min=minimum, max=maximum))
        except ValueError:
            print("  " + t("num_invalid"))


def ask_yes_no(prompt, default=True):
    """Ask a yes/no question."""
    hint = "[Y/n]" if default else "[y/N]"
    while True:
        answer = input(f"{prompt} {hint}: ").strip().lower()
        if not answer:
            return default
        if answer in ("y", "yes", "д", "да", "1"):
            return True
        if answer in ("n", "no", "н", "нет", "0"):
            return False
        print("  " + t("yn_retry"))


def get_hidden(prompt):
    """Hidden input (getpass) with a visible fallback."""
    try:
        value = getpass.getpass(prompt)
    except Exception:
        print("  " + t("hidden_unavailable"))
        value = input(prompt)
    return value.strip()


def get_hidden_confirmed(prompt):
    """Hidden input, entered twice for confirmation."""
    while True:
        value = get_hidden(prompt + ": ")
        if not value:
            print("  " + t("input_empty"))
            continue
        confirm = get_hidden(prompt + " " + t("input_repeat") + ": ")
        if value == confirm:
            return value
        print("  " + t("input_mismatch"))
        print()


# ============================================================
# Cryptography
# ============================================================

_MNEMO_CACHE = {}


def _mnemo():
    """Cached Mnemonic object (the wordlist is not a secret)."""
    if WORDLIST_LANGUAGE not in _MNEMO_CACHE:
        _MNEMO_CACHE[WORDLIST_LANGUAGE] = Mnemonic(WORDLIST_LANGUAGE)
    return _MNEMO_CACHE[WORDLIST_LANGUAGE]


def generate_seed():
    """Generate a new BIP-39 seed phrase (24 words, 256 bits)."""
    return _mnemo().generate(strength=BIP39_STRENGTH)


def validate_mnemonic(mnemonic):
    """Validate a BIP-39 checksum (supports 12/15/18/21/24 words)."""
    return _mnemo().check(mnemonic)


def mnemonic_to_entropy(mnemonic):
    """Convert a mnemonic to entropy (bytes)."""
    mnemo = _mnemo()
    if not mnemo.check(mnemonic):
        raise ValueError("Invalid BIP-39 checksum.")
    return mnemo.to_entropy(mnemonic)


def entropy_to_mnemonic(entropy):
    """Convert entropy back into a mnemonic."""
    return _mnemo().to_mnemonic(entropy)


def secret_fingerprint(entropy_bytes):
    """First 8 hex chars of SHA-256(entropy).

    A public identifier of the secret: it does not reveal the secret
    itself, but lets the user detect a wrong passphrase or foreign
    shares during recovery.
    """
    return hashlib.sha256(entropy_bytes).hexdigest()[:8].upper()


def get_passphrase():
    """Ask for an optional SLIP-39 passphrase (used when splitting)."""
    print()
    print("  " + t("pp_intro1"))
    print("  " + t("pp_intro2"))
    print()
    print_warning([
        t("pp_warn_title"),
        "",
        t("pp_warn1"),
        t("pp_warn2"),
        "",
        t("pp_warn3"),
        t("pp_warn4"),
        t("pp_warn5"),
    ])

    if not ask_yes_no("  " + t("pp_use"), default=False):
        return b""

    while True:
        passphrase = get_hidden("  " + t("pp_enter") + " ")
        if not passphrase:
            print("  " + t("pp_empty"))
            continue
        confirm = get_hidden("  " + t("pp_confirm") + " ")
        if passphrase == confirm:
            return passphrase.encode("utf-8")
        print("  " + t("pp_mismatch"))
        print()


def split_entropy(entropy_bytes, threshold, total, passphrase=b""):
    """Split entropy with SLIP-39. Returns a flat list of share phrases."""
    groups = [(threshold, total)]

    result = generate_mnemonics(
        group_threshold=1,
        groups=groups,
        master_secret=entropy_bytes,
        passphrase=passphrase,
        extendable=False,
        iteration_exponent=ITERATION_EXPONENT,
    )

    # generate_mnemonics returns [[share1..shareN]] — flatten the single group
    return result[0] if result else []


def _valid_threshold(text):
    """Parse a threshold string, returning None if out of range."""
    try:
        value = int(text)
    except (TypeError, ValueError):
        return None
    return value if 1 <= value <= MAX_SHARES else None


def _threshold_from_error(exc):
    """Extract the share threshold from a combine_mnemonics error.

    The reference library raises e.g.
    'Wrong number of mnemonics. Expected 4 mnemonics starting with
    "...", but 10 were provided.' when the subset size is wrong.
    This check runs before the slow passphrase KDF, which is what
    makes such failures cheap and the threshold discoverable.
    """
    m = _EXPECTED_COUNT_RE.search(str(exc))
    return _valid_threshold(m.group(1)) if m else None


def _is_cheap_failure(exc):
    """True when the failure is a wrong-subset-size (preprocessing).

    Cheap failures occur before the passphrase KDF and therefore do
    not consume the expensive-attempt budget.
    """
    return _threshold_from_error(exc) is not None


def probe_share(share):
    """Validate one share and extract its parameters (no KDF for T>=2).

    Structural checks first (word count, wordlist), then the optional
    reference decoder, then a single-share combine probe: a share of a
    T>=2 set always fails the count check BEFORE any key derivation,
    and the error names its threshold T.

    Returns (ok, threshold, group_index, member_index, identifier,
             error_code, error_detail); unknown values are None.
    error_code: None | "length" | "words" | "library".
    """
    words = share.split()

    # Structural check 1: length. SLIP-39 mnemonics for 16/20/24/28/32
    # byte secrets are 20/23/27/30/33 words. This also rejects pasted
    # BIP-39 phrases (12-24 words) and truncated pastes.
    if len(words) not in VALID_SHARE_WORD_COUNTS:
        return (False, None, None, None, None, "length", len(words))

    # Structural check 2: wordlist membership (if the wordlist was
    # importable). Catches most typos immediately.
    if _SLIP39_WORDSET is not None:
        if any(w not in _SLIP39_WORDSET for w in words):
            return (False, None, None, None, None, "words", None)

    # Preferred: the reference decoder (shamir-mnemonic >= 1.3.0),
    # which also provides identifier / group / member information.
    if _decode_mnemonic is not None:
        try:
            info = _decode_mnemonic(share)
            return (True,
                    getattr(info, "member_threshold", None),
                    getattr(info, "group_index", None),
                    getattr(info, "member_index", None),
                    getattr(info, "identifier", None),
                    None, None)
        except Exception:
            pass  # fall through to the message-based probe

    try:
        combine_mnemonics([share], passphrase=b"")
        # A share that combines alone is a 1-of-1 backup.
        return (True, 1, None, None, None, None, None)
    except Exception as e:
        thr = _threshold_from_error(e)
        if thr is not None:
            # Valid share of a T>=2 set; the error named its threshold.
            return (True, thr, None, None, None, None, None)
        if "checksum" in str(e).lower():
            # Structurally plausible but the checksum is broken —
            # a real typo. (A digest failure, by contrast, may mean a
            # valid 1-of-1 share protected by a passphrase, so it is
            # NOT treated as invalid here.)
            return (False, None, None, None, None, "library", str(e))
        # Unrecognized error: accept optimistically. A bad share can
        # never combine, so this cannot produce a wrong secret — the
        # fingerprint check remains the final safety net.
        return (True, None, None, None, None, None, None)


def try_combine(shares, passphrase, threshold=None):
    """Recover the master secret from shares, tolerating extras.

    The reference combine_mnemonics() accepts EXACTLY T shares per
    group, so subsets must be selected by the caller. Three phases:

      Phase 1 - the whole set as entered. Succeeds when its size
                equals T; otherwise the count error reveals T.
      Phase 2 - T-sized subsets: first T, last T, then all in order.
                (The first/last ordering survives a foreign or broken
                share entered at either end.)
      Phase 3 - candidate thresholds discovered by probing each share
                individually (cheap, before the KDF), then subsets of
                those sizes. Handles mixed sets from several backups
                and a wrongly pinned threshold.

    Cheap failures (wrong subset size) never consume the KDF budget.
    Returns entropy bytes or None.
    """
    if not shares:
        return None
    k = len(shares)

    # --- Phase 1: the whole set ---
    try:
        return combine_mnemonics(list(shares), passphrase=passphrase)
    except Exception as e:
        learned = _threshold_from_error(e)
        if learned is not None:
            threshold = learned

    # --- Phase 2: T-sized subsets ---
    if threshold is not None and threshold < k:
        budget = KDF_ATTEMPT_BUDGET
        calls = 0
        tried = set()
        ordered = [tuple(shares[:threshold]), tuple(shares[-threshold:])]
        ordered.extend(combinations(shares, threshold))
        for subset in ordered:
            if subset in tried:
                continue
            tried.add(subset)
            calls += 1
            if calls > MAX_SCAN_CALLS:
                break
            try:
                return combine_mnemonics(list(subset), passphrase=passphrase)
            except Exception as e:
                if not _is_cheap_failure(e):
                    budget -= 1
                    if budget <= 0:
                        break
        # fall through to Phase 3 (mixed sets, wrong pin)

    # --- Phase 3: candidate thresholds, discovered per share ---
    # A single share of a T>=2 set always fails the count check before
    # the KDF, so probing every share is cheap and names each one's T.
    candidates = set()
    for s in shares:
        try:
            combine_mnemonics([s], passphrase=passphrase)
            continue  # a 1-of-1 share: Phase 1 already covers k == 1
        except Exception as e:
            thr = _threshold_from_error(e)
            if thr is not None and thr > 1:
                candidates.add(thr)

    calls = 0
    for size in sorted(candidates):
        if size > k:
            continue
        size_budget = KDF_ATTEMPT_BUDGET
        for subset in combinations(shares, size):
            calls += 1
            if calls > MAX_SCAN_CALLS:
                return None
            try:
                return combine_mnemonics(list(subset), passphrase=passphrase)
            except Exception as e:
                if not _is_cheap_failure(e):
                    size_budget -= 1
                    if size_budget <= 0:
                        break  # next candidate size, fresh budget
    return None


# ============================================================
# Secret display
# ============================================================

def _render_words(words, per_line=4):
    """Render words as a numbered grid: '1. word' per cell."""
    lines = []
    for i in range(0, len(words), per_line):
        chunk = words[i:i + per_line]
        parts = []
        for j, word in enumerate(chunk):
            num = i + j + 1
            cell = f"{num:2d}. {word}"
            parts.append(cell.ljust(16))
        lines.append("  " + "".join(parts).rstrip())
    return "\n".join(lines)


def confirm_privacy():
    """Show the privacy warning and ask for confirmation."""
    print_warning([
        t("privacy_title"),
        "",
        t("privacy_intro"),
        "",
        t("privacy_ensure"),
        t("privacy_1"),
        t("privacy_2"),
        t("privacy_3"),
        t("privacy_4"),
        t("privacy_5"),
    ])
    return ask_yes_no("  " + t("privacy_confirm"))


def _show_secret_words(title, words, fingerprint, footer_lines,
                       enter_msg, confirm_msg):
    """Display one secret, wait for confirmation, clear the screen."""
    while True:
        clear_screen()
        print_header(title)
        print("  " + t("secret_write"))
        print("  " + t("secret_no_copy"))
        print()
        print(_render_words(words))
        print()
        print("  " + t("secret_count", count=len(words)))
        print()
        print("  " + t("secret_fp", fp=fingerprint))
        print("  " + t("secret_fp_hint1"))
        print("  " + t("secret_fp_hint2"))
        print()
        for line in footer_lines:
            print("  " + line)
        print()

        input("  " + enter_msg)
        clear_screen()

        if ask_yes_no("  " + confirm_msg):
            break
        print("  " + t("secret_again"))


def display_seed_phrase(mnemonic, fingerprint):
    """Show a BIP-39 seed phrase."""
    _show_secret_words(
        t("seed_title"),
        mnemonic.split(),
        fingerprint,
        [t("seed_hint")],
        t("secret_entered"),
        t("secret_confirm"),
    )


def display_share(share, index, total, threshold, fingerprint):
    """Show one SLIP-39 share."""
    _show_secret_words(
        t("share_title", index=index, total=total, threshold=threshold),
        share.split(),
        fingerprint,
        [
            t("share_hint"),
            t("share_label",
              index=index, total=total, threshold=threshold, fp=fingerprint),
        ],
        t("share_entered", index=index),
        t("share_confirm", index=index),
    )


# ============================================================
# Scheme selection
# ============================================================

def _choose_scheme():
    """Select the Shamir threshold and share count."""
    print_header(t("scheme_title"))

    print("  " + t("scheme_t"))
    print("  " + t("scheme_n"))
    print()
    print("  " + t("scheme_examples"))
    print("  " + t("scheme_ex1"))
    print("  " + t("scheme_ex2"))
    print("  " + t("scheme_ex3"))
    print()
    print("  " + t("scheme_storage"))
    print()

    total = ask_number(
        "  " + t("scheme_total", max=MAX_SHARES) + " ",
        2, MAX_SHARES
    )
    threshold = ask_number(
        "  " + t("scheme_threshold", total=total) + " ",
        2, total
    )

    print()
    print("  " + t("scheme_chosen", threshold=threshold, total=total))
    print()
    return threshold, total


# ============================================================
# Core operations
# ============================================================

def _verify_shares(entropy_bytes, shares, threshold, passphrase):
    """Automatic check: the first T shares must restore the secret."""
    print("  " + t("verify_running", threshold=threshold))
    try:
        recovered = combine_mnemonics(shares[:threshold], passphrase=passphrase)
        if entropy_bytes == recovered:
            print("  ✓ " + t("verify_ok", threshold=threshold))
            return True
        print("  ✗ " + t("verify_bad"))
        return False
    except Exception as e:
        print("  ✗ " + t("verify_exc", err=e))
        return False


def _final_report(fingerprint, threshold, total, used_passphrase):
    """Print the operation summary."""
    print()
    print("  " + "─" * 50)
    print("  " + t("report_title"))
    print("  " + "─" * 50)
    print("  " + t("report_scheme", threshold=threshold, total=total))
    print("  " + t("report_fp", fp=fingerprint))
    print("  " + t("report_pp",
                  value=(t("report_pp_yes") if used_passphrase
                         else t("report_pp_no"))))
    print()
    print("  " + t("report_remember"))
    print("  " + t("report_r1"))
    print("  " + t("report_r2"))
    if used_passphrase:
        print("  " + t("report_r3"))
    print()


def generate_new_backup():
    """Generate a new seed phrase and split it with Shamir."""
    clear_screen()
    print_header(t("new_title"))

    if not confirm_privacy():
        return

    print()
    print("  " + t("new_generating"))
    mnemonic = generate_seed()
    entropy = bytearray(mnemonic_to_entropy(mnemonic))
    fingerprint = secret_fingerprint(bytes(entropy))

    display_seed_phrase(mnemonic, fingerprint)

    threshold, total = _choose_scheme()
    passphrase = get_passphrase()

    clear_screen()
    print("  " + t("splitting", threshold=threshold, total=total))
    print("  " + t("splitting_slow"))
    print()

    try:
        shares = split_entropy(bytes(entropy), threshold, total, passphrase)
    except Exception as e:
        print("  ✗ " + t("split_error", err=e))
        wipe(entropy)
        mnemonic = None
        passphrase = None
        purge_memory()
        return

    for index, share in enumerate(shares, start=1):
        display_share(share, index, total, threshold, fingerprint)

    clear_screen()
    print_header(t("verify_title"))
    print()
    ok = _verify_shares(bytes(entropy), shares, threshold, passphrase)

    _final_report(fingerprint, threshold, total, bool(passphrase))

    if not ok:
        print("  ⚠  " + t("verify_failed"))
        print()

    input("  " + t("finish_enter"))
    clear_screen()

    wipe(entropy)
    mnemonic = None
    shares = None
    passphrase = None
    purge_memory()

    print("  " + t("memory_cleared"))
    print("  " + t("store_advice"))
    print()


def split_existing_mnemonic():
    """Split an existing seed phrase with Shamir."""
    clear_screen()
    print_header(t("split_title"))

    if not confirm_privacy():
        return

    print()
    print("  " + t("split_intro1"))
    print("  " + t("split_intro2"))
    print()

    mnemonic = get_hidden_confirmed("  " + t("seed_prompt"))
    # Repair copy/paste artifacts (case, double spaces, line breaks).
    mnemonic = normalize_phrase(mnemonic)

    print()
    print("  " + t("checking"))

    if not validate_mnemonic(mnemonic):
        print("  ✗ " + t("checksum_bad"))
        print("  " + t("checksum_check"))
        mnemonic = None
        purge_memory()
        return

    print("  ✓ " + t("checksum_ok"))

    entropy = bytearray(mnemonic_to_entropy(mnemonic))
    fingerprint = secret_fingerprint(bytes(entropy))

    threshold, total = _choose_scheme()
    passphrase = get_passphrase()

    clear_screen()
    print("  " + t("splitting", threshold=threshold, total=total))
    print("  " + t("splitting_slow"))
    print()

    try:
        shares = split_entropy(bytes(entropy), threshold, total, passphrase)
    except Exception as e:
        print("  ✗ " + t("split_error", err=e))
        wipe(entropy)
        mnemonic = None
        passphrase = None
        purge_memory()
        return

    for index, share in enumerate(shares, start=1):
        display_share(share, index, total, threshold, fingerprint)

    clear_screen()
    print_header(t("verify_title"))
    print()
    ok = _verify_shares(bytes(entropy), shares, threshold, passphrase)

    _final_report(fingerprint, threshold, total, bool(passphrase))

    if not ok:
        print("  ⚠  " + t("verify_failed"))
        print()

    input("  " + t("finish_enter"))
    clear_screen()

    wipe(entropy)
    mnemonic = None
    shares = None
    passphrase = None
    purge_memory()

    print("  " + t("memory_cleared"))
    print()


def recover_seed():
    """Recover a seed phrase from Shamir shares."""
    clear_screen()
    print_header(t("rec_title"))

    if not confirm_privacy():
        return

    print()
    print("  " + t("rec_intro1"))
    print("  " + t("rec_intro2"))
    print("  " + t("rec_intro3"))
    print("  " + t("rec_intro4"))
    print()

    # Ask about the passphrase UP FRONT, so the user is never stuck.
    pp = None
    if ask_yes_no("  " + t("rec_pp_used"), default=False):
        pp = get_hidden("  " + t("rec_pp_prompt") + " ")
        passphrase = pp.encode("utf-8") if pp else b""
        pp = None
    else:
        passphrase = b""

    print()

    shares = []
    seen_texts = set()   # exact-text dedup (always active)
    slots = set()        # (identifier, group, member) dedup (if known)
    identifier = None
    threshold = None     # learned from the shares themselves
    result = None

    def attempt():
        """Try to recover with everything collected so far."""
        if not shares:
            return None
        return try_combine(shares, passphrase, threshold)

    def cleanup_state():
        """Drop all recovery state (used on abort and on success)."""
        nonlocal shares, passphrase, pp, seen_texts, slots
        nonlocal identifier, threshold
        shares = None
        passphrase = None
        pp = None
        seen_texts = None
        slots = None
        identifier = None
        threshold = None
        purge_memory()

    while True:
        # Try to recover with the shares collected so far.
        result = attempt()
        if result is not None:
            break

        # Enough distinct shares but decryption fails: almost
        # certainly a wrong passphrase. (With mixed shares from
        # several backups this heuristic can fire early — the
        # message deliberately says "almost always".)
        if threshold is not None and len(shares) >= threshold:
            print()
            print("  " + t("rec_pp_suspect_title"))
            print("  " + t("rec_pp_suspect_hint"))
            print()
            if ask_yes_no("  " + t("rec_pp_retry"), default=True):
                pp = get_hidden("  " + t("rec_pp_prompt") + " ")
                passphrase = pp.encode("utf-8") if pp else b""
                pp = None
                result = attempt()
                if result is not None:
                    break
            if not ask_yes_no("  " + t("rec_continue"), default=False):
                cleanup_state()
                print("  " + t("rec_aborted"))
                print()
                return
            # The user wants to add more shares (suspects typos).

        print("  " + t("rec_share_header", num=len(shares) + 1))
        share = normalize_phrase(input("  " + t("rec_share_prompt") + " "))

        if not share:
            if not shares:
                print("  " + t("rec_first"))
                print()
                continue

            # Empty input: offer passphrase change / more shares / exit
            print()
            if ask_yes_no("  " + t("rec_pp_retry"), default=False):
                pp = get_hidden("  " + t("rec_pp_prompt") + " ")
                passphrase = pp.encode("utf-8") if pp else b""
                pp = None
                result = attempt()
                if result is not None:
                    break
            print("  " + t("rec_reasons"))
            for k in (1, 2, 3, 4):
                print("  " + t("rec_reason%d" % k))
            print()
            if not ask_yes_no("  " + t("rec_continue"), default=True):
                cleanup_state()
                print("  " + t("rec_aborted"))
                print()
                return
            continue

        if share in seen_texts:
            print("  " + t("rec_dup"))
            print()
            continue

        # Immediate structural validation of the entered share.
        (ok, thr, group_index, member_index, share_id,
         err_code, err_detail) = probe_share(share)

        if not ok:
            if err_code == "length":
                print("  ✗ " + t("rec_share_bad_length", count=err_detail))
            elif err_code == "words":
                print("  ✗ " + t("rec_share_bad_words"))
            else:
                print("  ✗ " + t("rec_invalid_share", err=err_detail))
            print()
            continue

        if thr is not None:
            if threshold is None:
                threshold = thr
            elif thr != threshold:
                print("  ⚠  " + t("rec_mixed"))
                print()
        if share_id is not None:
            if identifier is not None and share_id != identifier:
                print("  ⚠  " + t("rec_foreign"))
                print()
            identifier = share_id
        if group_index is not None and member_index is not None:
            slot = (share_id, group_index, member_index)
            if slot in slots:
                print("  " + t("rec_dup_slot", member=member_index + 1))
                print()
                continue
            slots.add(slot)

        seen_texts.add(share)
        shares.append(share)

        if threshold is not None:
            print("  ✓ " + t("rec_status",
                             have=len(shares), need=threshold))
        else:
            print("  ✓ " + t("rec_accepted", count=len(shares)))
        print()

    # Recovered
    entropy = bytearray(result)
    result = None
    print()
    print("  ✓ " + t("rec_recovered"))
    print()

    # Fingerprint verification against the share sheets
    print("  " + t("rec_fp_intro1"))
    print("  " + t("rec_fp_intro2"))
    fp_entered = input("  " + t("rec_fp_prompt") + " ").strip().upper()
    fp_entered = fp_entered.replace(" ", "").replace(":", "").replace("FP", "")
    print()

    fp_actual = secret_fingerprint(bytes(entropy))
    fp_ok = True

    if fp_entered:
        if fp_entered == fp_actual:
            print("  ✓ " + t("rec_fp_match", fp=fp_actual))
        else:
            fp_ok = False
            print("  ✗ " + t("rec_fp_mismatch"))
            print("    " + t("rec_fp_expected", fp=fp_entered))
            print("    " + t("rec_fp_got", fp=fp_actual))
            print()
            print("    " + t("rec_fp_mean1"))
            print("    " + t("rec_fp_mean2"))
            print()
    else:
        print("  " + t("rec_fp_shown", fp=fp_actual))
        print("  " + t("rec_fp_manual"))
        print()

    # Convert to BIP-39
    try:
        mnemonic = entropy_to_mnemonic(bytes(entropy))
    except Exception as e:
        print("  ✗ " + t("rec_convert_error", err=e))
        wipe(entropy)
        cleanup_state()
        return

    if fp_ok:
        display_seed_phrase(mnemonic, fp_actual)
    else:
        # Wrong passphrase / foreign shares — do not show the bogus secret
        print("  ⚠  " + t("rec_show_blocked"))
        input("  " + t("enter_continue"))

    clear_screen()
    wipe(entropy)
    mnemonic = None
    cleanup_state()

    print("  " + t("memory_cleared"))
    print()


def test_recovery():
    """Automatic test suite on a random disposable secret."""
    clear_screen()
    print_header(t("test_title"))

    print("  " + t("test_intro"))
    print()

    threshold, total = _choose_scheme()

    results = []

    def check(name, fn):
        try:
            ok = fn()
            print(f"  {'✓' if ok else '✗'} {name}")
        except Exception as e:
            print(f"  ✗ {name} — {t('test_exc', err=e)}")
            ok = False
        results.append(ok)

    print("  " + t("test_generating"))
    mnemonic = generate_seed()
    entropy = bytearray(mnemonic_to_entropy(mnemonic))

    print("  " + t("test_splitting", threshold=threshold, total=total))
    try:
        shares = split_entropy(bytes(entropy), threshold, total, b"")
    except Exception as e:
        print("  ✗ " + t("test_split_error", err=e))
        return

    fp = secret_fingerprint(bytes(entropy))
    print(f"  Fingerprint: {fp}")
    print()

    # Test 1: the first T shares (exact count)
    check(t("test_1", threshold=threshold),
          lambda: combine_mnemonics(shares[:threshold], passphrase=b"")
          == bytes(entropy))

    # Test 2: the last T shares (exact count)
    last_start = total - threshold + 1
    check(t("test_2", start=last_start, end=total),
          lambda: combine_mnemonics(shares[-threshold:], passphrase=b"")
          == bytes(entropy))

    # Test 3: random T shares (exact count)
    sample = random.sample(shares, threshold)
    check(t("test_3", threshold=threshold),
          lambda: combine_mnemonics(sample, passphrase=b"") == bytes(entropy))

    # Test 4: ALL N shares at once — the robust recovery path must
    # select a valid T-subset automatically (this is what users do).
    check(t("test_4", total=total),
          lambda: try_combine(shares, b"", threshold=threshold)
          == bytes(entropy))

    # Test 5: T-1 shares must be rejected
    def test_insufficient():
        try:
            combine_mnemonics(shares[:threshold - 1], passphrase=b"")
            return False   # recovery succeeded — that is a bug
        except Exception:
            return True
    check(t("test_5", count=threshold - 1), test_insufficient)

    # Test 6: a wrong passphrase must not yield the original secret
    def test_wrong_passphrase():
        result = try_combine(shares[:threshold], b"wrong-passphrase-test",
                             threshold=threshold)
        return result is None or result != bytes(entropy)
    check(t("test_6"), test_wrong_passphrase)

    # Test 7: fingerprint reproducibility
    check(t("test_7"),
          lambda: secret_fingerprint(
              combine_mnemonics(shares[:threshold], passphrase=b"")) == fp)

    # Test 8: T shares in reverse order (order must not matter)
    reversed_shares = list(reversed(shares[:threshold]))
    check(t("test_8", threshold=threshold),
          lambda: combine_mnemonics(reversed_shares, passphrase=b"")
          == bytes(entropy))

    # Test 9: extra shares WITHOUT telling the program the threshold —
    # it must discover the right subset on its own.
    if threshold < total:
        extra = shares[:threshold] + [shares[-1]]
        check(t("test_9"),
              lambda: try_combine(extra, b"") == bytes(entropy))

    # Test 10: a foreign share (from an unrelated backup) mixed into
    # the set must not prevent recovery of the original secret.
    def test_foreign_share():
        junk_mnemonic = generate_seed()
        junk_shares = split_entropy(
            mnemonic_to_entropy(junk_mnemonic), 2, 3, b"")
        mixed = shares[:threshold] + [junk_shares[0]]
        return try_combine(mixed, b"") == bytes(entropy)
    check(t("test_10"), test_foreign_share)

    # Test 11: pasted text with wrong case / extra spaces must be
    # normalized back to the canonical share.
    def test_normalization():
        scrambled = "   " + shares[0].upper().replace(" ", "   ") + "  "
        return normalize_phrase(scrambled) == shares[0]
    check(t("test_11"), test_normalization)

    print()
    print("  " + "═" * 50)
    passed = sum(1 for ok in results if ok)
    print("  " + t("test_result", passed=passed, total=len(results)))
    if passed == len(results):
        print("  " + t("test_all_ok") + " ✓")
    else:
        print("  " + t("test_failed"))
    print("  " + "═" * 50)

    wipe(entropy)
    mnemonic = None
    shares = None
    purge_memory()

    print()
    input("  " + t("enter_continue"))
    clear_screen()


# ============================================================
# Environment check (via /proc and /sys, no shell calls)
# ============================================================

def check_environment():
    """Check the operating environment for security issues."""
    clear_screen()
    print_header(t("env_title"))
    print()

    issues = []
    info = []

    # 1: stdout must be a terminal
    if sys.stdout.isatty():
        info.append("✓ " + t("env_stdout_ok"))
    else:
        issues.append("✗ " + t("env_stdout_bad"))

    # 2: stdin must be a terminal
    if sys.stdin.isatty():
        info.append("✓ " + t("env_stdin_ok"))
    else:
        issues.append("✗ " + t("env_stdin_bad"))

    # 3: swap (Linux)
    try:
        with open("/proc/swaps") as f:
            active = [l for l in f
                      if l.strip() and not l.startswith("Filename")]
        if active:
            issues.append("✗ " + t("env_swap_bad", count=len(active)))
        else:
            info.append("✓ " + t("env_swap_ok"))
    except OSError:
        info.append("? " + t("env_swap_unknown"))

    # 4: core dumps
    try:
        import resource
        soft, _ = resource.getrlimit(resource.RLIMIT_CORE)
        if soft == 0:
            info.append("✓ " + t("env_core_ok"))
        else:
            issues.append("✗ " + t("env_core_bad"))
    except Exception:
        info.append("? " + t("env_core_unknown"))

    # 5: running as root
    if os.name == "posix":
        try:
            if os.geteuid() == 0:
                issues.append("⚠  " + t("env_root_bad"))
            else:
                info.append("✓ " + t("env_root_ok"))
        except AttributeError:
            pass

    # 6: network interfaces (Linux, via /sys)
    net_up = []
    try:
        for iface in os.listdir("/sys/class/net"):
            if iface == "lo":
                continue
            try:
                with open(f"/sys/class/net/{iface}/operstate") as f:
                    if f.read().strip() == "up":
                        net_up.append(iface)
            except OSError:
                pass
        if net_up:
            issues.append("⚠  " + t("env_net_bad", ifaces=", ".join(net_up)))
        else:
            info.append("✓ " + t("env_net_ok"))
    except OSError:
        info.append("? " + t("env_net_unknown"))

    # 7: Python version
    info.append("✓ " + t("env_python",
                          ver=f"{sys.version_info.major}.{sys.version_info.minor}"))

    # 8: library versions
    try:
        from importlib.metadata import version as pkg_version
        libs = t("env_libs",
                 a=pkg_version("mnemonic"),
                 b=pkg_version("shamir-mnemonic"))
    except Exception:
        libs = t("env_libs", a="?", b="?")
    info.append("✓ " + libs)

    # Output
    print("  " + "─" * 50)
    for line in info:
        print("  " + line)
    print("  " + "─" * 50)
    print()

    if issues:
        print("  ⚠  " + t("env_issues"))
        print()
        for issue in issues:
            print("  " + issue)
        print()
        print("  " + t("env_recommend"))
        print("    " + t("env_rec_swap"))
        print("    " + t("env_rec_core"))
        print("    " + t("env_rec_net"))
    else:
        print("  ✓ " + t("env_clean"))

    return len(issues)


# ============================================================
# Menu
# ============================================================

def show_menu():
    """Main menu loop."""
    while True:
        clear_screen()
        print_header(f"{APP_NAME} v{APP_VERSION}")
        print("      " + t("app_tagline"))
        print()
        print("  ──────────────────────────────────────────")
        print("   1. " + t("menu_1"))
        print("   2. " + t("menu_2"))
        print("   3. " + t("menu_3"))
        print("   4. " + t("menu_4"))
        print("   5. " + t("menu_5"))
        print("   6. " + t("menu_6"))
        print("  ──────────────────────────────────────────")
        print()

        choice = input("  " + t("menu_choice") + " ").strip()

        if choice == "1":
            generate_new_backup()
        elif choice == "2":
            split_existing_mnemonic()
        elif choice == "3":
            recover_seed()
        elif choice == "4":
            test_recovery()
        elif choice == "5":
            check_environment()
            input("\n  " + t("enter_continue"))
            clear_screen()
        elif choice == "6":
            print()
            print("  " + t("exit_cleaning"))
            purge_memory()
            clear_screen()
            print()
            print("  " + t("exit_close1"))
            print("  " + t("exit_close2"))
            print()
            break
        else:
            print("  " + t("menu_unknown"))


# ============================================================
# Entry point
# ============================================================

def _signal_handler(signum, frame):
    """Signal handler — emergency cleanup and exit."""
    print("\n\n  " + t("sig_interrupt"))
    purge_memory()
    clear_screen()
    sys.exit(0)


def main():
    # Signal handlers
    signal.signal(signal.SIGINT, _signal_handler)
    if os.name == "posix":
        try:
            signal.signal(signal.SIGHUP, _signal_handler)
            signal.signal(signal.SIGTERM, _signal_handler)
        except (AttributeError, ValueError, OSError):
            pass

        # Disable core dumps for this process
        try:
            import resource
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        except Exception:
            pass

    # stdin must be a terminal (interactive tool)
    if not sys.stdin.isatty():
        print("stdin is not a terminal / stdin не терминал — exiting.",
              file=sys.stderr)
        sys.exit(1)

    # stdout redirect warning (bilingual — language not selected yet)
    if not sys.stdout.isatty():
        print("=" * 60, file=sys.stderr)
        print("WARNING: stdout is redirected! Secrets may be written to a file.",
              file=sys.stderr)
        print("ВНИМАНИЕ: stdout перенаправлен! Секреты могут попасть в файл.",
              file=sys.stderr)
        print("Press Ctrl+C to exit / Ctrl+C для выхода.", file=sys.stderr)
        print("=" * 60, file=sys.stderr)
        try:
            answer = input("Continue anyway? / Продолжить? [y/N]: ")
        except EOFError:
            sys.exit(1)
        if answer.strip().lower() not in ("y", "yes", "д", "да"):
            sys.exit(1)

    # UI language
    set_language(select_language())

    try:
        show_menu()
    except EOFError:
        print("\n\n  " + t("eof_exit"))
        purge_memory()
        clear_screen()
        sys.exit(1)


if __name__ == "__main__":
    main()
