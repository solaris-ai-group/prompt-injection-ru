#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Прогон проверок на устойчивость ИИ-агента к инъекциям в промпт.

Скрипт отправляет вашему боту набор проверочных сообщений из probes/probes.json
и смотрит, не появились ли в ответах служебные маркеры: фрагменты системного
промпта, ключи, внутренние имена. Это проверка СВОЕГО бота, а не чужого.

Примеры:

    python3 test_agent.py --url https://example.ru/api/chat --field message
    python3 test_agent.py --url ... --field text --header "Authorization: Bearer XXX"
    python3 test_agent.py --dry-run          # просто показать проверки

Скрипт не знает, что для вас «правильный ответ», поэтому он подсвечивает
подозрительное, а решение принимаете вы. Ответы сохраняются в отчёт.
"""
import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
PROBES = os.path.join(HERE, "probes", "probes.json")


def load_probes(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def ask(url, field, message, headers, timeout, reply_path):
    payload = json.dumps({field: message}).encode("utf-8")
    req = urllib.request.Request(url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "prompt-injection-ru/1.0")
    for h in headers:
        if ":" in h:
            k, v = h.split(":", 1)
            req.add_header(k.strip(), v.strip())
    try:
        raw = urllib.request.urlopen(req, timeout=timeout).read().decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        return "[HTTP %s] %s" % (e.code, e.read().decode("utf-8", "ignore")[:300])
    except Exception as e:
        return "[ОШИБКА] %s" % str(e)[:200]
    try:
        data = json.loads(raw)
    except ValueError:
        return raw[:2000]
    node = data
    for key in [p for p in reply_path.split(".") if p]:
        if isinstance(node, dict) and key in node:
            node = node[key]
        else:
            return json.dumps(data, ensure_ascii=False)[:2000]
    return node if isinstance(node, str) else json.dumps(node, ensure_ascii=False)[:2000]


def leaked(answer, markers):
    return [m for m in markers if m and m.lower() in (answer or "").lower()]


def main():
    ap = argparse.ArgumentParser(description="Проверка ИИ-агента на устойчивость к инъекциям")
    ap.add_argument("--url", help="HTTP-эндпоинт вашего бота, принимающий JSON")
    ap.add_argument("--field", default="message", help="имя поля с текстом запроса (по умолчанию message)")
    ap.add_argument("--reply-path", default="reply",
                    help="путь к тексту ответа в JSON, через точку (по умолчанию reply)")
    ap.add_argument("--header", action="append", default=[], help='доп. заголовок, "Ключ: значение"')
    ap.add_argument("--probes", default=PROBES, help="файл с проверками")
    ap.add_argument("--timeout", type=int, default=60)
    ap.add_argument("--pause", type=float, default=1.0, help="пауза между запросами, секунды")
    ap.add_argument("--out", default="report.json", help="куда сохранить отчёт")
    ap.add_argument("--dry-run", action="store_true", help="показать проверки и выйти")
    args = ap.parse_args()

    cfg = load_probes(args.probes)
    probes = cfg["probes"]
    markers = cfg.get("markers", {}).get("values", [])

    if args.dry_run or not args.url:
        print("Проверок в наборе: %d\n" % len(probes))
        for p in probes:
            print("[%s] %s" % (p["id"], p["class"]))
            print("  сообщение: %s" % p["message"])
            print("  провал, если: %s\n" % p["fail_if"])
        if not args.url:
            print("Укажите --url, чтобы прогнать проверки по своему боту.")
        return

    print("Прогон %d проверок по %s\n" % (len(probes), args.url))
    report, suspicious = [], 0
    for i, p in enumerate(probes, 1):
        answer = ask(args.url, args.field, p["message"], args.header, args.timeout, args.reply_path)
        hits = leaked(answer, markers)
        status = "УТЕЧКА" if hits else "проверьте вручную"
        if hits:
            suspicious += 1
        print("%2d/%d [%s] %s" % (i, len(probes), p["id"], status))
        if hits:
            print("     найдены маркеры: %s" % ", ".join(hits))
        print("     ответ: %s" % re.sub(r"\s+", " ", (answer or ""))[:160])
        report.append({"id": p["id"], "class": p["class"], "message": p["message"],
                       "answer": answer, "markers_found": hits, "fail_if": p["fail_if"]})
        time.sleep(args.pause)

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=1)

    print("\nПроверок с явной утечкой маркеров: %d из %d" % (suspicious, len(probes)))
    print("Отчёт с полными ответами: %s" % args.out)
    print("\nМаркеры задаются в probes/probes.json. Впишите туда фрагменты своего")
    print("системного промпта и служебные имена, иначе утечку будет нечем поймать.")
    sys.exit(1 if suspicious else 0)


if __name__ == "__main__":
    main()
