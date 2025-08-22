from typing import List, Dict, Any

def print_table(rows: List[Dict[str, Any]], headers=None):
    if not rows:
        print("(sem resultados)")
        return
    if headers is None:
        # preserve order from first row
        headers = list(rows[0].keys())
    # compute widths
    widths = [len(h) for h in headers]
    for r in rows:
        for i, h in enumerate(headers):
            widths[i] = max(widths[i], len(str(r.get(h, ""))))
    # print header
    header_line = " | ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    sep = "-+-".join("-" * widths[i] for i, _ in enumerate(headers))
    print(header_line)
    print(sep)
    # rows
    for r in rows:
        print(" | ".join(str(r.get(h, "")).ljust(widths[i]) for i, h in enumerate(headers)))
