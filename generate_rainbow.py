import hashlib, json, os

WORDLIST = os.path.join("data", "wordlist.txt")
OUT_JSON = os.path.join("data", "rainbow_table.json")

def hashes_for(password: str):
    p = password.encode()
    return {
        hashlib.md5(p).hexdigest(): password,
        hashlib.sha256(p).hexdigest(): password,
        hashlib.sha512(p).hexdigest(): password
    }

def main():
    if not os.path.exists(WORDLIST):
        # create a small default wordlist if missing
        os.makedirs("data", exist_ok=True)
        with open(WORDLIST, "w", encoding="utf-8") as f:
            f.write("\n".join([
                "password","123456","letmein","admin","qwerty",
                "iloveyou","welcome","dragon","superman","batman"
            ]))
        print(f"📂 Created sample wordlist at {WORDLIST}")

    with open(WORDLIST, "r", encoding="utf-8") as f:
        words = [w.strip() for w in f if w.strip()]

    table = {}
    for w in words:
        table.update(hashes_for(w))

    os.makedirs("data", exist_ok=True)
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(table, f, indent=2)

    print(f"✅ Rainbow table written to {OUT_JSON} with {len(table)} entries")

if __name__ == "__main__":
    main()
