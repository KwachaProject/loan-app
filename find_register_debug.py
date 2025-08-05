import os

search_term = "register_customer_debug"
templates_dir = "templates"

for root, dirs, files in os.walk(templates_dir):
    for file in files:
        if file.endswith(".html"):
            path = os.path.join(root, file)
            with open(path, "r", encoding="utf-8") as f:
                for i, line in enumerate(f, start=1):
                    if search_term in line:
                        print(f"Found '{search_term}' in {path} on line {i}:")
                        print(f"  {line.strip()}\n")
