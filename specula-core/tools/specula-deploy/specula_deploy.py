import os
import argparse
import zipfile

TEMPLATE_DIR = "templates"
OUTPUT_DIR = "output"

def load_template(name):
    with open(os.path.join(TEMPLATE_DIR, name), "r") as f:
        return f.read()

def generate_file(template_name, output_path, context):
    content = load_template(template_name)
    for key, value in context.items():
        content = content.replace(f"{{{{{key}}}}}", value)

    with open(output_path, "w") as f:
        f.write(content)

def create_zip(client_name):
    zip_name = f"{OUTPUT_DIR}/SpeculaDeploy-{client_name}.zip"
    with zipfile.ZipFile(zip_name, 'w') as zipf:
        for root, dirs, files in os.walk(OUTPUT_DIR):
            for file in files:
                if file.endswith(".ps1") or file.endswith(".sh"):
                    path = os.path.join(root, file)
                    zipf.write(path, os.path.basename(path))
    return zip_name

def main():
    parser = argparse.ArgumentParser(description="Specula Deploy Tool")
    parser.add_argument("--client", required=True)
    parser.add_argument("--manager", required=True)
    parser.add_argument("--group", default="default")
    parser.add_argument("--token", default="CHANGE_ME")

    args = parser.parse_args()

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    context = {
        "CLIENT": args.client,
        "MANAGER": args.manager,
        "GROUP": args.group,
        "TOKEN": args.token
    }

    generate_file("install-windows.ps1.tpl", f"{OUTPUT_DIR}/install-specula.ps1", context)
    generate_file("install-linux.sh.tpl", f"{OUTPUT_DIR}/install-specula.sh", context)

    zip_file = create_zip(args.client)

    print(f"✅ Package généré : {zip_file}")

if __name__ == "__main__":
    main()