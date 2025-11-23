import os
import  re


def make_dir(path) -> None:
    try:
        os.makedirs(path, exist_ok=True)
        print(f"Directory tree created at: {path}")
    except OSError as err:
        print(f"Error creating directory: {err}")

def replace_txt(tpl_file, replacement: dict[str, str]) -> str:
    try:
        with open(tpl_file, "r") as f:
            content: str = f.read()
    except FileNotFoundError as err:
        print(f"Error: Source file not found at {tpl_file}: {err}")

    for placeholder, target in replacement.items():
        content = content.replace(placeholder, str(target))
    return content

def make_file(out_file, content) -> None:
    try:
        with open(out_file, "w") as f:
            f.write(content)
    except IOError as err:
        print(f"Error writing file to {out_file}: {err}")


def main() -> None:
    base_dir: str = "root"

    domains: dict[str, list[str]] = {
        "main": ["prod.lt", "prod.lv"],
        "sub": ["tst.lt", "tst.ee"]
    }
    products: list[str] = [
        "prod-1",
        "prod-2"
    ]
    file_types: dict[str, dict] = {
        "terramate": {
            "template": "tm.tpl",
            "replace": {
                "{domain}": "{domain_dash}",
                "{product}": "{product}"
            },
            "out_file": "{product_path}\\stack.tm"
        },
        "terragrunt": {
            "template": "tg.tpl",
            "replace": {
                "{domain}": "{domain_dash}",
                "{product}": "{product}"
            },
            "out_file": "{product_path}\\tg.hcl"
        },
        "import": {
            "template": "imp.tpl",
            "replace": {
                "{rs_ids}": "{rs_ids}"
            },
            "out_file": "{base_dir}\\import-{domain_dash}-{product}.hcl"
        },
        "rule_yaml": {
            "template": None,
            "out_text": "{rs_config}",
            "out_file": "{product_path}\\rule.yaml"
        },
        "page_yaml": {
            "template": None,
            "out_text": "",
            "out_file": "{product_path}\\page.yaml"
        }
    }

    for grp, doms in domains.items():
        for domain in doms:
            domain_path: str = f"{base_dir}\\{grp}\\{domain}"
            for product in products:
                product_path: str = f"{domain_path}\\{product}"
                make_dir(product_path)

                domain_dash = re.sub("\\.", "-", domain)
                rs_ids = f"<resource id list>"
                rs_config = f"<yaml resource contents>"

                for _, params in file_types.items():
                    if params.get("template"):
                        str_replace: dict[str, str] = {k: v.format(**vars()) for k, v in params.get("replace").items()}
                        out_text: str = replace_txt(params.get("template"), str_replace)
                    else:
                        out_text: str = params.get("out_text").format(**vars())

                    out_file = params.get("out_file").format(**vars())
                    make_file(out_file, out_text)


if __name__ == '__main__':
    main()