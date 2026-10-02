import os
import zipfile
import json

base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
dist_dir = os.path.join(base_dir, "dist")
out_dir = os.path.join(base_dir, "release-zips")
os.makedirs(out_dir, exist_ok=True)

with open(os.path.join(base_dir, "package.json"), "r", encoding="utf-8") as f:
    pkg = json.load(f)
version = pkg.get("version", "1.2.6")

# 1. Firefox release zip
ff_zip_path = os.path.join(out_dir, f"xorapass-extension-firefox-v{version}.zip")
with zipfile.ZipFile(ff_zip_path, "w", zipfile.ZIP_DEFLATED) as z:
    for root, dirs, files in os.walk(dist_dir):
        for f in files:
            full_p = os.path.join(root, f)
            rel_p = os.path.relpath(full_p, dist_dir)
            z.write(full_p, rel_p)

# 2. Chrome release zip (manifest without 'key' property)
cr_zip_path = os.path.join(out_dir, f"xorapass-extension-chrome-v{version}.zip")
manifest_path = os.path.join(dist_dir, "manifest.json")
with open(manifest_path, "r", encoding="utf-8") as f:
    m = json.load(f)
if "key" in m:
    del m["key"]
manifest_bytes = json.dumps(m, indent=2).encode("utf-8")

with zipfile.ZipFile(cr_zip_path, "w", zipfile.ZIP_DEFLATED) as z:
    for root, dirs, files in os.walk(dist_dir):
        for f in files:
            full_p = os.path.join(root, f)
            rel_p = os.path.relpath(full_p, dist_dir)
            if rel_p == "manifest.json":
                z.writestr("manifest.json", manifest_bytes)
            else:
                z.write(full_p, rel_p)

# 3. Edge / Opera copy
opera_zip_path = os.path.join(out_dir, f"xorapass-extension-opera-v{version}.zip")
with open(cr_zip_path, "rb") as src, open(opera_zip_path, "wb") as dst:
    dst.write(src.read())

print("SUCCESS: Packages created in", out_dir)
print(f"  Firefox: {ff_zip_path} ({os.path.getsize(ff_zip_path)} bytes)")
print(f"  Chrome:  {cr_zip_path} ({os.path.getsize(cr_zip_path)} bytes)")
print(f"  Opera:   {opera_zip_path} ({os.path.getsize(opera_zip_path)} bytes)")
