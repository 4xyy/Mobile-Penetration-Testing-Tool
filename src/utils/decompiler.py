import os
import subprocess

def decompile_apk(file_path, output_dir="output"):
    """
    Decompiles an APK file using JADX and saves the results in the output directory.

    :param file_path: Path to the APK file.
    :param output_dir: Directory where decompiled files will be stored.
    """
    if not os.path.exists(file_path):
        print(f"File {file_path} does not exist.")
        return

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    try:
        subprocess.run(["jadx", "-d", output_dir, file_path], check=True)
        print(f"APK decompiled successfully into {output_dir}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to decompile APK: {e}")

def decompile_ipa(file_path, output_dir="output"):
    """
    Decompiles an IPA file using class-dump (or another appropriate tool) and saves the results.

    :param file_path: Path to the IPA file.
    :param output_dir: Directory where decompiled files will be stored.
    """
    if not os.path.exists(file_path):
        print(f"File {file_path} does not exist.")
        return

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    try:
        # Assuming `class-dump` or a similar tool is installed for iOS decompiling
        subprocess.run(["class-dump", "-H", "-o", output_dir, file_path], check=True)
        print(f"IPA decompiled successfully into {output_dir}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to decompile IPA: {e}")

