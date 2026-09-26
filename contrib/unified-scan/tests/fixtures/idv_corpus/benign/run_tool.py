import subprocess
import sys


def convert(pdf_path, out_dir):
    subprocess.run(["pdftotext", "-layout", pdf_path, out_dir + "/out.txt"], check=True)


if __name__ == "__main__":
    convert(sys.argv[1], sys.argv[2])
