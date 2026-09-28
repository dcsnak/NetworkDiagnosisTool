import os
import subprocess
import sys


ROOT = os.path.dirname(os.path.abspath(__file__))


def build_exe():
    command = [
        sys.executable,
        '-m',
        'PyInstaller',
        '--noconfirm',
        '--onefile',
        '--windowed',
        '--name',
        'NetworkDiagnosisTool',
        os.path.join(ROOT, 'main.py'),
    ]
    subprocess.run(command, cwd=ROOT, check=True)


if __name__ == '__main__':
    build_exe()
    print('EXE build completed. Output: dist\\NetworkDiagnosisTool.exe')
