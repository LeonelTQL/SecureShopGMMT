"""Execute and save the five notebooks with this environment's Python kernel."""
import os
from pathlib import Path
import sys
import argparse

import nbformat
from nbclient import NotebookClient
from jupyter_client import KernelManager

ROOT = Path(__file__).resolve().parent

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--only', choices=['01', '02', '03', '04', '05'], help='Execute one phase using existing preceding outputs.')
    args = parser.parse_args()
    # Keep Jupyter's writable state within this advance, not in the user profile.
    for key, subdir in [('JUPYTER_CONFIG_DIR', 'config'), ('JUPYTER_RUNTIME_DIR', 'runtime'), ('IPYTHONDIR', 'ipython')]:
        path = ROOT / '.jupyter' / subdir
        path.mkdir(parents=True, exist_ok=True)
        os.environ[key] = str(path)
    for path in sorted((ROOT / 'notebooks').glob('*.ipynb')):
        if args.only and not path.name.startswith(args.only):
            continue
        nb = nbformat.read(path, as_version=4)
        km = KernelManager(kernel_name='python3')
        km.kernel_spec.argv = [sys.executable, '-m', 'ipykernel_launcher', '-f', '{connection_file}']
        client = NotebookClient(nb, km=km, timeout=600, resources={'metadata': {'path': str(ROOT)}})
        try:
            client.execute()
        finally:
            if km.has_kernel:
                km.shutdown_kernel(now=True)
        nbformat.write(nb, path)
        print(f'Executed {path.name}', flush=True)
