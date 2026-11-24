"""Reproduce PDF §7.1-7.5. No repository scanning is implemented here."""
from src.dataset import prepare
from src.experiment import run_experiment
from src.report import build_report

if __name__ == '__main__':
    prepare()
    run_experiment()
    build_report()
