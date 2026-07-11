from flask import request
import os
import shlex
import subprocess as sp


def cwe_078_local_positive():
    cmd = request.args.get("cmd")
    os.system(cmd)


def cwe_078_interprocedural_positive():
    cmd = request.form.get("cmd")
    run_command_wrapper(cmd)


def run_command_wrapper(cmd):
    os.system(cmd)


def cwe_078_alias_positive():
    cmd = input()
    sp.Popen(cmd, shell=True)


def cwe_078_try_body_positive():
    cmd = request.cookies.get("cmd")
    try:
        subprocess.run(cmd, shell=True)
    except OSError:
        pass


def cwe_078_sanitized_negative():
    cmd = shlex.quote(request.args.get("cmd"))
    os.system(cmd)


def cwe_078_safe_negative():
    os.system("echo safe")

