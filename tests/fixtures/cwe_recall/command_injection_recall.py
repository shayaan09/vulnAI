from flask import request
import os
import subprocess
import subprocess as sp


def cmdi_001_os_system_direct():
    cmd = request.args.get("cmd")
    os.system(cmd)


def cmdi_002_fstring_command():
    filename = request.form.get("filename")
    cmd = f"cat {filename}"
    os.system(cmd)


def cmdi_003_subprocess_run_shell_true():
    cmd = request.cookies.get("cmd")
    subprocess.run(cmd, shell=True)


def cmdi_004_subprocess_alias_popen():
    cmd = input()
    sp.Popen(cmd, shell=True)


def cmdi_005_interprocedural_sink_param():
    cmd = request.args.get("cmd")
    cmdi_005_run(cmd)


def cmdi_005_run(cmd):
    os.system(cmd)


def cmdi_006_helper_returns_command():
    cmd = cmdi_006_build_command()
    os.system(cmd)


def cmdi_006_build_command():
    name = request.args.get("name")
    return "grep " + name + " /var/log/app.log"


def cmdi_007_keyword_argument_flow():
    cmd = request.args.get("cmd")
    cmdi_007_run(command=cmd)


def cmdi_007_run(command):
    os.system(command)


def cmdi_008_join_built_command():
    host = request.args.get("host")
    cmd = " ".join(["ping", "-c", "1", host])
    os.system(cmd)


def cmdi_009_try_body_sink():
    cmd = request.headers.get("X-Command")
    try:
        os.system(cmd)
    except OSError:
        pass


def cmdi_010_object_attribute_flow(holder):
    cmd = request.args.get("cmd")
    holder.cmd = cmd
    os.system(holder.cmd)

