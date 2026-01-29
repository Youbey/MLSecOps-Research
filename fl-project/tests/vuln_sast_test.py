import pickle
import subprocess

# This is a FAKE vulnerability to test Bandit/Semgrep
def risky_code(user_input):
    # Bandit should flag B301 (Pickle) and B602 (Shell)
    obj = pickle.loads(user_input)
    subprocess.Popen("echo " + user_input, shell=True)