
def run_query(sql_string):
    pass


from database import run_query
import os

def local_helper(data):
    """Scenario A: A target local function definition."""
    return data.strip()

def main():
    # 1. Built-in: Should be totally ignored by the gatekeeper
    print("Initializing scan...")
    
    # 2. Scenario A: Local function call (Same-file jump)
    clean_data = local_helper("  malicious_payload  ")
    
    # 3. Scenario B: From-Import function call (Cross-file jump)
    run_query(clean_data)
    
    # 4. External Library: Should be totally ignored by the gatekeeper
    os.system(f"echo {clean_data}")

def shadow_wrapper(run_query):
    """Scenario C: Parameter Shadowing Trap.
    
    The local parameter 'run_query' overrides the global import statement.
    The gatekeeper must intercept this and drop it!
    """
    run_query("Select * from logs")