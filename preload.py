import json
from guardian_swarm.core.models import VerificationAgent
from guardian_swarm.utils.paths import PROJECT_ROOT, STATE_FILE, resolve_state_file
from guardian_swarm.utils.visual import Color

import sys
sys.path.insert(0, str(PROJECT_ROOT))

def run_preload():
    print(f"{Color.HEADER}=== Guardian Swarm V3 Pre-load Resolution ==={Color.END}")
    
    # Force removal of any existing runtime state before pre-loading
    state_file = resolve_state_file()
    if state_file.exists():
        try:
            state_file.unlink()
        except Exception:
            pass

    # Instantiate the agent. It will do CUDA checks/psutil dynamically to find the best configuration
    agent = VerificationAgent()
    
    # If external backends are preferred or configured, we can let the agent discover them.
    # Otherwise, it falls back to PyTorch model loading or Heuristics.
    print("Determining best available security verification engine backend...")
    
    # Try scanning local external server connections
    results = agent.scan_local_servers()
    connected = False
    for name, info in results.items():
        if info.get("status") == "connected" and info.get("models"):
            agent.engine_type = info["type"]
            agent.connected_server = name
            agent.connected_url = info["url"]
            agent.connected_model = info["models"][0]
            print(f"{Color.GREEN}✔ Discovered active external backend: {name} (Model: {agent.connected_model}){Color.END}")
            connected = True
            break
            
    if not connected:
        print("No external model servers discovered on localhost. Probing local PyTorch model requirements...")
        # Under normal conditions load_model() will run memory detection and resolve fallback vs primary
        agent.load_model()
        
    # Write the resolved state to the project data directory
    state = {
        "engine_type": agent.engine_type,
        "device": agent.device,
        "model_name": agent.model_name,
        "is_fallback": agent.is_fallback,
        "connected_server": agent.connected_server,
        "connected_url": agent.connected_url,
        "connected_model": agent.connected_model
    }
    
    with STATE_FILE.open("w", encoding="utf-8") as f:
        json.dump(state, f, indent=4)
        
    print(f"\n{Color.GREEN}✔ Pre-load successful! Configuration saved to [{STATE_FILE}]:{Color.END}")
    print(json.dumps(state, indent=4))
    print(f"{Color.HEADER}============================================={Color.END}\n")

if __name__ == "__main__":
    run_preload()
