# <samp> CipherSky

<samp>
  
**CipherSky is a quantum‑enhanced defense HUD for real‑time traffic capture, anomaly detection, and active response. It combines IsolationForest ML, Shannon entropy, and YARA rules for threat scoring across ports, protocols, and geolocation. Coordinated attacks are modeled with quantum entanglement, visualized in a 3D Bloch Sphere and force‑directed particle simulations. A multiprocessing scapy sniffer, cross‑platform blocking (netsh/iptables), and WebGL dashboards (Streamlit, Plotly, PyDeck) deliver adaptive, high‑fidelity verdicts.**

<details>
   
**<summary>Project Details</summary>**

<details>
   
**<summary>CipherSky Preview</summary>**

</details>

<details>
   
**<summary>CipherSky Features</summary>**

* **Threat Detection : Utilizes `sklearn.ensemble.IsolationForest` to detect statistical outliers in traffic patterns. Calculates Shannon entropy on packet payloads to detect encrypted C2 channels or compressed malware exfiltration. Real-time threat scoring based on port reputation, protocol anomalies, and geographic consistency. Integrated YARA-style rule matching for detecting suspicious network strings and dark web activity.**
  
* **Quantum & Physics Analysis : Analyzes connection correlation using simulated quantum entanglement principles to detect coordinated attacks (botnets). 3D representation of the network's "Quantum State" (Coherence vs. Decoherence) based on entropy and threat levels. Force-directed 3D graph simulations where nodes act as particles with mass (data volume) and gravity (threat level).**
  
* **Active Defense & Forensics : Cross-platform blocking capabilities (Windows `netsh`, Linux `iptables`) directly from the UI. Single-click containment for high-risk IPs or subnets. Automated WHOIS, DNS resolution, and Reverse DNS lookups for forensic analysis. 3D interactive globe visualizing threat vectors and traffic sources using MaxMind GeoLite2.**
* **Performance Modes : Optimized for laptops. Reduces particle count and sampling rates. Balanced visual fidelity and analysis depth.Full physics simulations and deep packet inspection (Requires strong CPU).**
  
* **Visualizations : CipherSky standard charts, employing advanced mathematical models for visualization. Uses force-directed graph algorithms where nodes (IPs) repulse each other, but edges (connections) act as springs. Visualizes network health on a Bloch Sphere. High entropy/threats push the state vector towards decoherence.**

</details>

<details>
   
**<summary>Technical Details</summary>**



**CipherSky operates on a decoupled multi-process architecture to ensure the UI remains responsive while handling high-velocity packet capture.**

* **Sniffer Process (`multiprocessing`): A dedicated background process uses `scapy` to sniff raw sockets. It parses TCP/UDP/ICMP/DNS headers and computes immediate metrics (entropy, flags).**
  
* **Data Pipeline : Packets are prioritized based on threat score and pushed into a thread-safe `multiprocessing.Queue`.**
  
* **Analytics Engine : The main process retrieves packets, performs OSINT enrichment (with caching), runs ML inference, and updates the physics simulation state.**
  
* **Frontend : Streamlit renders the data using `Plotly` and `PyDeck` for WebGL-accelerated 3D visualizations.**



| Component      | Technology                  | Description                                                        | Data Flow Role                                      | Performance Notes                                                                 |
|----------------|-----------------------------|--------------------------------------------------------------------|-----------------------------------------------------|----------------------------------------------------------------------------------|
| Frontend       | Streamlit                   | Renders the reactive HUD and manages user interaction.              | Consumes analytics output and visual states.        | Lightweight UI; offloads heavy computation to backend; supports WebGL acceleration. |
| Packet Engine  | Scapy / Multiprocessing     | Captures and parses raw TCP/UDP/ICMP/DNS packets in a separate process. | Ingests raw traffic and pushes metrics into queue.  | Parallelized sniffing; isolates capture overhead; tuned for high‑velocity streams. |
| Visualization  | Plotly / PyDeck             | Renders WebGL 3D graphs, maps, and physics simulations.             | Maps analytics into interactive 3D topology views.  | GPU‑accelerated rendering; adaptive particle count for laptops vs. HPC setups.     |
| Analysis Core  | NumPy / NetworkX / Sklearn  | Computes entropy, graph centrality, and ML anomaly scores.          | Processes queued packets; enriches with OSINT/ML.   | Vectorized math; cached lookups; scalable anomaly detection via IsolationForest.   |
| Defense        | OS Subprocess               | Interfaces with system firewalls (netsh/iptables) for active blocking. | Executes containment and mitigation commands.       | Cross‑platform subprocess calls; minimal latency; integrates with forensic lookups.|

</details>

<details>


**<summary>Architecture</summary>** 

```mermaid
%%{init: {'flowchart': {'nodeSpacing': 80, 'rankSpacing': 100}}}%%
graph TD
    %% --- GLOBAL SETTINGS ---
    %% 1. Make all connecting lines BOLD and DARK GREY
    linkStyle default stroke:#263238,stroke-width:3px,fill:none;

    %% --- CLASS DEFINITIONS (Customized with Larger Font) ---
    %% UI: Blue theme, Bold Text, Thicker Border, Large Font
    classDef ui fill:#e1f5fe,stroke:#01579b,stroke-width:3px,font-weight:bold,color:#01579b,font-size:16px;
    
    %% Process: Orange theme, Bold Text, Large Font
    classDef process fill:#fff3e0,stroke:#e65100,stroke-width:3px,font-weight:bold,color:#e65100,font-size:16px;
    
    %% Storage: Green theme, Bold Text, Large Font
    classDef storage fill:#e8f5e9,stroke:#1b5e20,stroke-width:3px,font-weight:bold,color:#1b5e20,font-size:16px;
    
    %% Logic: Purple theme, Bold Text, Large Font
    classDef logic fill:#f3e5f5,stroke:#4a148c,stroke-width:3px,font-weight:bold,color:#4a148c,font-size:16px;
    
    %% Quantum: Dark theme, Neon Blue Border, White Bold Text, Dashed Border, Large Font
    classDef quantum fill:#263238,stroke:#00b0ff,stroke-width:4px,color:#fff,font-weight:bold,stroke-dasharray: 5 5,font-size:16px;

    %% --- FLOWCHART START ---

    %% ENTRY POINT
    Start([User Launches App]) --> Consent{Consent Agreed?}
    Consent -- No --> GatePage[Show Age/Disclaimer Gate]
    GatePage --> Stop([Stop Execution])
    Consent -- Yes --> Init[Initialize Session State]
    
    %% UI LAYER
    Init --> Header[Render Header & Dashboard Controls]
    Header --> Sidebar[Render Sidebar Controls]
    
    Sidebar --> Action{User Action}
    Action -- Start Capture --> SpawnProcess[Spawn Sniffer Process]
    Action -- Stop Capture --> KillProcess[Terminate Process]
    Action -- Block IP --> FirewallCall[Call Firewall Controller]
    Action -- Export --> DataExport[Generate CSV/JSON]
    
    Dashboard[Dynamic Dashboard Refresh]
    Tabs[Render Tabs: Global, Live, Threats, Quantum]

    %% BACKEND PROCESSING
    SpawnProcess --> SnifferFunc(sniffer_process)
    SnifferFunc --> Scapy[Scapy Sniff / Socket]
    Scapy --> PacketCallback{Packet Captured?}
    
    PacketCallback -- Yes --> ProcessPkt[process_packet]
    ProcessPkt --> GeoIP[GeoResolver Cache]
    ProcessPkt --> Entropy[Calc Shannon Entropy]
    ProcessPkt --> ThreatCalc[ThreatDetector Score]
    
    %% QUANTUM LOGIC (Flattened)
    ThreatCalc --> QState[Calc Quantum State]
    QState --> Decoherence[Calc Decoherence Factor]
    
    Decoherence ==> Enqueue[/Put Data in Queue/]

    %% STATE MEMORY
    Enqueue -.-> Queue[(Multiprocessing Queue)]
    Queue -.-> Dequeue[/Get Data from Queue/]
    Dequeue ==> SessionState[(st.session_state)]
    
    SessionState --> DNS_List[DNS Queries List]
    SessionState --> Pkt_List[Packet Dataframe]
    SessionState --> Alert_List[Active Alerts]
    SessionState --> Blocked_Set[Firewall Blocked IPs]

    %% ANALYTICS ENGINE
    Dashboard --> Dequeue
    
    Pkt_List --> ML_Engine[MLAnomalyEngine]
    Pkt_List --> Graph_Algos[NetworkTopologyAnalyzer]
    Pkt_List --> Physics_Sim[PhysicsBasedVisualizations]
    
    ML_Engine --> UpdateScores[Update Anomaly Scores]
    
    Graph_Algos --> Viz3D_Topo[3D Network Graph]
    Physics_Sim --> Viz3D_Radar[3D Security Radar]
    Physics_Sim --> Viz_Spectrum[Spectral Analysis]
    
    GeoData[Geo Data] --> Viz_Globe[3D Globe / Map]

    %% FINAL RENDERING
    UpdateScores --> Tabs
    Viz3D_Topo --> Tabs
    Viz3D_Radar --> Tabs
    Viz_Spectrum --> Tabs
    Viz_Globe --> Tabs
    FirewallCall --> Blocked_Set

    %% --- APPLY CLASSES ---
    class Header,Sidebar,Tabs,GatePage ui;
    class SnifferFunc,Scapy,ProcessPkt,GeoIP,Entropy,ThreatCalc process;
    class Queue,SessionState,DNS_List,Pkt_List,Alert_List,Blocked_Set storage;
    class ML_Engine,Graph_Algos,Physics_Sim,Viz3D_Topo,Viz3D_Radar logic;
    class QState,Decoherence quantum;
```

</details>
<details>


**<summary>Legal Disclaimer</summary>** 

```javascript

CipherSky is intended for defensive security analysis and educational purposes only. Ensure you have authorization before monitoring network traffic. The developers are not responsible for any misuse of this tool. Usage implies consent to local monitoring laws and regulations.
  
```
</details>

