Here is a detailed Markdown Mermaid flowchart representing the architecture, data flow, and user interaction logic of the **CipherSky** application.

### **CipherSky Application Architecture**

This flowchart visualizes how the application utilizes **Streamlit** for the frontend and **Multiprocessing** for the backend packet sniffing, bridged by a thread-safe Queue.

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

-----

### **Flowchart Breakdown**

1.  **Initialization & Consent:**

      * The app begins by checking `ensure_user_consent`. If the user hasn't agreed to the T\&C and age verification, the app stops there.
      * Once agreed, `st.session_state` is initialized to hold data like `packet_data`, `blocked_ips`, and class instances (e.g., `ThreatDetector`).

2.  **The Backend (Sniffer Process):**

      * When **Start** is clicked, a separate `multiprocessing.Process` is spawned running `sniffer_process`.
      * 
      * It uses `scapy` to capture packets.
      * **Processing:** Every packet goes through `process_packet` where:
          * Geolocation is resolved (Cached).
          * Shannon Entropy is calculated (for encryption detection).
          * **Quantum Analysis:** Coherence and entanglement factors are calculated based on packet properties.
      * The processed dict is pushed into a `multiprocessing.Queue`.

3.  **The Data Bridge:**

      * The `Queue` acts as the thread-safe bridge. The background process *writes* to it, and the Streamlit frontend *reads* from it during every page rerun (refresh).

4.  **The Frontend (Streamlit UI):**

      * **Auto-Refresh:** The `DynamicDashboard` triggers reruns (e.g., every 2 seconds).
      * **Data Ingestion:** On every rerun, the app pulls packets from the Queue and appends them to `st.session_state.packet_data`.
      * **Firewall Controller:** Manage OS-level blocking (iptables/netsh) based on user interaction.

5.  **Visualization & Analytics:**

      * **Physics Engine:** Calculates node mass and force for the 3D particle simulation.
      * **Visualizations:**
        \*

[Image of 3D network topology]

```
    * **Global Intel:** 3D Globe with flight paths.
    * **Quantum:** Bloch sphere visualization of network states.
    * **Radar:** 3D Security and Performance metrics.
```
