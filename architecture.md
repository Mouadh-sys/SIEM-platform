# Description du projet

> Mise en place d’une architecture distribuée de traitement, corrélation et analyse des événements de sécurité
> 

```mermaid
graph TD
    subgraph Sources["Sources de sécurité"]
        A[Serveurs Linux / Windows]
        B[Firewall / IDS]
        C[Serveurs Web / Applications]
        D[Équipements réseau]
    end

    subgraph Collecte["Collecte et normalisation"]
        E[Fluent Bit]
    end

    subgraph Streaming["Transport des événements"]
        F[Apache Kafka]
    end

    subgraph Processing["Traitement"]
        G[Data Prepper]
    end

    subgraph SIEM["Analyse de sécurité"]
        H[OpenSearch]
        I[Security Analytics]
        J[Corrélation / Alerting]
    end

    subgraph TI["Threat Intelligence"]
        K[MISP]
    end

    subgraph Presentation["Présentation et investigation"]
        L[OpenSearch Dashboards]
        M[Portail de sécurité<br/>React + FastAPI]
    end

    A --> E
    B --> E
    C --> E
    D --> E

    E --> F
    F --> G
    G --> H
    H --> I
    I --> J

    K -. IOC / Threat Intelligence .-> I
    J --> L
    J --> M
    H --> L
    H --> M
```

## 1. Architecture technique

```mermaid
graph TD
    subgraph Sources["Sources de logs"]
        S1[Linux / Windows]
        S2[Firewall / IDS]
        S3[Web Server / Applications]
        S4[Network devices]
    end

    subgraph Collecte["Collecte & Normalisation"]
        FB[Fluent Bit<br/>Collection / Parse / Normalize / Filter]
    end

    subgraph Transport["Event Streaming"]
        KF[Apache Kafka<br/>Buffer / Queue]
    end

    subgraph Bridge["Pont Kafka → OpenSearch"]
        DP[Data Prepper<br/>ou Logstash / Kafka Connect]
    end

    subgraph Analytics["OpenSearch"]
        OS[Indexing / Search / Storage]
        SA[Security Analytics<br/>Détecteurs / Règles Sigma]
        COR[Corrélation cross-log]
        AL[Alerting]
    end

    subgraph TI["Threat Intelligence"]
        MISP[MISP<br/>IOC / Feeds<br>]
    end

    subgraph Presentation["Couche présentation"]
        DASH[OpenSearch Dashboards<br/>SOC dashboards]
        APP[Portail Sécurité<br/>React + FastAPI]
    end

    S1 --> FB
    S2 --> FB
    S3 --> FB
    S4 --> FB
    FB --> KF
    KF --> DP
    DP --> OS
    OS --> SA
    SA --> COR
    COR --> AL
    MISP -.IOC.-> SA
    OS --> DASH
    OS --> APP
    AL --> APP
    MISP -.lookup IOC.-> APP
```

## 2. Flux de détection

```mermaid
sequenceDiagram
    participant Attaquant
    participant Serveur as Serveur Linux (SSH)
    participant FB as Fluent Bit
    participant KF as Kafka
    participant OS as OpenSearch
    participant SA as Security Analytics
    participant APP as Portail Sécurité

    Attaquant->>Serveur: Tentatives de connexion répétées
    Serveur-->>FB: Logs auth.log (échecs)
    FB->>KF: Événements normalisés
    KF->>OS: Indexation
    OS->>SA: Évaluation règle Sigma (seuil échecs/IP)
    SA-->>SA: Finding généré (IP suspecte)
    SA->>APP: Alerte transmise
    APP-->>APP: Création incident (sévérité, IP, timeline)
```

## 3. Architecture cible

```mermaid
graph TB
    subgraph DMZ["Zone DMZ"]
        LB[Load Balancer / Reverse Proxy<br/>TLS termination]
    end

    subgraph Sources["Sources de logs"]
        S1[Linux / Windows]
        S2[Firewall / IDS]
        S3[Web / Apps]
        S4[Network devices]
        S5[Cloud / EDR / DNS - extension future]
    end

    subgraph Collecte["Collecte distribuée"]
        FB1[Fluent Bit #1]
        FB2[Fluent Bit #2]
    end

    subgraph KafkaCluster["Kafka Cluster - 3 brokers"]
        K1[Broker 1]
        K2[Broker 2]
        K3[Broker 3]
        ZK[Coordination<br/>KRaft / ZooKeeper]
    end

    DP[Data Prepper<br/>Consumer group scalable]

    subgraph OSCluster["OpenSearch Cluster"]
        M[Master nodes x3]
        D1[Data node 1]
        D2[Data node 2]
        D3[Data node 3]
        ILM[Index Lifecycle Mgmt<br/>hot / warm / cold]
    end

    subgraph SecOps["Sécurité opérationnelle"]
        VAULT[Secrets Manager<br/>Vault / equiv.]
        IAM[RBAC / SSO<br/>OIDC]
    end

    subgraph Observabilite["Monitoring du SIEM lui-même"]
        PROM[Prometheus]
        GRAF[Grafana]
    end

    subgraph TI["Threat Intelligence"]
        MISP[MISP]
    end

    subgraph AppLayer["Application"]
        APP1[Portail Sécurité<br/>instance 1]
        APP2[Portail Sécurité<br/>instance 2]
        DB[(PostgreSQL<br/>incidents, users)]
    end

    S1 --> FB1
    S2 --> FB1
    S3 --> FB2
    S4 --> FB2
    S5 -.futur.-> FB2

    FB1 --> K1
    FB2 --> K2
    K1 --- K2 --- K3
    K1 -.-> ZK

    K1 --> DP
    K2 --> DP
    K3 --> DP
    DP --> D1
    DP --> D2
    DP --> D3
    M --- D1
    M --- D2
    M --- D3
    D1 --> ILM

    MISP -.IOC.-> DP

    LB --> APP1
    LB --> APP2
    APP1 --> DB
    APP2 --> DB
    APP1 --> D1
    APP2 --> D2

    IAM --> LB
    VAULT -.credentials.-> FB1
    VAULT -.credentials.-> DP
    VAULT -.credentials.-> APP1

    PROM -.scrape.-> KafkaCluster
    PROM -.scrape.-> OSCluster
    PROM -.scrape.-> AppLayer
    GRAF --> PROM
```

---