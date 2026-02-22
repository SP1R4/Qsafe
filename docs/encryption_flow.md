Encryption Flow
graph TD
    A[Start Encryption] --> B[Generate Kyber Keypair]
    B --> C[Encrypt Secret Key with Passphrase]
    C --> D[Save Encrypted Secret Key]
    D --> E[Open Input/Output Files]
    E --> F[Generate Random Nonce]
    F --> G[Kyber Encapsulation]
    G --> H{Shared Secret}
    H --> I[Derive AES Key with HKDF]
    I --> J[Initialize AES-256-GCM Context]
    J --> K[Write Version Header, KEM Ciphertext]
    K --> L[Read File in Chunks]
    L --> M[Encrypt Chunk with AES-GCM]
    M --> N[Write to Output File]
    N --> O{More Chunks?}
    O -->|Yes| L
    O -->|No| P[Finalize AES-GCM, Get Tag]
    P --> Q[Write Nonce and Tag]
    Q --> R[Cleanup: Free Memory, Close Files]
    R --> S[End]

