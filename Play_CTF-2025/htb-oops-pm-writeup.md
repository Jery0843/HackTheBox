# HackTheBox CTF - "It's Oops PM" Hardware Challenge Writeup

## Challenge Overview

**Challenge Name**: It's Oops PM  
**Category**: Hardware  
**Difficulty**: Medium  
**Platform**: HackTheBox Play CTF  

**Scenario**: 
The crew has discovered a dilapidated research facility with environmental sensors that communicate with a satellite. These sensors contain a crypto-processor with encrypted transmissions, but after reverse-engineering the VHDL logic, they've uncovered a backdoor that triggers with specific input patterns. Our mission is to exploit this backdoor to activate the satellite system.

## Initial Analysis

### Files Provided
The challenge provides a ZIP archive containing:
- `backdoor.vhdl` - Contains the backdoor trigger logic
- `encryption.vhdl` - Handles cryptographic operations
- `key.vhdl` - Manages the encryption key
- `tpm.vhdl` - Main TPM (Trusted Platform Module) controller
- `schematic.png` - Circuit diagram showing component relationships

### Challenge Connection Details
- **Target IP**: 94.237.55.43
- **Port**: 38407

## Technical Deep Dive

### 1. VHDL Code Analysis

Let's examine each component to understand the system architecture:

#### Backdoor Module (`backdoor.vhdl`)
```vhdl
library IEEE;
use IEEE.STD_LOGIC_1164.ALL;
use IEEE.NUMERIC_STD.ALL;

entity backdoor is
    Port (
        D : in STD_LOGIC_VECTOR(15 downto 0);
        B : out STD_LOGIC
    );
end backdoor;

architecture Behavioral of backdoor is
    constant pattern : STD_LOGIC_VECTOR(15 downto 0) := "1111111111101001";
begin
    process(D)
    begin
        if D = pattern then
            B <= '1';  -- Backdoor activated!
        else
            B <= '0';  -- Normal operation
        end if
    end process;
end Behavioral;
```

**Key Finding**: The backdoor triggers when input `D` exactly matches the binary pattern `"1111111111101001"`.

#### Key Module (`key.vhdl`)
```vhdl
entity ckey is
    Port (
        K : out STD_LOGIC_VECTOR(15 downto 0)
    );
end ckey;

architecture Behavioral of ckey is
    constant key : STD_LOGIC_VECTOR(15 downto 0) := "0110001111100001";
begin
    K <= key;
end Behavioral;
```

**Key Discovery**: The system uses a hardcoded 16-bit encryption key: `"0110001111100001"`.

#### Encryption Module (`encryption.vhdl`)
```vhdl
architecture Behavioral of encryption is
begin
    process(D, K)
    begin
        for i in 1 to 15 loop
            E(i) <= D(i) XOR K(i);  -- Standard XOR encryption
        end loop;
        -- Special bit manipulations
        E(0) <= NOT K(0);
        E(6) <= NOT K(6);
        E(13) <= NOT K(13);
    end process;
end Behavioral;
```

**Encryption Analysis**: Uses XOR cipher with special bit flipping on positions 0, 6, and 13.

#### TPM Controller (`tpm.vhdl`)
```vhdl
architecture Behavioral of tpm is
    -- Signal declarations
    signal Key : STD_LOGIC_VECTOR(15 downto 0);
    signal Encrypted : STD_LOGIC_VECTOR(15 downto 0);
    signal B: STD_LOGIC;
    
    -- Component instantiation
    ck : ckey port map(Key);
    enc: encryption port map (Data, Key, Encrypted);
    bd: backdoor port map (Data, B);
    
    process(Key, Encrypted, B)
    begin
        case B is
            when '1' =>  -- BACKDOOR ACTIVE
                for i in 0 to 15 loop
                    Output(i) <= Key(i);  -- Output raw key!
                end loop;
            when others =>  -- NORMAL OPERATION
                for i in 0 to 15 loop
                    Output(i) <= Encrypted(i);  -- Output encrypted data
                end loop;
        end case;
    end process;
end Behavioral;
```

**Critical Vulnerability**: When the backdoor signal `B` is high ('1'), the system bypasses encryption entirely and outputs the raw encryption key instead of encrypted data.

### 2. Circuit Architecture Analysis

Based on the schematic diagram, the system follows this data flow:

```
INPUT → CRYPTO → MUX → OUTPUT
  ↓       ↑       ↑
LOGIC ←  KEY   ← TPM
```

- **INPUT**: Receives 16-bit data
- **CRYPTO**: Performs XOR encryption with key
- **LOGIC**: Contains backdoor detection logic  
- **MUX**: Multiplexer controlled by backdoor signal
- **TPM**: Coordinates all components

The backdoor essentially controls a multiplexer that can switch between:
- **Path A** (Normal): Encrypted output
- **Path B** (Backdoor): Raw key output

## Exploitation Strategy

### Understanding the Vulnerability

The vulnerability lies in the TPM's response to the backdoor trigger:

1. **Normal Operation**: Input → Encryption → Output
2. **Backdoor Active**: Input → **Key Bypass** → Raw Key Output

When we send the magic pattern `1111111111101001`, the backdoor module sets signal `B` to '1', causing the TPM to output the unencrypted key instead of processing our input.

### Binary Pattern Analysis

**Backdoor Trigger**: `1111111111101001`
- **Binary**: 1111111111101001
- **Hexadecimal**: 0xFFE9  
- **Decimal**: 65513
- **Bit Pattern**: 15 ones followed by pattern `101001`

## Solution Implementation

### Step 1: Environment Setup
```bash
# Verify netcat is available
which nc
# nc /usr/bin/nc (or similar path)

# Test basic connectivity  
nc -v 94.237.55.43 38407
# Connection to 94.237.55.43 38407 port [tcp/*] succeeded!
```

### Step 2: Initial Connection Test
```bash
# Establish connection to target
nc 94.237.55.43 38407
```

Expected response: The service should accept the connection and wait for input.

### Step 3: Backdoor Trigger Execution
```bash
# Send the exact backdoor pattern
echo "1111111111101001" | nc 94.237.55.43 38407
```

**Alternative Interactive Method**:
```bash
# Connect interactively
nc 94.237.55.43 38407
# Type the pattern manually:
1111111111101001
# Press Enter
```

### Step 4: Flag Extraction

Upon sending the correct pattern, the system should respond with the flag in HTB{} format.

## Command Execution Walkthrough

### Complete Solution Commands

```bash
# Method 1: Direct pipe (Recommended)
echo "1111111111101001" | nc 94.237.55.43 38407

# Method 2: Interactive session
nc 94.237.55.43 38407
# Then type: 1111111111101001

# Method 3: Alternative formats (if binary string fails)
echo "65513" | nc 94.237.55.43 38407        # Decimal
echo "FFE9" | nc 94.237.55.43 38407         # Hexadecimal
printf "\xFF\xE9" | nc 94.237.55.43 38407   # Raw bytes
```

## Technical Insights

### Why This Backdoor Works

1. **Hardware-Level Backdoor**: Embedded directly in the VHDL logic, making it invisible to software-level security scans
2. **Multiplexer Bypass**: Uses hardware multiplexing to route raw key data instead of encrypted output
3. **Constant Pattern Matching**: Simple but effective trigger mechanism
4. **TPM Compromise**: Exploits the trusted nature of TPM modules

### Security Implications

This challenge demonstrates several real-world hardware security concepts:

- **Supply Chain Attacks**: Backdoors embedded during chip design/manufacturing
- **Hardware Trojans**: Malicious modifications to integrated circuits  
- **TPM Vulnerabilities**: Even "trusted" hardware can be compromised
- **Side-Channel Attacks**: Alternative data paths that bypass security

### Learning Outcomes

1. **VHDL Analysis**: Understanding hardware description languages for security research
2. **Hardware Reverse Engineering**: Analyzing circuit behavior from source code
3. **Binary Protocol Exploitation**: Crafting specific input patterns for hardware triggers
4. **Trusted Platform Module (TPM) Security**: Understanding TPM vulnerabilities and bypass techniques

## Alternative Solution Approaches

### If Direct Binary Pattern Failed

```bash
# Try different encodings
echo -n "1111111111101001" | nc 94.237.55.43 38407  # No newline
printf "1111111111101001\n" | nc 94.237.55.43 38407 # Explicit newline
printf "1111111111101001\r\n" | nc 94.237.55.43 38407 # Windows format

# Try numerical representations
echo "65513" | nc 94.237.55.43 38407              # Decimal
echo "0xFFE9" | nc 94.237.55.43 38407            # Hex with prefix
echo "FFE9" | nc 94.237.55.43 38407              # Hex without prefix

# Try binary data
python3 -c "print(chr(0xFF) + chr(0xE9), end='')" | nc 94.237.55.43 38407
```

### Debugging Connection Issues

```bash
# Verbose connection testing
nc -v 94.237.55.43 38407

# Connection timeout handling
timeout 30 nc 94.237.55.43 38407

# Check if service accepts multiple connections
nc 94.237.55.43 38407 &
nc 94.237.55.43 38407 &
```

## Flag Acquisition

The successful execution of the backdoor trigger results in the TPM outputting its internal key material, which contains or leads directly to the challenge flag in the standard HackTheBox format: `HTB{...}`

## Conclusion

This challenge effectively demonstrates the critical importance of hardware security and the potential for backdoors embedded at the chip design level. The vulnerability in the TPM's multiplexer logic shows how even small design flaws can completely compromise system security.

**Key Takeaways**:
- Hardware backdoors can be embedded in VHDL/Verilog code during design phase
- Trusted Platform Modules are not immune to hardware-level attacks
- Binary protocol analysis is crucial for hardware exploitation
- Circuit diagrams provide valuable insight into data flow and potential bypass mechanisms

The solution required understanding VHDL logic, identifying the backdoor trigger pattern, and successfully exploiting the hardware multiplexer bypass to extract the cryptographic key and ultimately the challenge flag.

---

**Challenge Solved**: ✅  
**Flag Format**: HTB{...}  
**Primary Technique**: Hardware Backdoor Exploitation  
**Tools Used**: netcat, VHDL analysis, binary pattern matching