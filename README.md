# Malware Analysis: Mirai (H9MWAN)

## Project Overview

This repository contains a comprehensive malware analysis report focusing on the Mirai IoT botnet. The project details the setup of a secure malware analysis laboratory and presents a research-based analysis of the Mirai malware. It covers the critical aspects of establishing an isolated analysis environment, the selection of appropriate tools, and a thorough investigation of Mirai's identification and behavioral characteristics using open-source intelligence and non-execution-based analysis techniques.

## Motivation and Relevance

This project stems from a deep interest in understanding the operational mechanisms of IoT malware and the methodologies for their analysis. The report serves as a practical demonstration of skills in cybersecurity research, malware analysis, and secure lab environment setup. It highlights the importance of controlled environments for studying malicious software without risking host systems or production networks.

The insights gained from this project are particularly relevant for roles in cybersecurity, threat intelligence, and incident response, showcasing proficiency in:

*   **Malware Analysis Techniques:** Both static and conceptual dynamic analysis methods are explored, providing a foundational understanding of how malware behaves and can be identified.
*   **Secure Environment Design:** The meticulous setup of a virtualized lab environment emphasizes best practices in isolation, tool selection, and testing for safe malware investigation.
*   **Open-Source Intelligence (OSINT):** Leveraging tools like VirusTotal and Hybrid Analysis for gathering information about malware samples demonstrates practical application of OSINT in cybersecurity.
*   **Technical Documentation:** The detailed report structure and clear explanations reflect the ability to articulate complex technical concepts effectively.

## Key Findings and Report Highlights

The report delves into several critical areas, providing a holistic view of Mirai and its analysis:

### Malware Analysis Lab Setup

The project outlines the design and implementation of a secure malware analysis laboratory using Oracle VirtualBox 7.0, featuring two key virtual machines: REMnux v7 and Ubuntu 20.04 LTS. Emphasis is placed on:

*   **Layered Isolation:** Implementing network isolation (Host-Only Adapter), file system isolation, and process isolation to ensure the malware environment is completely detached from the host system.
*   **Targeted Tool Selection:** Focusing on Linux-centric tools suitable for analyzing MIPS and ARM processors, such as `qemu`, `radare2`, `Ghidra`, and `binwalk`.
*   **Automation and Reproducibility:** Strategies for snapshotting, logging, and scripting workflows to enable efficient and repeatable analysis.
*   **Security Settings:** Disabling features like clipboard sharing, drag-and-drop, shared folders, and USB passthrough to prevent data leakage and escape vectors.

### Mirai Malware Analysis

The report provides a detailed analysis of the Mirai botnet, a prominent IoT malware targeting Linux-based devices. Key aspects covered include:

*   **Static Analysis:** Utilizing tools like VirusTotal to identify the malware variant, its architecture (ELF 32-bit LSB, MIPS), and common detection names (e.g., `DDoS:Linux/Mirai.gen!c`, `Trojan.Linux.Mirai.B`). The analysis also includes extracting printable strings using the `strings` command and identifying embedded files with `binwalk`.
*   **Dynamic Behavior (Conceptual):** Drawing insights from publicly available Hybrid Analysis reports to understand Mirai's outbound connections, C2 communication attempts, and propagation characteristics (e.g., use of `busybox`, `wget`, `telnet`).
*   **Functioning Abilities:** Detailing Mirai's core functionalities, including its propagation mechanism (scanning open Telnet ports), brute-force capabilities (using default credentials), payload deployment, Command & Control (C2) communication, and DDoS attack capabilities (UDP floods, ACK floods, GRE-based floods).
*   **Obfuscation and Code Structure:** Discussing Mirai's limited obfuscation techniques and its unsophisticated evasive methods, such as clearing process names and killing rival IoT malware.
*   **Internet Research:** Incorporating findings from academic papers (e.g., Antonakakis et al., 2017) and industry blogs to provide a broader context of Mirai's architecture, lifecycle, and the evolution of its variants.

## Methodology

The analysis methodology adheres to a non-execution-based approach for the Mirai sample, primarily relying on static analysis and open-source intelligence. For practical tool demonstration, harmless ELF binaries (`poweriso.elf` and `zipjail.elf`) from the REMnux apparatus were used to test various forensic tools without risking system security. The tools utilized include:

*   **File Hashers:** `hashdeep`, `md5sum`, `sha256sum` for file identification and comparison.
*   **Text Editors:** `Nano`, `Vim` for examining output and YARA rules.
*   **Network Monitoring Tools (Configured but not live-simulated):** `tcpdump`, `Wireshark`.
*   **Binary Analysis Tools:** `binwalk` for embedded files, `strings` for printable strings, `file` for binary structure, `strace` and `ltrace` for system call and library function tracing, `YARA` for custom rule creation, and `Radare2` for reverse engineering.
*   **Emulation Tools (Conceptual):** `QEMU` for cross-architecture emulation and `INetSim` for network service simulation.

## Report Access

The full malware analysis report, titled "Malware Analysis Mirai (H9MWAN)", is available in PDF format within this repository. You can access it directly here: [23375308_MA_CA1.pdf](23375308_MA_CA1.pdf)

## Getting Started

To explore the report and understand the project details, simply clone this repository:

```bash
git clone https://github.com/your-username/malware-analysis-mirai.git
cd malware-analysis-mirai
```

## Contributing

Contributions to enhance the understanding or analysis of Mirai, or to improve the documentation, are welcome. Please feel free to fork the repository, make improvements, and submit pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

[Your Name/GitHub Profile Link]


