# Darken Anticheat
Open source anticheat for protecting your software against tampering and reverse engineering.

# What does the anti-cheat do?

The anti-cheat monitors both the operating system's kernel as well as the protected usermode processes to find any illegitimate code execution or tampering. The ways in which the anti-cheat does so are described below.

# Current features
- Uses serverside for detection logic, the clientside/driver just acts as a collector of the detection info.
- Detects loaded user and kernel modules which are not digitally signed.
- Detects patches to non writable sections in loaded user and kernel modules.
- Detects kernel threads whose start address is outside of a valid module.
- Detects execution outside of a valid kernel or user module by interrupting CPU cores with a NMI (non maskable interrupt).
- Detects the usage of reserved MSRs (model specific registers), to detect a virtual machine environment.
- Detects emulated environments via DbgPrompt, DBGCTL MSR being unchanged after a write, various ntoskrnl and KUSER_SHARED_DATA fields indicating a debugger, calling ZwSystemDebugControl and expecting a 'debugger inactive' response.

# Licensing
This project has been placed under the [GNU General Public License](LICENSE), if there are any specific enquiries regarding usage, please contact the founder of the project [noahware](https://github.com/noahware).