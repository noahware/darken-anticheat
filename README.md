# Darken Anticheat
Open source anticheat for protecting your software against tampering and reverse engineering.

# What does the anti-cheat do?

The anti-cheat monitors both the operating system's kernel as well as the protected usermode processes to find any illegitimate code execution or tampering. The ways in which the anti-cheat does so are described below.

# Current features
- Detects loaded dlls which are not digitally signed.
- Detects loaded kernel modules which are not digitally signed.
- Strips permissions of handles that are attempted to be opened to any of our protected processes.
- Detects system threads which have a start address outside of any legitimate kernel module.
- Detects system threads which are attached to any of our protected processes.
- Detects process threads which have a start address outside of any legitimate module in the respective protected process.
- Detects debugger being attached via the PEB's `BeingDebugged` byte.
- Force-triggering PatchGuard (KPP) checks to run (causes bugcheck to occur if there are any violations of PatchGuard's checks).
- Causing bugcheck if PatchGuard (KPP) is disabled / has an invalid context.
- Checking usage of reserved MSRs (model specific registers).
- Sending non maskable interrupts and analyzing the rip to detect execution outside of valid kernel modules.
- Resolving all of our driver imports manually.
- Integrity check of ntoskrnl's .text section.
- Integrity check of rest of kernel drivers' .text section.
- Detects all kernel modules' data sections' PTEs being set to executable.

# Windows versions supported

I have tested the anticheat on Windows 10 22H2 and Windows 11 24H2, but I have implemented offsets for each build from Windows 10 1507 -> Windows 11 24H2, so the anticheat should in theory function for all the Windows 10 and Windows 11 versions currently released to the public.

# Credits
- [papstuc](https://github.com/papstuc) for the [nocrt portable executable library used](https://github.com/papstuc/nocrt_portable_executable).
- [jonomango](https://github.com/jonomango), [Satoshi Tanda](https://github.com/tandasat), and [Petr Beneš](https://github.com/wbenny) for their contributions to the [ia32-doc](https://github.com/tandasat/ia32-doc) project.

# Licensing
This project has been placed under the [GNU General Public License](LICENSE), if there are any specific enquiries regarding usage, please contact the founder of the project [noahware](https://github.com/noahware).