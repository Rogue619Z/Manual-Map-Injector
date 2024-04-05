I've developed a rather effective driver for DLL injection targeting EAC Protected Games, and since I'm not aware of any notable games utilizing that particular anti-cheat system, I've opted to share it here.

Functionality:

The driver suspends anti-cheat threads.
It disables AC image load callbacks and protection.
The usermode client manually maps the DLL and hijacks the thread.
The driver restores all callbacks.
The driver resumes AC threads.

Games tested:
Rust (Steam)
Apex Legends
