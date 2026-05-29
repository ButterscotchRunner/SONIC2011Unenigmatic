# SONIC 2011 Unenigmatic

SONIC 2011 Unenigmatic is a tool to dump [SONIC 2011](https://gamejolt.com/games/sonic/783884)'s `data.win` file.

SONIC 2011 uses Enigma to encrypt the executable, hence the name. Unenigmatic tracks when Enigma tries to write the `data.win` file and dumps it to the `dump/datawin.dump` file.

We need to do this instead of dumping it directly from memory because the YoYo Runner patches pointers in-place, so if you dumped directly from memory you would have pointers that do not point where they should to, so we need to get the `data.win` BEFORE the runner attempts to patch the pointers.

Originally this tool was made because I wanted to test out SONIC 2011 in [Butterscotch](https://github.com/ButterscotchRunner/Butterscotch), but after [a Twitter thread was posted](https://x.com/SONIC2011DELUXE/status/2059987163719008557) saying that someone else had dumped the `data.win` and that "some of the game assets are still encrypted" (?) and that they didn't want to share how it was done, I've decided to publish the code to dump it.

This may also work with other games that also use Enigma, but it will require tweaking the source code to replace `sonic.exe` with the name of the game's executable.

## Instructions

You'll need a C23 compiler and CMake to build the project.

1. Clone the repository
2. `mkdir build && cd build`
3. `cmake ..`
4. `cmake --build .`
5. Copy the `hook.dll` and `inject.exe` to the same folder where `sonic.exe` is
6. Run `inject.exe` (also works with Wine)

The `data.win` file will be inside the `dump` folder.