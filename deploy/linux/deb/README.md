### Setup GitHub Runner

Before setting up the GitHub runner, you need to install the following packages on your system:

```bash
pip install clang-tidy
pip install clang-format
pip install cmake-format
sudo wget -qO- https://apt.llvm.org/llvm.sh | sudo bash -s -- 20
sudo apt install cppcheck 

sudo apt-get update
sudo apt-get install -y libx11-dev libx11-xcb-dev libfontenc-dev libice-dev libsm-dev libxau-dev libxaw7-dev \
libxcomposite-dev libxcursor-dev libxdamage-dev libxfixes-dev libxi-dev libxinerama-dev libxkbfile-dev \
libxmuu-dev libxrandr-dev libxrender-dev libxres-dev libxss-dev libxtst-dev libxv-dev libxxf86vm-dev \
libxcb-glx0-dev libxcb-render0-dev libxcb-render-util0-dev libxcb-xkb-dev libxcb-icccm4-dev libxcb-image0-dev \
libxcb-keysyms1-dev libxcb-randr0-dev libxcb-shape0-dev libxcb-sync-dev libxcb-xfixes0-dev libxcb-xinerama0-dev \
libxcb-dri3-dev uuid-dev libxcb-cursor-dev libxcb-dri2-0-dev libxcb-dri3-dev libxcb-present-dev libxcb-composite0-dev \
libxcb-ewmh-dev libxcb-res0-dev libxcb-util-dev pkg-config libgl-dev libgl1-mesa-dev
```
