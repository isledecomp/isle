FROM docker.io/library/debian:stable-slim

# Gather dependencies
RUN dpkg --add-architecture i386
RUN apt-get update -y
RUN apt-get install git wine wine64 wine32 wget unzip -y

# Silence debug warnings in wine (creates noise during compile)
RUN export WINEDEBUG=-all

# Set up the wineprefix
RUN wine wineboot

# Set up MSVC 4.20 and CMake for Windows
RUN git clone https://github.com/itsmattkc/MSVC420 ~/.wine/drive_c/msvc
RUN wget https://github.com/Kitware/CMake/releases/download/v3.26.6/cmake-3.26.6-windows-i386.zip
RUN unzip cmake-3.26.6-windows-i386.zip -d ~/.wine/drive_c
RUN mv ~/.wine/drive_c/cmake-3.26.6-windows-i386 ~/.wine/drive_c/cmake
RUN rm cmake-3.26.6-windows-i386.zip

RUN wget https://github.com/ninja-build/ninja/releases/download/v1.12.1/ninja-win.zip
RUN unzip ninja-win.zip -d ~/.wine/drive_c
RUN rm ninja-win.zip

# Set up entrypoint script to perform the build
COPY entrypoint.sh entrypoint.sh
RUN chmod +x entrypoint.sh
ENTRYPOINT [ "./entrypoint.sh" ]
