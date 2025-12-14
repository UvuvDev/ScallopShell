mkdir -p build
cd build

cmake .. \
  -DQEMU_SRC=$HOME/Downloads/qemu \
  -DQEMU_BUILD=$HOME/Downloads/qemu/build

cmake --build . 
mv librefactorscallop.so ../scallop_plugin.so
cp ../scallop_plugin.so /home/bradley/SoftDev/ScallopShell/qemu-plugins/scallop_plugin.so
cp ../src/*.cpp /home/bradley/SoftDev/ScallopShell/qemu-plugins/src/
cp ../include/*.hpp /home/bradley/SoftDev/ScallopShell/qemu-plugins/include/
echo $PWD