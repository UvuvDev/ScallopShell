mkdir -p build
cd build

cmake .. \
  -DQEMU_SRC=$QEMU_SRC_DIR \
  -DQEMU_BUILD=$QEMU_SRC_DIR/build

cmake --build . 
mv librefactorscallop.so ../scallop_plugin.so
