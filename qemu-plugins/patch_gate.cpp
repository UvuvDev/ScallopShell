#include <atomic>
#include <thread>

std::atomic<bool> running{true};

void worker() {
  while (running.load()) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
}

int main() {
  std::thread t(worker);
  running.store(false);
  t.join();
}
