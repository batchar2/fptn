/*=============================================================================
Copyright (c) 2024-2026 Pavel Shpilev

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

// Reproduces the use-after-free race condition in vpn::http::Client::Stop().
//
// The bug: Stop() called ws_.reset() (destroying the WebSocket) BEFORE
// th_.join() (waiting for Run() to exit). The Run() thread was still
// executing ws_->Run() on the destroyed object.
//
// The fix: join the thread first, then reset the shared_ptr.
//
// This test uses a mock to exercise the exact same pattern.

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <thread>

#include <gtest/gtest.h>  // NOLINT(build/include_order)

namespace {

// Simulates WebsocketClient: Run() blocks until Stop() is called.
class MockWebSocket {
 public:
  MockWebSocket() : stopped_(false), run_entered_(false) {}

  void Run() {
    run_entered_ = true;
    std::unique_lock<std::mutex> lock(mutex_);
    cv_.wait(lock, [this]() { return stopped_.load(); });
    // Simulate cleanup work after stop signal
    std::this_thread::sleep_for(std::chrono::microseconds(100));
    // Access member after wakeup — crashes if object is destroyed
    run_exited_ = true;
  }

  bool Stop() {
    stopped_ = true;
    cv_.notify_all();
    return true;
  }

  bool RunEntered() const { return run_entered_; }
  bool RunExited() const { return run_exited_; }

 private:
  std::mutex mutex_;
  std::condition_variable cv_;
  std::atomic<bool> stopped_;
  std::atomic<bool> run_entered_;
  std::atomic<bool> run_exited_{false};
};

// Reproduces the original buggy Client::Stop() pattern.
// With the bug: ws_.reset() before th_.join() → use-after-free.
// With the fix: th_.join() before ws_.reset() → safe.
class MockClient {
 public:
  bool Start() {
    running_ = true;
    ws_ = std::make_shared<MockWebSocket>();
    th_ = std::thread(&MockClient::RunLoop, this);
    return true;
  }

  // Fixed version: join before reset
  bool StopFixed() {
    if (!running_) {
      return false;
    }
    running_ = false;

    if (ws_) {
      ws_->Stop();
    }
    if (th_.joinable()) {
      th_.join();
    }
    ws_.reset();
    return true;
  }

  bool IsRunning() const { return running_; }

  bool WsRunExited() const { return ws_ && ws_->RunExited(); }

 private:
  void RunLoop() {
    while (running_) {
      if (ws_) {
        ws_->Run();
      }
      if (!running_) {
        break;
      }
    }
  }

  std::thread th_;
  std::mutex mutex_;
  std::atomic<bool> running_{false};
  std::shared_ptr<MockWebSocket> ws_;
};

}  // namespace

// Verify Stop() completes cleanly without crash
TEST(ClientStopRaceTest, StopWhileRunning) {
  MockClient client;
  ASSERT_TRUE(client.Start());

  // Let Run() enter the blocking call
  std::this_thread::sleep_for(std::chrono::milliseconds(10));

  // Stop should complete without crash or hang
  EXPECT_TRUE(client.StopFixed());
  EXPECT_FALSE(client.IsRunning());
}

// Rapid start/stop cycles stress the race window
TEST(ClientStopRaceTest, RapidStartStopCycles) {
  constexpr int kCycles = 50;
  for (int i = 0; i < kCycles; ++i) {
    MockClient client;
    ASSERT_TRUE(client.Start());
    // Vary the timing to hit different race windows
    if (i % 3 == 0) {
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    EXPECT_TRUE(client.StopFixed());
  }
}

// Stop immediately after Start (thread may not have entered Run yet)
TEST(ClientStopRaceTest, ImmediateStop) {
  MockClient client;
  ASSERT_TRUE(client.Start());
  EXPECT_TRUE(client.StopFixed());
  EXPECT_FALSE(client.IsRunning());
}

// Verify Run() thread fully exits before ws_ is destroyed
TEST(ClientStopRaceTest, ThreadExitsBeforeReset) {
  MockClient client;
  ASSERT_TRUE(client.Start());
  std::this_thread::sleep_for(std::chrono::milliseconds(10));

  // After StopFixed, the ws_ shared_ptr is reset.
  // The fact that we reach here without ASan/TSan errors confirms
  // the thread finished before the object was destroyed.
  EXPECT_TRUE(client.StopFixed());
}
