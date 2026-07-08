SRC_DIR := src/main/java
TEST_DIR := src/test/java
BUILD_DIR := build/classes
SOURCES := $(shell find $(SRC_DIR) -name '*.java' 2>/dev/null)
TESTS := $(shell find $(TEST_DIR) -name '*.java' 2>/dev/null)

.PHONY: compile test run clean

compile:
	mkdir -p $(BUILD_DIR)
	javac -d $(BUILD_DIR) $(SOURCES)

test:
	mkdir -p $(BUILD_DIR)
	javac -d $(BUILD_DIR) $(SOURCES) $(TESTS)
	java -cp $(BUILD_DIR) dev.tzheng.weblogtriage.TestRunner

run: compile
	java -cp $(BUILD_DIR) dev.tzheng.weblogtriage.Main samples/access.log

clean:
	rm -rf build

