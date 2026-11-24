CXX      := g++
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra -Iinclude
TARGET   := net_guardian
SRCS     := src/main.cpp src/pcap_reader.cpp src/packet_parser.cpp src/dpi_engine.cpp

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRCS)

demo: $(TARGET)
	./$(TARGET) --generate-demo samples/demo_traffic.pcap
	./$(TARGET) --pcap samples/demo_traffic.pcap --verbose --json samples/demo_report.json

clean:
	rm -f $(TARGET) $(TARGET).exe
