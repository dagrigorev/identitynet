CXX      = g++
CXXFLAGS = -std=c++20 -O2 -Wall -Wextra -Wno-unused-parameter \
           -I./include \
           -pthread

LDFLAGS  = -pthread -lssl -lcrypto

BINDIR   = build

HEADERS  = include/identity.hpp \
           include/crypto.hpp \
           include/protocol.hpp \
           include/transport.hpp \
           include/handshake.hpp \
           include/session.hpp \
           include/keystore.hpp \
           include/discovery.hpp \
           include/authz.hpp \
           include/server.hpp \
           include/client.hpp

all: dirs discovery server client tests demo proxy-server proxy-client

dirs:
	@mkdir -p $(BINDIR)

discovery: $(HEADERS) src/main_discovery.cpp
	$(CXX) $(CXXFLAGS) src/main_discovery.cpp -o $(BINDIR)/identitynet-discovery $(LDFLAGS)

server: $(HEADERS) src/main_server.cpp
	$(CXX) $(CXXFLAGS) src/main_server.cpp -o $(BINDIR)/identitynet-server $(LDFLAGS)

client: $(HEADERS) src/main_client.cpp
	$(CXX) $(CXXFLAGS) src/main_client.cpp -o $(BINDIR)/identitynet-client $(LDFLAGS)

tests: $(HEADERS) tests/tests.cpp
	$(CXX) $(CXXFLAGS) tests/tests.cpp -o $(BINDIR)/identitynet-tests $(LDFLAGS)

demo: $(HEADERS) tests/demo.cpp
	$(CXX) $(CXXFLAGS) tests/demo.cpp -o $(BINDIR)/identitynet-demo $(LDFLAGS)

clean:
	rm -rf $(BINDIR)

run-tests: tests
	cd $(BINDIR) && ./identitynet-tests

.PHONY: all dirs discovery server client tests clean run-tests

proxy-server: $(HEADERS) include/proxy_proto.hpp src/main_proxy_server.cpp
	$(CXX) $(CXXFLAGS) src/main_proxy_server.cpp -o $(BINDIR)/identitynet-proxy-server $(LDFLAGS)

proxy-client: $(HEADERS) include/proxy_proto.hpp src/main_proxy_client.cpp
	$(CXX) $(CXXFLAGS) src/main_proxy_client.cpp -o $(BINDIR)/identitynet-proxy-client $(LDFLAGS)

proxy: proxy-server proxy-client

proxy-tests: $(HEADERS) include/proxy_proto.hpp tests/test_proxy.cpp
	$(CXX) $(CXXFLAGS) tests/test_proxy.cpp -o $(BINDIR)/identitynet-proxy-tests $(LDFLAGS)
